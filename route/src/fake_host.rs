//! A recording fake Bloom host, used only by this crate's tests.
//!
//! The `host` seam in `lib.rs` dispatches here under `cfg(test)`, so a test can
//! drive a whole write flow — build, sign, simulate, broadcast — and then
//! assert on the exact requests the route made and the exact durable state it
//! left behind. Nothing here is compiled into a route component.
//!
//! Requests are matched by a key: for a JSON-RPC body it is
//! `"<url> <jsonrpc method>"`, otherwise it is the URL alone. Each key holds a
//! list of replies which are handed out in order; once the list is exhausted
//! the last reply repeats, so a test only scripts the responses it cares
//! about changing.

use petal::{
    HostStatus, HttpRequest, HttpResponse, PayloadSignRequest, PetalKeyOutcome, SdkError,
    SignOutcome,
};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;

/// One HTTP request the route made, as the host saw it.
#[derive(Clone, Debug)]
pub struct Call {
    pub method: String,
    pub url: String,
    pub body: Value,
}

impl Call {
    /// The JSON-RPC method name, when the body is a JSON-RPC request.
    pub fn rpc_method(&self) -> Option<&str> {
        self.body.get("method").and_then(Value::as_str)
    }

    /// The JSON-RPC parameters, when the body is a JSON-RPC request.
    pub fn rpc_params(&self) -> Option<&Value> {
        self.body.get("params")
    }
}

#[derive(Default)]
pub struct FakeHost {
    /// What `host::now_ms` reports.
    pub now_ms: u64,
    /// Every HTTP request the route made, in order.
    pub calls: Vec<Call>,
    /// Every signing request the route made, in order.
    pub sign_requests: Vec<PayloadSignRequest>,
    pub key_requests: Vec<Value>,
    state: BTreeMap<String, Vec<u8>>,
    secrets: BTreeMap<String, Vec<u8>>,
    replies: BTreeMap<String, Vec<Value>>,
    served: BTreeMap<String, usize>,
    signatures: Vec<Result<SignOutcome, SdkError>>,
    derivations: Vec<Result<PetalKeyOutcome, SdkError>>,
    /// Successful store writes so far.
    pub puts: usize,
    /// Make every store write after this many successful writes fail, to model
    /// a process that dies between a host effect and its durable record.
    pub fail_store_after: Option<usize>,
}

impl FakeHost {
    pub fn new(now_ms: u64) -> Self {
        Self {
            now_ms,
            ..Self::default()
        }
    }

    /// Queue one reply for a request key.
    pub fn reply(&mut self, key: &str, body: Value) -> &mut Self {
        self.replies.entry(key.to_owned()).or_default().push(body);
        self
    }

    /// Replace every queued reply for a request key with this one.
    pub fn reply_only(&mut self, key: &str, body: Value) -> &mut Self {
        self.replies.insert(key.to_owned(), vec![body]);
        self.served.remove(key);
        self
    }

    /// Seed a value in the public state namespace.
    pub fn seed_state(&mut self, key: &str, value: &impl serde::Serialize) -> &mut Self {
        self.state.insert(
            key.to_owned(),
            serde_json::to_vec(value).expect("seed serializes"),
        );
        self
    }

    /// Seed a value in the secret namespace.
    pub fn seed_secret(&mut self, key: &str, value: &impl serde::Serialize) -> &mut Self {
        self.secrets.insert(
            key.to_owned(),
            serde_json::to_vec(value).expect("seed serializes"),
        );
        self
    }

    /// Queue one signing outcome. Unqueued calls return a fixed signature.
    pub fn sign_outcome(&mut self, outcome: Result<SignOutcome, SdkError>) -> &mut Self {
        self.signatures.push(outcome);
        self
    }

    /// Queue one key-derivation outcome.
    pub fn derivation(&mut self, outcome: Result<PetalKeyOutcome, SdkError>) -> &mut Self {
        self.derivations.push(outcome);
        self
    }

    /// Read back a public state value.
    pub fn state_json(&self, key: &str) -> Option<Value> {
        self.state
            .get(key)
            .map(|bytes| serde_json::from_slice(bytes).expect("stored state is JSON"))
    }

    /// Read back a secret-namespace value.
    pub fn secret_json(&self, key: &str) -> Option<Value> {
        self.secrets
            .get(key)
            .map(|bytes| serde_json::from_slice(bytes).expect("stored secret is JSON"))
    }

    /// Every JSON-RPC method name the route asked for, in order.
    pub fn rpc_methods(&self) -> Vec<&str> {
        self.calls.iter().filter_map(Call::rpc_method).collect()
    }

    /// The calls that carried a given JSON-RPC method.
    pub fn calls_for(&self, rpc_method: &str) -> Vec<&Call> {
        self.calls
            .iter()
            .filter(|call| call.rpc_method() == Some(rpc_method))
            .collect()
    }

    fn namespace_for(key: &str, secret: bool) -> bool {
        secret || key == "creds" || key.starts_with("creds/")
    }

    fn writable(&mut self) -> Result<(), SdkError> {
        if self
            .fail_store_after
            .is_some_and(|limit| self.puts >= limit)
        {
            return Err(SdkError::Host(HostStatus::Backend));
        }
        self.puts += 1;
        Ok(())
    }

    fn fetch(&mut self, request: &HttpRequest) -> Result<HttpResponse, SdkError> {
        let body: Value = if request.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&request.body).map_err(|error| {
                SdkError::Message(format!("fake host: unreadable body: {error}"))
            })?
        };
        let call = Call {
            method: request.method.clone(),
            url: request.url.clone(),
            body,
        };
        let key = match call.rpc_method() {
            Some(rpc) => format!("{} {}", call.url, rpc),
            None => call.url.clone(),
        };
        self.calls.push(call);
        let Some(replies) = self.replies.get(&key) else {
            return Err(SdkError::Message(format!(
                "fake host: no reply scripted for {key}"
            )));
        };
        let served = self.served.entry(key).or_default();
        let index = (*served).min(replies.len() - 1);
        *served += 1;
        let body = serde_json::to_vec(&replies[index]).expect("reply serializes");
        Ok(HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body,
        })
    }
}

thread_local! {
    static HOST: RefCell<Option<FakeHost>> = const { RefCell::new(None) };
}

/// Install a fake host for the current test thread.
pub fn install(host: FakeHost) {
    HOST.with(|slot| *slot.borrow_mut() = Some(host));
}

/// Borrow the installed fake host.
pub fn with<T>(body: impl FnOnce(&mut FakeHost) -> T) -> T {
    HOST.with(|slot| {
        let mut slot = slot.borrow_mut();
        body(
            slot.as_mut()
                .expect("install a FakeHost before exercising a route"),
        )
    })
}

pub fn http(request: &HttpRequest, max_bytes: usize) -> Result<HttpResponse, SdkError> {
    with(|host| {
        let response = host.fetch(request)?;
        if response.body.len() > max_bytes {
            return Err(SdkError::Host(HostStatus::BufferTooSmall {
                needed: response.body.len(),
            }));
        }
        Ok(response)
    })
}

pub fn store_get(key: &str, max_bytes: usize) -> Result<Vec<u8>, SdkError> {
    with(|host| {
        let bytes = host
            .state
            .get(key)
            .cloned()
            .ok_or(SdkError::Host(HostStatus::NotFound))?;
        if bytes.len() > max_bytes {
            return Err(SdkError::Host(HostStatus::BufferTooSmall {
                needed: bytes.len(),
            }));
        }
        Ok(bytes)
    })
}

pub fn store_get_secret(key: &str) -> Result<Option<Vec<u8>>, String> {
    with(|host| Ok(host.secrets.get(key).cloned()))
}

pub fn store_put(key: &str, value: &[u8], secret: bool) -> Result<(), SdkError> {
    with(|host| {
        host.writable()?;
        let target = if FakeHost::namespace_for(key, secret) {
            &mut host.secrets
        } else {
            &mut host.state
        };
        target.insert(key.to_owned(), value.to_vec());
        Ok(())
    })
}

pub fn store_put_new(key: &str, value: &[u8], secret: bool) -> Result<(), SdkError> {
    with(|host| {
        host.writable()?;
        let target = if FakeHost::namespace_for(key, secret) {
            &mut host.secrets
        } else {
            &mut host.state
        };
        if target.contains_key(key) {
            return Err(SdkError::Host(HostStatus::Denied));
        }
        target.insert(key.to_owned(), value.to_vec());
        Ok(())
    })
}

pub fn store_list(prefix: &str, max_bytes: usize) -> Result<Vec<String>, SdkError> {
    with(|host| {
        let keys: Vec<String> = host
            .state
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        let size: usize = keys.iter().map(String::len).sum();
        if size > max_bytes {
            return Err(SdkError::Host(HostStatus::BufferTooSmall { needed: size }));
        }
        Ok(keys)
    })
}

pub fn derive_key(request_jcs: &[u8]) -> Result<PetalKeyOutcome, SdkError> {
    with(|host| {
        host.key_requests
            .push(serde_json::from_slice(request_jcs).expect("canonical key request"));
        if host.derivations.is_empty() {
            // Unscripted: the session's key is live and authorized.
            return Ok(PetalKeyOutcome::Ready {
                operation_id: "fake-key-op".into(),
                scope_digest: "fake-scope-digest".into(),
                key_ref_jcs: br#"{"public_key_fingerprint":"test-fingerprint"}"#.to_vec(),
                addresses: Vec::new(),
            });
        }
        host.derivations.remove(0)
    })
}

pub fn sign_payload(request: &PayloadSignRequest) -> Result<SignOutcome, SdkError> {
    with(|host| {
        host.sign_requests.push(request.clone());
        if host.signatures.is_empty() {
            return Ok(SignOutcome::Signature(vec![7u8; 64]));
        }
        host.signatures.remove(0)
    })
}

pub fn now_ms() -> u64 {
    with(|host| host.now_ms)
}
