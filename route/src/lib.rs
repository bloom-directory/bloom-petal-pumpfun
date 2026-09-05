use base64::{Engine, engine::general_purpose::STANDARD as B64};
use petal::{
    Ctx, DispatchResponse, HostStatus, HttpRequest, PayloadSignRequest, SdkError, SignOutcome,
    SignSelector,
};
use serde::{Deserialize, Serialize};
pub use serde_json::json;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX: usize = 131072;
const MAX_TX: usize = 1232;
const MAX_SESSION_MS: u64 = 86_400_000;
const MAX_PRIORITY_FEE_LAMPORTS: u64 = 5_000_000;
const BUILD: &str = "https://fun-block.pump.fun";
const COINS: &str = "https://frontend-api-v3.pump.fun/coins-v2";
const RPC: &str = "https://rpc.solanatracker.io/public";
const JITO: &str = "https://mainnet.block-engine.jito.wtf/api/v1/transactions";
const SOL: &str = "So11111111111111111111111111111111111111112";
const ROUTES: [&str; 6] = [
    "ROUTE_CREATE",
    "ROUTE_BUY",
    "ROUTE_SELL",
    "ROUTE_FEES",
    "ROUTE_SHARING",
    "ROUTE_NEW",
];
const CLASSES: [&str; 5] = [
    "pumpfun.create",
    "pumpfun.buy",
    "pumpfun.sell",
    "pumpfun.collect_fees",
    "pumpfun.sharing_config",
];
const PROGRAMS: [&str; 9] = [
    "ComputeBudget111111111111111111111111111111",
    "11111111111111111111111111111111",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
    "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
    "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ",
    "AgenTMiC2hvxGebTsgmsD4HHBa8WEcqGFf87iwRRxLo7",
];
const JITO_DONT_FRONT: &str = "jitodontfront11111111111111111111111111pump";
const JITO_TIPS: [&str; 8] = [
    "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5",
    "HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe",
    "Cw8CFyM9FkoMi7K7Crf6HNQqf4uEMzpKw6QNghXLvLkY",
    "ADaUMid9yfUytqMBgopwjb2DTLSokTSzL1zt6iGPaS49",
    "DfXygSm4jCyNCybVYYK6DwvWqjKee8pbDmJGcLWNDXjh",
    "ADuUkR4vqLUMWXxW9gh6D6L8pMSawimctcNZ5pGwDcEt",
    "DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL",
    "3AVi9Tg9Uo68tJfuvoKvqKNWKkC5wPdSSdeBnizKZ6jT",
];

fn bad(e: impl Into<String>) -> DispatchResponse {
    petal::error(-3, e)
}
fn deny(e: impl Into<String>) -> DispatchResponse {
    petal::error(-2, e)
}
fn fail(e: impl Into<String>) -> DispatchResponse {
    petal::error(-4, e)
}
pub fn body(b: &[u8]) -> Result<(), DispatchResponse> {
    if b.len() <= MAX {
        Ok(())
    } else {
        Err(bad("body exceeds 128 KiB"))
    }
}
fn ident(s: &str, n: &str) -> Result<String, DispatchResponse> {
    if s.is_empty()
        || s.len() > 96
        || matches!(s, "." | "..")
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        Err(bad(format!("invalid {n}")))
    } else {
        Ok(s.into())
    }
}
pub fn wallet(c: &Ctx) -> Result<String, DispatchResponse> {
    ident(petal::param(c, "wallet")?, "wallet")
}
pub fn session(c: &Ctx) -> Result<String, DispatchResponse> {
    ident(petal::param(c, "session")?, "session")
}
pub fn operation(c: &Ctx) -> Result<String, DispatchResponse> {
    ident(petal::param(c, "operation")?, "operation")
}
fn pk(s: &str) -> Result<[u8; 32], String> {
    bs58::decode(s)
        .into_vec()
        .map_err(|_| "invalid base58 pubkey".to_string())?
        .try_into()
        .map_err(|_| "pubkey is not 32 bytes".to_string())
}
fn sk(w: &str, s: &str, x: &str) -> String {
    format!("state/sessions/{w}/{s}/{x}")
}
fn sec(w: &str, s: &str, o: &str) -> String {
    format!("sessions/{w}/{s}/operations/{o}.json")
}
fn session_sec(w: &str, s: &str) -> String {
    format!("sessions/{w}/{s}/session.json")
}
fn put<T: Serialize + ?Sized>(k: &str, v: &T, secret: bool) -> Result<(), DispatchResponse> {
    petal::sdk::store_put(
        k,
        &serde_json::to_vec(v).map_err(|e| fail(e.to_string()))?,
        secret,
    )
    .map_err(|e| fail(e.message()))
}
fn put_new<T: Serialize + ?Sized>(k: &str, v: &T, secret: bool) -> Result<(), DispatchResponse> {
    petal::sdk::store_put_new(
        k,
        &serde_json::to_vec(v).map_err(|e| fail(e.to_string()))?,
        secret,
    )
    .map_err(|e| fail(e.message()))
}
fn get<T: for<'a> Deserialize<'a>>(k: &str) -> Result<Option<T>, DispatchResponse> {
    match petal::sdk::store_get(k, MAX) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| fail(e.to_string())),
        Err(SdkError::Host(HostStatus::NotFound)) => Ok(None),
        Err(e) => Err(fail(e.message())),
    }
}
fn get_secret<T: for<'a> Deserialize<'a>>(k: &str) -> Result<Option<T>, DispatchResponse> {
    match petal::bindings::bloom::store::kv::get("secrets", k) {
        Ok(Some(b)) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| fail(e.to_string())),
        Ok(None) => Ok(None),
        Err(e) => Err(fail(e)),
    }
}
fn fetch(method: &str, url: String, body: Vec<u8>) -> Result<Value, DispatchResponse> {
    let r = petal::sdk::http_fetch(
        &HttpRequest {
            method: method.into(),
            url,
            headers: vec![("content-type".into(), "application/json".into())],
            body,
        },
        MAX,
    )
    .map_err(|e| fail(e.message()))?;
    let v: Value =
        serde_json::from_slice(&r.body).map_err(|e| fail(format!("invalid remote JSON: {e}")))?;
    if !(200..300).contains(&r.status) || v.get("error").is_some() {
        Err(fail(format!("remote rejected request: {}", safe(&v))))
    } else {
        Ok(v)
    }
}
fn post(url: &str, v: &Value) -> Result<Value, DispatchResponse> {
    fetch(
        "POST",
        url.into(),
        serde_json::to_vec(v).map_err(|e| fail(e.to_string()))?,
    )
}
fn safe(v: &Value) -> String {
    let mut safe = Map::new();
    for field in ["statusCode", "error", "message"] {
        if let Some(value) = v.get(field)
            && (value.is_string() || value.is_number() || value.is_boolean())
        {
            safe.insert(field.into(), value.clone());
        }
    }
    if safe.is_empty() {
        "remote request failed".into()
    } else {
        Value::Object(safe).to_string().chars().take(2048).collect()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    schema: String,
    wallet: String,
    id: String,
    pub address: String,
    duration_ms: u64,
    created_ms: u64,
    expires_ms: u64,
    pub stopped: bool,
}
#[derive(Serialize, Deserialize)]
struct SessionSecret {
    key_ref_jcs: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct New {
    id: String,
    #[serde(default)]
    duration_ms: Option<u64>,
}
pub fn new_session(_c: &Ctx, w: String, b: &[u8]) -> DispatchResponse {
    let r: New = match serde_json::from_slice(b) {
        Ok(v) => v,
        Err(e) => return bad(e.to_string()),
    };
    let id = match ident(&r.id, "session id") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let life = r.duration_ms.unwrap_or(3_600_000);
    if !(60_000..=MAX_SESSION_MS).contains(&life) {
        return bad("duration_ms must be between 60000 and 86400000");
    }
    let public_key = sk(&w, &id, "session.json");
    match get::<Session>(&public_key) {
        Ok(Some(existing)) if existing.duration_ms == life => return DispatchResponse::Write,
        Ok(Some(_)) => return bad("session id already used with a different duration"),
        Ok(None) => {}
        Err(e) => return e,
    }
    let out = match petal::sdk::derive_key(&petal::PetalKeyRequest {
        wallet_id: w.clone(),
        key_slot: format!(
            "pumpfun-{}",
            &hex::encode(Sha256::digest(id.as_bytes()))[..40]
        ),
        allowed_routes: ROUTES.iter().map(|x| x.to_string()).collect(),
        allowed_operation_classes: CLASSES.iter().map(|x| x.to_string()).collect(),
        allowed_crypto_suites: vec!["ed25519-message".into()],
        maximum_lifetime_ms: life,
    }) {
        Ok(v) => v,
        Err(e) => return fail(e.message()),
    };
    let (key_ref_jcs, address) = match out {
        petal::PetalKeyOutcome::Pending {
            operation_id,
            scope_digest,
        } => {
            return deny(format!(
                "key approval required: {}",
                json!({"operation_id":operation_id,"scope_digest":scope_digest})
            ));
        }
        petal::PetalKeyOutcome::Ready {
            key_ref_jcs,
            addresses,
            ..
        } => {
            let Some(a) = addresses.into_iter().find(|a| pk(a).is_ok()) else {
                return fail("no Solana address in derived key");
            };
            (key_ref_jcs, a)
        }
    };
    let now = petal::sdk::now_ms();
    let v = Session {
        schema: "bloom.pumpfun_session.v1".into(),
        wallet: w.clone(),
        id: id.clone(),
        address,
        duration_ms: life,
        created_ms: now,
        expires_ms: now + life,
        stopped: false,
    };
    let secret_key = session_sec(&w, &id);
    let secret = SessionSecret { key_ref_jcs };
    if let Err(e) = put_new(&secret_key, &secret, true) {
        match get_secret::<SessionSecret>(&secret_key) {
            Ok(Some(existing)) if existing.key_ref_jcs == secret.key_ref_jcs => {}
            _ => return e,
        }
    }
    match put_new(&public_key, &v, false) {
        Ok(()) => DispatchResponse::Write,
        Err(e) => e,
    }
}
pub fn read_session(w: &str, s: &str) -> DispatchResponse {
    match get::<Session>(&sk(w, s, "session.json")) {
        Ok(Some(v)) => petal::read_json_value(&v),
        Ok(None) => bad("session not found"),
        Err(e) => e,
    }
}
pub fn stop(w: &str, s: &str) -> DispatchResponse {
    let k = sk(w, s, "session.json");
    let mut v = match get::<Session>(&k) {
        Ok(Some(v)) => v,
        Ok(None) => return bad("session not found"),
        Err(e) => return e,
    };
    v.stopped = true;
    match put(&k, &v, false) {
        Ok(()) => DispatchResponse::Write,
        Err(e) => e,
    }
}

#[derive(Clone, Copy)]
pub enum Action {
    Create,
    Buy,
    Sell,
    Fees,
    Sharing,
}
impl Action {
    fn class(self) -> &'static str {
        match self {
            Self::Create => CLASSES[0],
            Self::Buy => CLASSES[1],
            Self::Sell => CLASSES[2],
            Self::Fees => CLASSES[3],
            Self::Sharing => CLASSES[4],
        }
    }
    fn path(self) -> &'static str {
        match self {
            Self::Create => "/agents/create-coin",
            Self::Buy | Self::Sell => "/agents/swap",
            Self::Fees => "/agents/collect-fees",
            Self::Sharing => "/agents/sharing-config",
        }
    }
}
#[derive(Serialize, Deserialize)]
struct Pending {
    digest: String,
    tx: String,
    api: Value,
    front: bool,
    network_fee_lamports: u64,
    status: String,
    signature: Option<String>,
    approval: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Public {
    schema: String,
    action: String,
    status: String,
    signature: Option<String>,
    api: Value,
    updated_ms: u64,
}
fn active_session(w: &str, s: &str) -> Result<Session, DispatchResponse> {
    let session =
        get::<Session>(&sk(w, s, "session.json"))?.ok_or_else(|| bad("session not found"))?;
    if session.stopped || session.expires_ms <= petal::sdk::now_ms() {
        Err(deny("session stopped or expired"))
    } else {
        Ok(session)
    }
}
fn build_pending(
    a: Action,
    user: &str,
    request: &Map<String, Value>,
    digest: String,
) -> Result<Pending, DispatchResponse> {
    let response = post(
        &format!("{BUILD}{}", a.path()),
        &Value::Object(request.clone()),
    )?;
    let tx = response
        .get("transaction")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("builder omitted transaction"))?
        .to_owned();
    validate_tx(&tx, user, a, request, &response)
        .map_err(|error| fail(format!("unsafe builder transaction: {error}")))?;
    let network_fee_lamports = transaction_fee(&tx)?;
    let mut api = response;
    api.as_object_mut()
        .ok_or_else(|| fail("builder response must be an object"))?
        .remove("transaction");
    Ok(Pending {
        digest,
        tx,
        api,
        front: request
            .get("frontRunningProtection")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        network_fee_lamports,
        status: "built".into(),
        signature: None,
        approval: None,
    })
}
pub fn execute(c: &Ctx, a: Action, w: String, s: String, b: &[u8]) -> DispatchResponse {
    let sess = match active_session(&w, &s) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let session_secret = match get_secret::<SessionSecret>(&session_sec(&w, &s)) {
        Ok(Some(value)) => value,
        Ok(None) => return fail("session signing reference is unavailable"),
        Err(e) => return e,
    };
    let mut r: Map<String, Value> = match serde_json::from_slice(b) {
        Ok(v) => v,
        Err(e) => return bad(e.to_string()),
    };
    let op = match r
        .remove("operationId")
        .and_then(|v| v.as_str().map(str::to_owned))
        .and_then(|v| ident(&v, "operationId").ok())
    {
        Some(v) => v,
        None => return bad("valid operationId required"),
    };
    if let Err(e) = normalize(a, &sess.address, &mut r) {
        return e;
    }
    let canonical = match serde_jcs::to_vec(&r) {
        Ok(value) => value,
        Err(e) => return bad(format!("request cannot be canonicalized: {e}")),
    };
    let digest = hex::encode(Sha256::digest([a.class().as_bytes(), &canonical].concat()));
    let key = sec(&w, &s, &op);
    let mut p = match get_secret::<Pending>(&key) {
        Ok(Some(mut v)) => {
            if v.digest != digest {
                return bad("operationId already bound");
            };
            if matches!(v.status.as_str(), "simulation_failed" | "approval_failed") {
                v = match build_pending(a, &sess.address, &r, digest.clone()) {
                    Ok(value) => value,
                    Err(e) => return e,
                };
                if let Err(e) = put(&key, &v, true) {
                    return e;
                }
                if let Err(e) = publish(&w, &s, &op, a, &v) {
                    return e;
                }
            }
            v
        }
        Ok(None) => {
            let p = match build_pending(a, &sess.address, &r, digest) {
                Ok(value) => value,
                Err(e) => return e,
            };
            if let Err(e) = put_new(&key, &p, true) {
                return e;
            }
            if let Err(e) = publish(&w, &s, &op, a, &p) {
                return e;
            }
            p
        }
        Err(e) => return e,
    };
    if matches!(
        p.status.as_str(),
        "submitted" | "broadcast_attempted" | "confirmed" | "finalized" | "chain_failed"
    ) {
        return DispatchResponse::Write;
    }
    let raw = match B64.decode(&p.tx) {
        Ok(v) => v,
        Err(_) => return fail("stored transaction invalid"),
    };
    let env = match envelope(&raw) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let hash: [u8; 32] = Sha256::digest(env.message).into();
    let route = match c
        .params
        .iter()
        .find_map(|(k, v)| (k == "bloom.route_id").then_some(v))
    {
        Some(v) => v,
        None => return fail("trusted route id unavailable"),
    };
    let batch = match petal::payload_batch_digest(&[petal::PayloadSignItem {
        preimage: env.message.to_vec(),
        claimed_hash: hash,
    }]) {
        Ok(value) => value,
        Err(e) => return fail(e.message()),
    };
    let parsed_message = match message(env.message) {
        Ok(value) => value,
        Err(e) => return fail(e),
    };
    let debits = match effects(a, &r, &parsed_message) {
        Ok(value) => value,
        Err(e) => return fail(e),
    };
    let claim = json!({"package_hash":c.package_hash,"route":route,"operation_class":a.class(),"crypto_suite":"ed25519-message","payload_digest":hex::encode(batch),"ordered_hashes":[hex::encode(hash)],"declared_debits":debits,"declared_destinations":destinations(&parsed_message),"declared_fee":{"kind":"fee","chain":"solana","asset":"native","amount":p.network_fee_lamports.to_string()},"nonce":hex::encode(Sha256::digest([p.digest.as_bytes(),&env.blockhash].concat())),"claim_assurance":{"kind":"machine_asserted"}});
    let claim_jcs = match serde_jcs::to_vec(&claim) {
        Ok(value) => value,
        Err(e) => return fail(format!("signing claim cannot be canonicalized: {e}")),
    };
    if let Err(e) = active_session(&w, &s) {
        return e;
    }
    let sig = match petal::sdk::sign_payload(&PayloadSignRequest {
        wallet: w.clone(),
        preimage: env.message.to_vec(),
        claimed_hash: hash,
        signature_algorithm: "ed25519-message".into(),
        operation_class: a.class().into(),
        petal_use_claim_jcs: claim_jcs,
        claim_assurance_evidence: None,
        approval_hint: p.approval.clone(),
        action: None,
        advisory: None,
        selector: SignSelector::Reusable,
        key_ref_jcs: Some(session_secret.key_ref_jcs),
    }) {
        Ok(SignOutcome::Signature(v)) => v,
        Ok(SignOutcome::ApprovalPending {
            action_id,
            expires_ms,
        }) => {
            p.status = "approval_pending".into();
            p.approval = Some(action_id.clone());
            if let Err(e) = put(&key, &p, true) {
                return e;
            }
            if let Err(e) = publish(&w, &s, &op, a, &p) {
                return e;
            }
            return deny(format!(
                "approval required: {}",
                json!({"action_id":action_id,"expires_ms":expires_ms,"operationId":op})
            ));
        }
        Err(e) => {
            p.status = "approval_failed".into();
            p.approval = None;
            if let Err(store_error) = put(&key, &p, true) {
                return store_error;
            }
            if let Err(store_error) = publish(&w, &s, &op, a, &p) {
                return store_error;
            }
            return deny(e.message());
        }
    };
    if sig.len() != 64 {
        return fail("non-Ed25519 signature");
    }
    let mut signed = raw.clone();
    signed[env.sig_offset..env.sig_offset + 64].copy_from_slice(&sig);
    let tx = B64.encode(signed);
    let signature = bs58::encode(sig).into_string();
    if let Err(e) = simulate(&tx) {
        p.status = "simulation_failed".into();
        p.approval = None;
        if let Err(store_error) = put(&key, &p, true) {
            return store_error;
        }
        if let Err(store_error) = publish(&w, &s, &op, a, &p) {
            return store_error;
        }
        return e;
    }
    if let Err(e) = active_session(&w, &s) {
        return e;
    }
    p.status = "broadcast_attempted".into();
    p.signature = Some(signature.clone());
    p.approval = None;
    if let Err(e) = put(&key, &p, true) {
        return e;
    }
    if let Err(e) = publish(&w, &s, &op, a, &p) {
        return e;
    }
    let result = if p.front {
        post(
            JITO,
            &rpc("sendTransaction", json!([tx,{"encoding":"base64"}])),
        )
    } else {
        post(
            RPC,
            &rpc(
                "sendTransaction",
                json!([tx,{"encoding":"base64","skipPreflight":false,"maxRetries":0}]),
            ),
        )
    };
    match result {
        Ok(v) if v.get("result").and_then(Value::as_str) == Some(&signature) => {
            p.status = "submitted".into();
            if let Err(e) = put(&key, &p, true) {
                return e;
            }
            if let Err(e) = publish(&w, &s, &op, a, &p) {
                return e;
            }
            DispatchResponse::Write
        }
        Ok(_) => fail("RPC signature mismatch"),
        Err(e) => e,
    }
}

fn normalize(a: Action, user: &str, r: &mut Map<String, Value>) -> Result<(), DispatchResponse> {
    let allowed = match a {
        Action::Create => &[
            "name",
            "symbol",
            "uri",
            "solLamports",
            "mayhemMode",
            "cashback",
            "tokenizedAgent",
            "buybackBps",
            "frontRunningProtection",
            "tipAmount",
        ][..],
        Action::Buy | Action::Sell => &[
            "mint",
            "amount",
            "slippagePct",
            "frontRunningProtection",
            "tipAmount",
        ][..],
        Action::Fees => &["mint", "frontRunningProtection", "tipAmount"][..],
        Action::Sharing => &[
            "mint",
            "shareholders",
            "mode",
            "frontRunningProtection",
            "tipAmount",
        ][..],
    };
    if let Some(field) = r.keys().find(|field| !allowed.contains(&field.as_str())) {
        return Err(bad(format!("unsupported field {field}")));
    }
    let front = optional_bool(r, "frontRunningProtection")?.unwrap_or(false);
    let tip_lamports = tip_lamports(r)?;
    if !front && tip_lamports != 0 {
        return Err(bad("tipAmount requires frontRunningProtection"));
    }
    r.insert("frontRunningProtection".into(), json!(front));
    r.insert(
        "tipAmount".into(),
        Value::Number(
            serde_json::Number::from_f64(tip_lamports as f64 / 1_000_000_000.0)
                .ok_or_else(|| bad("invalid tipAmount"))?,
        ),
    );
    r.insert("user".into(), json!(user));
    r.insert("encoding".into(), json!("base64"));
    if matches!(a, Action::Create | Action::Buy | Action::Sell) {
        r.insert("feePayer".into(), json!(user));
    }
    match a {
        Action::Create => {
            text(r, "name", 1, 64)?;
            text(r, "symbol", 1, 16)?;
            text(r, "uri", 1, 512)?;
            number(r, "solLamports", 1)?;
            let mayhem = optional_bool(r, "mayhemMode")?.unwrap_or(false);
            let cashback = optional_bool(r, "cashback")?.unwrap_or(false);
            let tokenized = optional_bool(r, "tokenizedAgent")?.unwrap_or(false);
            let buyback = match r.get("buybackBps") {
                Some(value) => value
                    .as_u64()
                    .filter(|value| *value <= 10_000)
                    .ok_or_else(|| bad("buybackBps must be an integer from 0 to 10000"))?,
                None => 5_000,
            };
            if !tokenized && r.contains_key("buybackBps") {
                return Err(bad("buybackBps requires tokenizedAgent"));
            }
            r.insert("mayhemMode".into(), json!(mayhem));
            r.insert("cashback".into(), json!(cashback));
            r.insert("tokenizedAgent".into(), json!(tokenized));
            r.insert("buybackBps".into(), json!(buyback));
            r.insert("creator".into(), json!(user));
        }
        Action::Buy | Action::Sell => {
            let mint = text(r, "mint", 32, 64)?;
            pk(&mint).map_err(bad)?;
            let amount = number(r, "amount", 1)?;
            let slip = r.get("slippagePct").and_then(Value::as_f64).unwrap_or(2.0);
            if !slip.is_finite() || !(0.0..=50.0).contains(&slip) {
                return Err(bad("slippagePct must be 0..=50"));
            }
            r.insert(
                "slippagePct".into(),
                Value::Number(
                    serde_json::Number::from_f64(slip).ok_or_else(|| bad("invalid slippagePct"))?,
                ),
            );
            if matches!(a, Action::Buy) {
                r.insert("inputMint".into(), json!(SOL));
                r.insert("outputMint".into(), json!(mint));
            } else {
                r.insert("inputMint".into(), json!(mint));
                r.insert("outputMint".into(), json!(SOL));
            }
            r.insert("amount".into(), json!(amount));
            r.remove("mint");
        }
        Action::Fees => {
            pk(&text(r, "mint", 32, 64)?).map_err(bad)?;
        }
        Action::Sharing => {
            pk(&text(r, "mint", 32, 64)?).map_err(bad)?;
            if let Some(mode) = r.get("mode")
                && !matches!(mode.as_str(), Some("create" | "update"))
            {
                return Err(bad("mode must be create or update"));
            }
            let Some(Value::Array(v)) = r.get("shareholders") else {
                return Err(bad("shareholders required"));
            };
            if v.is_empty() || v.len() > 10 {
                return Err(bad("1..=10 shareholders required"));
            }
            let mut total = 0u64;
            let mut addresses = BTreeSet::new();
            for x in v {
                let o = x.as_object().ok_or_else(|| bad("invalid shareholder"))?;
                if o.keys()
                    .any(|field| !matches!(field.as_str(), "address" | "bps"))
                {
                    return Err(bad("unsupported shareholder field"));
                }
                let address = o
                    .get("address")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("shareholder address required"))?;
                pk(address).map_err(bad)?;
                if !addresses.insert(address) {
                    return Err(bad("duplicate shareholder address"));
                }
                let bps = o
                    .get("bps")
                    .and_then(Value::as_u64)
                    .filter(|bps| (1..=10_000).contains(bps))
                    .ok_or_else(|| bad("shareholder bps must be an integer from 1 to 10000"))?;
                total = total
                    .checked_add(bps)
                    .ok_or_else(|| bad("shareholder bps overflow"))?;
            }
            if total != 10000 {
                return Err(bad("shareholder bps must total 10000"));
            }
        }
    }
    Ok(())
}
fn optional_bool(r: &Map<String, Value>, n: &str) -> Result<Option<bool>, DispatchResponse> {
    r.get(n)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| bad(format!("{n} must be boolean")))
        })
        .transpose()
}
fn tip_lamports(r: &Map<String, Value>) -> Result<u64, DispatchResponse> {
    let Some(value) = r.get("tipAmount") else {
        return Ok(0);
    };
    let tip = value
        .as_f64()
        .filter(|tip| tip.is_finite() && *tip >= 0.0 && *tip <= 0.01)
        .ok_or_else(|| bad("tipAmount must be a number from 0 to 0.01 SOL"))?;
    let lamports = tip * 1_000_000_000.0;
    if (lamports.round() - lamports).abs() > 0.000_001 {
        return Err(bad("tipAmount supports at most 9 decimal places"));
    }
    Ok(lamports.round() as u64)
}
fn text(
    r: &Map<String, Value>,
    n: &str,
    min: usize,
    max: usize,
) -> Result<String, DispatchResponse> {
    let s = r
        .get(n)
        .and_then(Value::as_str)
        .ok_or_else(|| bad(format!("{n} string required")))?;
    if s.len() < min || s.len() > max || s.chars().any(char::is_control) {
        Err(bad(format!("invalid {n}")))
    } else {
        Ok(s.into())
    }
}
fn number(r: &Map<String, Value>, n: &str, min: u64) -> Result<String, DispatchResponse> {
    let s = text(r, n, 1, 24)?;
    let v = s.parse::<u64>().map_err(|_| bad(format!("invalid {n}")))?;
    if v < min {
        Err(bad(format!("{n} too small")))
    } else {
        Ok(s)
    }
}
fn effects(a: Action, r: &Map<String, Value>, message: &Msg) -> Result<Vec<Value>, String> {
    let tip = tip_lamports(r).map_err(|_| "invalid normalized tipAmount")?;
    let mut effects = match a {
        Action::Create | Action::Buy => {
            let trade = message
                .instructions
                .iter()
                .find(|ix| has_discriminator(ix, IX_BUY))
                .ok_or_else(|| "approved buy instruction missing".to_owned())
                .and_then(|ix| instruction_u64(ix, 16))?;
            let total = trade.checked_add(tip).ok_or("native debit exceeds u64")?;
            vec![json!({"asset":{"chain":"solana","asset":"native"},"amount":total.to_string()})]
        }
        Action::Sell => vec![json!({
            "asset":{"chain":"solana","asset":r.get("inputMint").and_then(Value::as_str).ok_or("sell mint missing")?},
            "amount":r.get("amount").and_then(Value::as_str).ok_or("sell amount missing")?
        })],
        Action::Fees | Action::Sharing => vec![],
    };
    if tip > 0 && !matches!(a, Action::Create | Action::Buy) {
        effects.push(json!({
            "asset":{"chain":"solana","asset":"native"},
            "amount":tip.to_string()
        }));
    }
    Ok(effects)
}
fn destinations(message: &Msg) -> Vec<Value> {
    let system = pk(PROGRAMS[1]).ok();
    let tips = JITO_TIPS
        .iter()
        .filter_map(|tip| pk(tip).ok())
        .collect::<Vec<_>>();
    let protocol = PROGRAMS[5..]
        .iter()
        .filter_map(|program| pk(program).ok())
        .collect::<Vec<_>>();
    let mut values = BTreeSet::new();
    for ix in &message.instructions {
        let Some(program) = message.keys.get(ix.program) else {
            continue;
        };
        if protocol.contains(program) {
            values.insert(bs58::encode(program).into_string());
        }
        if Some(program) == system.as_ref()
            && let Ok(destination) = account(message, ix, 1)
            && tips.contains(destination)
        {
            values.insert(bs58::encode(destination).into_string());
        }
    }
    values
        .into_iter()
        .map(|destination| json!({"chain":"solana","destination":destination}))
        .collect()
}
fn publish(w: &str, s: &str, o: &str, a: Action, p: &Pending) -> Result<(), DispatchResponse> {
    put(
        &sk(w, s, &format!("operations/{o}.json")),
        &Public {
            schema: "bloom.pumpfun_operation.v1".into(),
            action: a.class().into(),
            status: p.status.clone(),
            signature: p.signature.clone(),
            api: p.api.clone(),
            updated_ms: petal::sdk::now_ms(),
        },
        false,
    )
}
pub fn read_operation(w: &str, s: &str, o: &str) -> DispatchResponse {
    let key = sk(w, s, &format!("operations/{o}.json"));
    let mut operation = match get::<Public>(&key) {
        Ok(Some(value)) => value,
        Ok(None) => return bad("operation not found"),
        Err(e) => return e,
    };
    if matches!(
        operation.status.as_str(),
        "broadcast_attempted" | "submitted"
    ) && let Some(signature) = operation.signature.as_deref()
        && let Ok(status) = post(
            RPC,
            &rpc(
                "getSignatureStatuses",
                json!([[signature], {"searchTransactionHistory":true}]),
            ),
        )
        && let Some(value) = status.pointer("/result/value/0")
        && !value.is_null()
    {
        let next = if value.get("err").is_some_and(|error| !error.is_null()) {
            "chain_failed"
        } else {
            match value.get("confirmationStatus").and_then(Value::as_str) {
                Some("finalized") => "finalized",
                Some("confirmed") => "confirmed",
                _ => operation.status.as_str(),
            }
        };
        if next != operation.status {
            operation.status = next.into();
            operation.updated_ms = petal::sdk::now_ms();
            if let Err(e) = put(&key, &operation, false) {
                return e;
            }
        }
    }
    petal::read_json_value(&operation)
}
pub fn status() -> DispatchResponse {
    petal::read_json_value(&json!({
        "schema":"bloom.pumpfun_status.v1",
        "ok":true,
        "network":"solana-mainnet",
        "writes":"session-scoped"
    }))
}
pub fn coin(m: &str) -> DispatchResponse {
    if pk(m).is_err() {
        return bad("invalid mint");
    };
    match fetch("GET", format!("{COINS}/{m}"), vec![]) {
        Ok(v) => petal::read_json_value(&v),
        Err(e) => e,
    }
}
fn stored_children(prefix: &str, suffix: Option<&str>) -> Result<Vec<String>, DispatchResponse> {
    let keys = petal::sdk::store_list(prefix, MAX).map_err(|error| fail(error.message()))?;
    let mut children = keys
        .into_iter()
        .filter_map(|key| key.strip_prefix(prefix).map(str::to_owned))
        .filter_map(|rest| match suffix {
            Some(suffix) => rest.strip_suffix(suffix).map(str::to_owned),
            None => rest.split('/').next().map(str::to_owned),
        })
        .filter(|child| ident(child, "stored id").is_ok())
        .collect::<Vec<_>>();
    children.sort();
    children.dedup();
    Ok(children)
}
pub fn list_wallets() -> Result<Vec<petal::RouteChild>, DispatchResponse> {
    stored_children("state/sessions/", None)
        .map(|children| children.into_iter().map(petal::dir).collect())
}
pub fn list_sessions(c: &Ctx) -> Result<Vec<petal::RouteChild>, DispatchResponse> {
    let wallet = wallet(c)?;
    stored_children(&format!("state/sessions/{wallet}/"), None)
        .map(|children| children.into_iter().map(petal::dir).collect())
}
pub fn list_operations(c: &Ctx) -> Result<Vec<petal::RouteChild>, DispatchResponse> {
    let wallet = wallet(c)?;
    let session = session(c)?;
    stored_children(
        &format!("state/sessions/{wallet}/{session}/operations/"),
        Some(".json"),
    )
    .map(|children| {
        children
            .into_iter()
            .map(|id| petal::file(format!("{id}.json")))
            .collect()
    })
}
fn rpc(m: &str, p: Value) -> Value {
    json!({"jsonrpc":"2.0","id":"bloom-pumpfun","method":m,"params":p})
}
fn transaction_fee(transaction: &str) -> Result<u64, DispatchResponse> {
    let raw = B64
        .decode(transaction)
        .map_err(|_| fail("builder transaction is not base64"))?;
    let env = envelope(&raw).map_err(fail)?;
    let response = post(
        RPC,
        &rpc(
            "getFeeForMessage",
            json!([B64.encode(env.message), {"commitment":"processed"}]),
        ),
    )?;
    response
        .pointer("/result/value")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("Solana RPC did not quote the transaction fee"))
}
fn simulate(tx: &str) -> Result<(), DispatchResponse> {
    let v = post(
        RPC,
        &rpc(
            "simulateTransaction",
            json!([tx,{"encoding":"base64","sigVerify":true,"commitment":"processed"}]),
        ),
    )?;
    if v.pointer("/result/value/err").is_none_or(Value::is_null) {
        Ok(())
    } else {
        Err(fail(format!("simulation failed: {}", safe(&v))))
    }
}
struct Env<'a> {
    sig_offset: usize,
    message: &'a [u8],
    blockhash: [u8; 32],
}
struct Msg {
    keys: Vec<[u8; 32]>,
    instructions: Vec<Ix>,
    blockhash: [u8; 32],
    required: usize,
}
struct Ix {
    program: usize,
    accounts: Vec<u8>,
    data: Vec<u8>,
}
fn short(b: &[u8], o: &mut usize) -> Result<usize, String> {
    let mut n = 0;
    for shift in [0, 7, 14] {
        let x = *b.get(*o).ok_or("truncated shortvec")?;
        *o += 1;
        n |= ((x & 127) as usize) << shift;
        if x & 128 == 0 {
            return Ok(n);
        }
    }
    Err("invalid shortvec".into())
}
fn envelope(b: &[u8]) -> Result<Env<'_>, String> {
    if b.len() > MAX_TX {
        return Err("transaction exceeds packet limit".into());
    }
    let mut o = 0;
    let n = short(b, &mut o)?;
    if !(1..=2).contains(&n) {
        return Err("unexpected signer count".into());
    }
    let sig = o;
    let end = o + n * 64;
    let ss = b.get(o..end).ok_or("truncated signatures")?;
    if ss[..64].iter().any(|x| *x != 0) || n == 2 && ss[64..].iter().all(|x| *x == 0) {
        return Err("invalid partial signatures".into());
    }
    o = end;
    let m = message(&b[o..])?;
    if m.required != n {
        return Err("signer/header mismatch".into());
    }
    Ok(Env {
        sig_offset: sig,
        message: &b[o..],
        blockhash: m.blockhash,
    })
}
fn message(b: &[u8]) -> Result<Msg, String> {
    let mut o = 0;
    if b.first() != Some(&128) {
        return Err("only v0 transactions accepted".into());
    }
    o += 1;
    let required = *b.get(o).ok_or("header missing")? as usize;
    o += 3;
    let n = short(b, &mut o)?;
    if n == 0 || n > 128 {
        return Err("invalid key count".into());
    }
    let mut keys = vec![];
    for _ in 0..n {
        keys.push(
            b.get(o..o + 32)
                .ok_or("truncated key")?
                .try_into()
                .map_err(|_| "invalid key length")?,
        );
        o += 32
    }
    let blockhash = b
        .get(o..o + 32)
        .ok_or("truncated blockhash")?
        .try_into()
        .map_err(|_| "invalid blockhash length")?;
    o += 32;
    let ni = short(b, &mut o)?;
    let mut instructions = vec![];
    for _ in 0..ni {
        let program = *b.get(o).ok_or("missing program")? as usize;
        o += 1;
        let a = short(b, &mut o)?;
        let accounts = b
            .get(o..o + a)
            .ok_or("truncated instruction accounts")?
            .to_vec();
        o += a;
        let d = short(b, &mut o)?;
        let data = b
            .get(o..o + d)
            .ok_or("truncated instruction data")?
            .to_vec();
        o += d;
        instructions.push(Ix {
            program,
            accounts,
            data,
        });
    }
    let nl = short(b, &mut o)?;
    for _ in 0..nl {
        o += 32;
        let w = short(b, &mut o)?;
        o += w;
        let r = short(b, &mut o)?;
        o += r;
        if o > b.len() {
            return Err("truncated lookup".into());
        }
    }
    if o != b.len() {
        return Err("trailing message bytes".into());
    }
    Ok(Msg {
        keys,
        instructions,
        blockhash,
        required,
    })
}
const IX_BUY: [u8; 8] = [102, 6, 61, 18, 1, 218, 235, 234];
const IX_SELL: [u8; 8] = [51, 230, 133, 164, 1, 127, 131, 173];
const IX_CREATE_V2: [u8; 8] = [214, 144, 76, 236, 95, 139, 49, 180];
const IX_CLAIM_CASHBACK: [u8; 8] = [37, 58, 35, 126, 190, 53, 228, 197];
const IX_COLLECT_CREATOR_FEE: [u8; 8] = [20, 22, 86, 123, 198, 28, 219, 132];
const IX_AMM_COLLECT_CREATOR_FEE: [u8; 8] = [160, 57, 89, 42, 181, 139, 43, 66];
const IX_DISTRIBUTE_CREATOR_FEES: [u8; 8] = [165, 114, 103, 0, 121, 206, 247, 81];
const IX_CREATE_SHARING: [u8; 8] = [195, 78, 86, 76, 111, 52, 251, 213];
const IX_UPDATE_SHARING: [u8; 8] = [189, 13, 136, 99, 187, 164, 237, 35];
const IX_MIGRATE_BONDING_CREATOR: [u8; 8] = [87, 124, 52, 191, 52, 38, 214, 232];
const IX_MIGRATE_POOL_CREATOR: [u8; 8] = [208, 8, 159, 4, 74, 175, 16, 58];
const IX_AGENT_INITIALIZE: [u8; 8] = [180, 248, 163, 8, 49, 94, 126, 96];

fn has_discriminator(ix: &Ix, discriminator: [u8; 8]) -> bool {
    ix.data.starts_with(&discriminator)
}
fn account<'a>(m: &'a Msg, ix: &Ix, position: usize) -> Result<&'a [u8; 32], String> {
    let index = *ix
        .accounts
        .get(position)
        .ok_or_else(|| format!("instruction account {position} missing"))? as usize;
    m.keys
        .get(index)
        .ok_or_else(|| format!("instruction account {position} is lookup-loaded"))
}
fn require_account(
    m: &Msg,
    ix: &Ix,
    position: usize,
    expected: &[u8; 32],
    label: &str,
) -> Result<(), String> {
    if account(m, ix, position)? == expected {
        Ok(())
    } else {
        Err(format!("{label} account mismatch"))
    }
}
fn validate_tx(
    transaction: &str,
    user: &str,
    action: Action,
    request: &Map<String, Value>,
    response: &Value,
) -> Result<(), String> {
    let raw = B64.decode(transaction).map_err(|_| "invalid base64")?;
    let env = envelope(&raw)?;
    let message = message(env.message)?;
    let payer = pk(user)?;
    if message.keys.first() != Some(&payer) {
        return Err("payer is not session key".into());
    }
    let mint_text = if matches!(action, Action::Create) {
        response
            .get("mintPublicKey")
            .and_then(Value::as_str)
            .ok_or("mint missing")?
    } else {
        request
            .get("mint")
            .or_else(|| {
                request
                    .get("inputMint")
                    .filter(|mint| mint.as_str() != Some(SOL))
            })
            .or_else(|| {
                request
                    .get("outputMint")
                    .filter(|mint| mint.as_str() != Some(SOL))
            })
            .and_then(Value::as_str)
            .ok_or("requested mint missing")?
    };
    let mint = pk(mint_text)?;
    if matches!(action, Action::Create) && message.keys.get(1) != Some(&mint) {
        return Err("mint signer mismatch".into());
    }
    validate_message(&message, &payer, &mint, action, request, response)
}
fn validate_message(
    message: &Msg,
    payer: &[u8; 32],
    mint: &[u8; 32],
    action: Action,
    request: &Map<String, Value>,
    response: &Value,
) -> Result<(), String> {
    let allowed = PROGRAMS
        .iter()
        .map(|program| pk(program))
        .collect::<Result<Vec<_>, _>>()?;
    for ix in &message.instructions {
        let program = message
            .keys
            .get(ix.program)
            .ok_or("program is lookup-loaded")?;
        if !allowed.contains(program) {
            return Err(format!(
                "unapproved program {}",
                bs58::encode(program).into_string()
            ));
        }
    }
    validate_compute_budget(message, request)?;
    let wrapped_accounts = validate_system_transfers(message, payer, action, request)?;
    validate_auxiliary_instructions(
        message,
        payer,
        mint,
        action,
        request,
        response,
        &wrapped_accounts,
    )?;
    validate_protocol_instructions(message, payer, mint, action, request, response)
}
fn validate_compute_budget(message: &Msg, request: &Map<String, Value>) -> Result<(), String> {
    let compute = pk(PROGRAMS[0])?;
    let dont_front = pk(JITO_DONT_FRONT)?;
    let protected = request
        .get("frontRunningProtection")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut limit = None;
    let mut price = None;
    for ix in &message.instructions {
        if message.keys.get(ix.program) != Some(&compute) {
            continue;
        }
        match ix.data.as_slice() {
            [2, rest @ ..] if rest.len() == 4 => {
                if limit.is_some() {
                    return Err("duplicate compute-unit limit".into());
                }
                let bytes: [u8; 4] = rest.try_into().map_err(|_| "invalid compute limit")?;
                let value = u32::from_le_bytes(bytes);
                if value == 0 || value > 1_400_000 {
                    return Err("compute-unit limit exceeds Solana bounds".into());
                }
                match ix.accounts.as_slice() {
                    [] => {}
                    [index]
                        if protected && message.keys.get(*index as usize) == Some(&dont_front) => {}
                    _ => return Err("invalid compute-budget accounts".into()),
                }
                limit = Some(value as u64);
            }
            [3, rest @ ..] if rest.len() == 8 && ix.accounts.is_empty() => {
                if price.is_some() {
                    return Err("duplicate compute-unit price".into());
                }
                let bytes: [u8; 8] = rest.try_into().map_err(|_| "invalid compute price")?;
                price = Some(u64::from_le_bytes(bytes));
            }
            _ => return Err("unsupported compute-budget instruction".into()),
        }
    }
    let (limit, price) = (
        limit.ok_or("compute-unit limit missing")?,
        price.ok_or("compute-unit price missing")?,
    );
    let priority_fee = (u128::from(limit) * u128::from(price)).div_ceil(1_000_000);
    if priority_fee > u128::from(MAX_PRIORITY_FEE_LAMPORTS) {
        return Err("priority fee exceeds 0.005 SOL".into());
    }
    Ok(())
}
fn validate_system_transfers(
    message: &Msg,
    payer: &[u8; 32],
    action: Action,
    request: &Map<String, Value>,
) -> Result<Vec<[u8; 32]>, String> {
    let system = pk(PROGRAMS[1])?;
    let tips = JITO_TIPS
        .iter()
        .map(|tip| pk(tip))
        .collect::<Result<Vec<_>, _>>()?;
    let expected_tip = tip_lamports(request).map_err(|_| "invalid normalized tipAmount")?;
    let mut tip_count = 0usize;
    let mut wrapped = Vec::new();
    let mut wrapped_total = 0u128;
    for ix in &message.instructions {
        if message.keys.get(ix.program) != Some(&system) {
            continue;
        }
        if ix.data.len() != 12 || ix.data[..4] != 2u32.to_le_bytes() || ix.accounts.len() != 2 {
            return Err("unsupported direct System instruction".into());
        }
        let from = account(message, ix, 0)?;
        let to = account(message, ix, 1)?;
        if from != payer {
            return Err("System debit is not from session key".into());
        }
        let amount_bytes: [u8; 8] = ix.data[4..]
            .try_into()
            .map_err(|_| "invalid System transfer amount")?;
        let amount = u64::from_le_bytes(amount_bytes);
        if tips.contains(to) {
            if amount != expected_tip {
                return Err("Jito tip differs from request".into());
            }
            tip_count += 1;
        } else {
            if !matches!(action, Action::Buy) {
                return Err("unexpected direct SOL transfer".into());
            }
            wrapped.push(*to);
            wrapped_total += u128::from(amount);
        }
    }
    let expected_tip_count = usize::from(expected_tip > 0);
    if tip_count != expected_tip_count {
        return Err("Jito tip count differs from request".into());
    }
    if wrapped_total > max_buy_lamports(request)? {
        return Err("wrapped SOL transfer exceeds requested buy and slippage".into());
    }
    Ok(wrapped)
}
fn max_buy_lamports(request: &Map<String, Value>) -> Result<u128, String> {
    let Some(amount) = request.get("amount").and_then(Value::as_str) else {
        return Ok(0);
    };
    let amount = amount
        .parse::<u64>()
        .map_err(|_| "invalid normalized amount")?;
    let slippage = request
        .get("slippagePct")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let slippage_millionths = (slippage * 1_000_000.0).ceil() as u128;
    let extra = (u128::from(amount) * slippage_millionths).div_ceil(100_000_000);
    Ok(u128::from(amount) + extra)
}
fn validate_auxiliary_instructions(
    message: &Msg,
    payer: &[u8; 32],
    mint: &[u8; 32],
    action: Action,
    _request: &Map<String, Value>,
    response: &Value,
    wrapped_accounts: &[[u8; 32]],
) -> Result<(), String> {
    let system = pk(PROGRAMS[1])?;
    let associated = pk(PROGRAMS[2])?;
    let token = pk(PROGRAMS[3])?;
    let token_2022 = pk(PROGRAMS[4])?;
    let wrapped_mint = pk(SOL)?;
    let mut closeable_wsol_accounts = wrapped_accounts.to_vec();
    let mut associated_count = 0usize;
    for ix in &message.instructions {
        let program = message
            .keys
            .get(ix.program)
            .ok_or("program is lookup-loaded")?;
        if program == &associated {
            associated_count += 1;
            if ix.data != [1] || ix.accounts.len() != 6 {
                return Err("only idempotent associated-token creation is allowed".into());
            }
            require_account(message, ix, 0, payer, "associated-token payer")?;
            let owner = account(message, ix, 2)?;
            let account_mint = account(message, ix, 3)?;
            if let Ok(system_program) = account(message, ix, 4)
                && system_program != &system
            {
                return Err("associated-token System program mismatch".into());
            }
            if let Ok(token_program) = account(message, ix, 5)
                && token_program != &token
                && token_program != &token_2022
            {
                return Err("unapproved associated-token program".into());
            }
            let mint_allowed = match action {
                Action::Create => account_mint == mint,
                Action::Buy | Action::Sell => account_mint == mint || account_mint == &wrapped_mint,
                Action::Fees | Action::Sharing => account_mint == &wrapped_mint,
            };
            if !mint_allowed {
                return Err("associated-token mint is unrelated to the request".into());
            }
            let owner_allowed = owner == payer
                || matches!(action, Action::Fees | Action::Sharing)
                    && ["creator", "sharingConfigAddress"]
                        .iter()
                        .filter_map(|field| response.get(field).and_then(Value::as_str))
                        .filter_map(|value| pk(value).ok())
                        .any(|value| &value == owner);
            if !owner_allowed {
                return Err("associated-token owner is unrelated to the request".into());
            }
            if account_mint == &wrapped_mint && owner == payer {
                closeable_wsol_accounts.push(*account(message, ix, 1)?);
            }
        } else if program == &token_2022 {
            return Err("direct Token-2022 instructions are not allowed".into());
        } else if program == &token {
            match ix.data.as_slice() {
                [17] if ix.accounts.len() == 1 => {
                    if !wrapped_accounts.contains(account(message, ix, 0)?) {
                        return Err("SyncNative account was not funded by this transaction".into());
                    }
                }
                [9] if ix.accounts.len() == 3 => {
                    if !closeable_wsol_accounts.contains(account(message, ix, 0)?) {
                        return Err(
                            "CloseAccount is not for a session-owned wrapped-SOL account".into(),
                        );
                    }
                    require_account(message, ix, 1, payer, "CloseAccount destination")?;
                    require_account(message, ix, 2, payer, "CloseAccount authority")?;
                }
                _ => return Err("unsupported direct SPL-token instruction".into()),
            }
        }
    }
    if associated_count > 2 {
        return Err("too many associated-token creations".into());
    }
    for wrapped in wrapped_accounts {
        let synced = message.instructions.iter().any(|ix| {
            message.keys.get(ix.program) == Some(&token)
                && ix.data == [17]
                && account(message, ix, 0).ok() == Some(wrapped)
        });
        let closed = message.instructions.iter().any(|ix| {
            message.keys.get(ix.program) == Some(&token)
                && ix.data == [9]
                && account(message, ix, 0).ok() == Some(wrapped)
                && account(message, ix, 1).ok() == Some(payer)
                && account(message, ix, 2).ok() == Some(payer)
        });
        if !synced || !closed {
            return Err("wrapped-SOL account must be synced and closed to the session".into());
        }
    }
    Ok(())
}
fn validate_protocol_instructions(
    message: &Msg,
    payer: &[u8; 32],
    mint: &[u8; 32],
    action: Action,
    request: &Map<String, Value>,
    response: &Value,
) -> Result<(), String> {
    let pump = pk(PROGRAMS[5])?;
    let amm = pk(PROGRAMS[6])?;
    let fees = pk(PROGRAMS[7])?;
    let agent = pk(PROGRAMS[8])?;
    let wrapped_mint = pk(SOL)?;
    let mut primary = 0usize;
    let mut create = 0usize;
    let mut agent_initialize = 0usize;
    let mut sharing_create = 0usize;
    let mut sharing_update = 0usize;
    for ix in &message.instructions {
        let program = message
            .keys
            .get(ix.program)
            .ok_or("program is lookup-loaded")?;
        match action {
            Action::Create if program == &pump && has_discriminator(ix, IX_CREATE_V2) => {
                require_account(message, ix, 0, mint, "create mint")?;
                require_account(message, ix, 5, payer, "create user")?;
                validate_create_data(ix, payer, request)?;
                create += 1;
            }
            Action::Create if program == &pump && has_discriminator(ix, IX_BUY) => {
                require_account(message, ix, 2, mint, "initial-buy mint")?;
                require_account(message, ix, 6, payer, "initial-buy user")?;
                let requested = request_u64(request, "solLamports")?;
                let maximum = u128::from(requested) + (u128::from(requested) * 2).div_ceil(100);
                validate_buy_cost(ix, maximum)?;
                primary += 1;
            }
            Action::Create if program == &agent && has_discriminator(ix, IX_AGENT_INITIALIZE) => {
                require_account(message, ix, 0, payer, "agent user")?;
                require_account(message, ix, 3, mint, "agent mint")?;
                validate_agent_initialize_data(ix, payer, request)?;
                agent_initialize += 1;
            }
            Action::Buy if program == &pump && has_discriminator(ix, IX_BUY) => {
                require_account(message, ix, 2, mint, "buy mint")?;
                require_account(message, ix, 6, payer, "buy user")?;
                validate_buy_cost(ix, max_buy_lamports(request)?)?;
                primary += 1;
            }
            Action::Buy if program == &amm && has_discriminator(ix, IX_BUY) => {
                require_account(message, ix, 1, payer, "AMM buy user")?;
                require_account(message, ix, 3, mint, "AMM buy mint")?;
                require_account(message, ix, 4, &wrapped_mint, "AMM buy quote mint")?;
                validate_buy_cost(ix, max_buy_lamports(request)?)?;
                primary += 1;
            }
            Action::Sell if program == &pump && has_discriminator(ix, IX_SELL) => {
                require_account(message, ix, 2, mint, "sell mint")?;
                require_account(message, ix, 6, payer, "sell user")?;
                validate_sell_amount(ix, request_u64(request, "amount")?)?;
                primary += 1;
            }
            Action::Sell if program == &amm && has_discriminator(ix, IX_SELL) => {
                require_account(message, ix, 1, payer, "AMM sell user")?;
                require_account(message, ix, 3, mint, "AMM sell mint")?;
                require_account(message, ix, 4, &wrapped_mint, "AMM sell quote mint")?;
                validate_sell_amount(ix, request_u64(request, "amount")?)?;
                primary += 1;
            }
            Action::Fees if program == &pump && has_discriminator(ix, IX_CLAIM_CASHBACK) => {
                require_account(message, ix, 0, payer, "cashback user")?;
                primary += 1;
            }
            Action::Fees if program == &pump && has_discriminator(ix, IX_COLLECT_CREATOR_FEE) => {
                primary += 1;
            }
            Action::Fees
                if program == &pump && has_discriminator(ix, IX_DISTRIBUTE_CREATOR_FEES) =>
            {
                require_account(message, ix, 0, mint, "fee-distribution mint")?;
                primary += 1;
            }
            Action::Fees if program == &amm && has_discriminator(ix, IX_CLAIM_CASHBACK) => {
                require_account(message, ix, 0, payer, "AMM cashback user")?;
                require_account(message, ix, 2, &wrapped_mint, "AMM cashback quote mint")?;
                primary += 1;
            }
            Action::Fees
                if program == &amm && has_discriminator(ix, IX_AMM_COLLECT_CREATOR_FEE) =>
            {
                require_account(message, ix, 0, &wrapped_mint, "AMM fee quote mint")?;
                primary += 1;
            }
            Action::Sharing if program == &fees && has_discriminator(ix, IX_CREATE_SHARING) => {
                require_account(message, ix, 2, payer, "fee-sharing authority")?;
                require_account(message, ix, 4, mint, "fee-sharing mint")?;
                if ix.data.len() != 8 {
                    return Err("fee-sharing create has unexpected data".into());
                }
                sharing_create += 1;
            }
            Action::Sharing if program == &fees && has_discriminator(ix, IX_UPDATE_SHARING) => {
                require_account(message, ix, 2, payer, "fee-sharing authority")?;
                require_account(message, ix, 4, mint, "fee-sharing mint")?;
                validate_shareholders(ix, request)?;
                sharing_update += 1;
            }
            Action::Sharing
                if program == &pump && has_discriminator(ix, IX_MIGRATE_BONDING_CREATOR) =>
            {
                require_account(message, ix, 0, mint, "creator-migration mint")?;
            }
            Action::Sharing
                if program == &amm && has_discriminator(ix, IX_MIGRATE_POOL_CREATOR) => {}
            _ if [pump, amm, fees, agent].contains(program) => {
                return Err("protocol instruction is incompatible with requested action".into());
            }
            _ => {}
        }
    }
    match action {
        Action::Create => {
            let tokenized = request
                .get("tokenizedAgent")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if create != 1 || primary != 1 || agent_initialize != usize::from(tokenized) {
                return Err("create transaction has an unexpected instruction shape".into());
            }
        }
        Action::Buy | Action::Sell if primary != 1 => {
            return Err("swap transaction must contain exactly one matching swap".into());
        }
        Action::Fees if primary == 0 => {
            return Err("fee transaction contains no supported fee operation".into());
        }
        _ => {}
    }
    if matches!(action, Action::Sharing) {
        if sharing_update != 1 || sharing_create > 1 {
            return Err("sharing transaction has an unexpected instruction shape".into());
        }
        let inferred_mode = if sharing_create == 1 {
            "create"
        } else {
            "update"
        };
        if let Some(requested_mode) = request.get("mode").and_then(Value::as_str)
            && requested_mode != inferred_mode
        {
            return Err("sharing transaction mode differs from request".into());
        }
        if let Some(reported_mode) = response.get("mode").and_then(Value::as_str)
            && reported_mode != inferred_mode
        {
            return Err("sharing response mode differs from transaction".into());
        }
    }
    Ok(())
}
fn instruction_u64(ix: &Ix, offset: usize) -> Result<u64, String> {
    let bytes: [u8; 8] = ix
        .data
        .get(offset..offset + 8)
        .ok_or("instruction amount missing")?
        .try_into()
        .map_err(|_| "instruction amount has invalid length")?;
    Ok(u64::from_le_bytes(bytes))
}
fn request_u64(request: &Map<String, Value>, field: &str) -> Result<u64, String> {
    request
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("normalized {field} missing"))?
        .parse()
        .map_err(|_| format!("normalized {field} invalid"))
}
fn validate_buy_cost(ix: &Ix, maximum: u128) -> Result<(), String> {
    let max_sol_cost = instruction_u64(ix, 16)?;
    if max_sol_cost == 0 || u128::from(max_sol_cost) > maximum {
        Err("buy maximum SOL cost exceeds the approved request".into())
    } else {
        Ok(())
    }
}
fn validate_sell_amount(ix: &Ix, requested: u64) -> Result<(), String> {
    if instruction_u64(ix, 8)? == requested {
        Ok(())
    } else {
        Err("sell amount differs from request".into())
    }
}
fn take<'a>(data: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8], String> {
    let end = offset
        .checked_add(length)
        .ok_or("instruction data offset overflow")?;
    let value = data.get(*offset..end).ok_or("instruction data truncated")?;
    *offset = end;
    Ok(value)
}
fn borsh_string(data: &[u8], offset: &mut usize) -> Result<String, String> {
    let length_bytes: [u8; 4] = take(data, offset, 4)?
        .try_into()
        .map_err(|_| "string length missing")?;
    let length = u32::from_le_bytes(length_bytes) as usize;
    std::str::from_utf8(take(data, offset, length)?)
        .map(str::to_owned)
        .map_err(|_| "instruction string is not UTF-8".into())
}
fn validate_create_data(
    ix: &Ix,
    payer: &[u8; 32],
    request: &Map<String, Value>,
) -> Result<(), String> {
    let mut offset = 8;
    for field in ["name", "symbol", "uri"] {
        let actual = borsh_string(&ix.data, &mut offset)?;
        if request.get(field).and_then(Value::as_str) != Some(actual.as_str()) {
            return Err(format!("create {field} differs from request"));
        }
    }
    if take(&ix.data, &mut offset, 32)? != payer {
        return Err("create creator differs from session key".into());
    }
    let mayhem = take(&ix.data, &mut offset, 1)?[0];
    let cashback = take(&ix.data, &mut offset, 1)?[0];
    if mayhem > 1 || cashback > 1 || offset != ix.data.len() {
        return Err("create flags have invalid encoding".into());
    }
    if request.get("mayhemMode").and_then(Value::as_bool) != Some(mayhem == 1)
        || request.get("cashback").and_then(Value::as_bool) != Some(cashback == 1)
    {
        return Err("create flags differ from request".into());
    }
    Ok(())
}
fn validate_agent_initialize_data(
    ix: &Ix,
    payer: &[u8; 32],
    request: &Map<String, Value>,
) -> Result<(), String> {
    if ix.data.len() != 42 || ix.data.get(8..40) != Some(payer.as_slice()) {
        return Err("tokenized-agent authority differs from session key".into());
    }
    let buyback_bytes: [u8; 2] = ix.data[40..42]
        .try_into()
        .map_err(|_| "tokenized-agent buyback is missing")?;
    let requested = request
        .get("buybackBps")
        .and_then(Value::as_u64)
        .ok_or("normalized buybackBps missing")?;
    if u64::from(u16::from_le_bytes(buyback_bytes)) != requested {
        return Err("tokenized-agent buyback differs from request".into());
    }
    Ok(())
}
fn validate_shareholders(ix: &Ix, request: &Map<String, Value>) -> Result<(), String> {
    let expected = request
        .get("shareholders")
        .and_then(Value::as_array)
        .ok_or("normalized shareholders missing")?;
    let mut offset = 8;
    let count_bytes: [u8; 4] = take(&ix.data, &mut offset, 4)?
        .try_into()
        .map_err(|_| "shareholder count missing")?;
    if u32::from_le_bytes(count_bytes) as usize != expected.len() {
        return Err("shareholder count differs from request".into());
    }
    for shareholder in expected {
        let object = shareholder
            .as_object()
            .ok_or("normalized shareholder invalid")?;
        let address = pk(object
            .get("address")
            .and_then(Value::as_str)
            .ok_or("normalized shareholder address missing")?)?;
        if take(&ix.data, &mut offset, 32)? != address {
            return Err("shareholder address differs from request".into());
        }
        let bps_bytes: [u8; 2] = take(&ix.data, &mut offset, 2)?
            .try_into()
            .map_err(|_| "shareholder bps missing")?;
        if u64::from(u16::from_le_bytes(bps_bytes))
            != object
                .get("bps")
                .and_then(Value::as_u64)
                .ok_or("normalized shareholder bps missing")?
        {
            return Err("shareholder bps differs from request".into());
        }
    }
    if offset != ix.data.len() {
        return Err("unexpected trailing shareholder data".into());
    }
    Ok(())
}
pub fn route_action(c: &Ctx, b: &[u8], a: Action) -> DispatchResponse {
    if let Err(e) = body(b) {
        return e;
    }
    let w = match wallet(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let s = match session(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    execute(c, a, w, s, b)
}
pub fn route_session(c: &Ctx) -> DispatchResponse {
    let w = match wallet(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let s = match session(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    read_session(&w, &s)
}
pub fn route_stop(c: &Ctx) -> DispatchResponse {
    let w = match wallet(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let s = match session(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    stop(&w, &s)
}
pub fn route_operation(c: &Ctx) -> DispatchResponse {
    let w = match wallet(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let s = match session(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let o = match operation(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    read_operation(&w, &s, &o)
}
pub fn static_list(e: &[(&str, bool, bool)]) -> Vec<petal::RouteChild> {
    e.iter()
        .map(|(n, d, w)| {
            if *d {
                petal::dir(*n)
            } else if *w {
                petal::writable(*n)
            } else {
                petal::file(*n)
            }
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    const USER: &str = "AgenTMiC2hvxGebTsgmsD4HHBa8WEcqGFf87iwRRxLo7";
    const BOND_MINT: &str = "C8CMvu8FXZruHrNjFaixaDJjiveG6gKmUvT5BrK5pump";
    const AMM_MINT: &str = "H3m3TD2mwmU5zkUTHRDoLU7RdxbWp6BEgoQa3s9wpump";
    const AMM_CREATOR: &str = "7g5fP4E7B74M5rtNT7JrS1w9FK2Sobf7XzQLNVvQ5sHv";

    fn fixture(name: &str) -> Value {
        let fixtures: Value =
            serde_json::from_str(include_str!("../tests/pump-builder-fixtures.json"))
                .expect("fixture JSON must parse");
        fixtures.get(name).expect("fixture must exist").clone()
    }
    fn normalized_for(action: Action, user: &str, value: Value) -> Map<String, Value> {
        let mut request = value
            .as_object()
            .expect("request must be an object")
            .clone();
        if normalize(action, user, &mut request).is_err() {
            panic!("normalization failed");
        }
        request
    }
    fn normalized(action: Action, value: Value) -> Map<String, Value> {
        normalized_for(action, USER, value)
    }
    fn assert_fixture(name: &str, action: Action, request: Value) {
        assert_fixture_for(name, action, USER, request)
    }
    fn assert_fixture_for(name: &str, action: Action, user: &str, request: Value) {
        let response = fixture(name);
        let transaction = response
            .get("transaction")
            .and_then(Value::as_str)
            .expect("fixture transaction");
        let request = normalized_for(action, user, request);
        let result = validate_tx(transaction, user, action, &request, &response);
        assert!(result.is_ok(), "{name}: {result:?}");
    }

    #[test]
    fn keys() {
        assert!(pk(SOL).is_ok());
        assert!(PROGRAMS.iter().all(|p| pk(p).is_ok()));
        assert!(pk("bad").is_err())
    }
    #[test]
    fn ids() {
        assert!(ident("op-1", "id").is_ok());
        assert!(ident("../x", "id").is_err());
        assert!(ident("..", "id").is_err())
    }
    #[test]
    fn current_pump_builder_transactions_pass_policy() {
        assert_fixture(
            "create",
            Action::Create,
            json!({"name":"Bloom Fixture","symbol":"BLMF","uri":"https://example.com/pumpfun-fixture.json","solLamports":"1000000"}),
        );
        assert_fixture(
            "mayhem",
            Action::Create,
            json!({"name":"Bloom Mayhem Fixture","symbol":"BLMM","uri":"https://example.com/pumpfun-mayhem-fixture.json","solLamports":"1000000","mayhemMode":true,"frontRunningProtection":true,"tipAmount":0.0001}),
        );
        assert_fixture(
            "agent",
            Action::Create,
            json!({"name":"Bloom Agent Fixture","symbol":"BLMA","uri":"https://example.com/pumpfun-agent-fixture.json","solLamports":"1000000","tokenizedAgent":true,"buybackBps":5000}),
        );
        assert_fixture(
            "buy_bond",
            Action::Buy,
            json!({"mint":BOND_MINT,"amount":"1000000","slippagePct":2}),
        );
        assert_fixture(
            "sell_bond",
            Action::Sell,
            json!({"mint":BOND_MINT,"amount":"1","slippagePct":2}),
        );
        assert_fixture(
            "buy_amm",
            Action::Buy,
            json!({"mint":AMM_MINT,"amount":"1000000","slippagePct":2}),
        );
        assert_fixture(
            "sell_amm",
            Action::Sell,
            json!({"mint":AMM_MINT,"amount":"1","slippagePct":2}),
        );
        assert_fixture("fees", Action::Fees, json!({"mint":BOND_MINT}));
        assert_fixture_for(
            "sharing",
            Action::Sharing,
            AMM_CREATOR,
            json!({"mint":AMM_MINT,"shareholders":[{"address":AMM_CREATOR,"bps":10000}]}),
        );
    }
    fn parsed_buy_fixture() -> (Msg, Map<String, Value>, Value) {
        let response = fixture("buy_bond");
        let raw = B64
            .decode(
                response
                    .get("transaction")
                    .and_then(Value::as_str)
                    .expect("fixture transaction"),
            )
            .expect("base64 fixture");
        let env = envelope(&raw).expect("transaction envelope");
        let message = message(env.message).expect("versioned message");
        let request = normalized(
            Action::Buy,
            json!({"mint":BOND_MINT,"amount":"1000000","slippagePct":2}),
        );
        (message, request, response)
    }
    #[test]
    fn verifier_rejects_wrong_action_and_unused_requested_mint() {
        let (mut message, request, response) = parsed_buy_fixture();
        let payer = pk(USER).expect("payer");
        let mint = pk(BOND_MINT).expect("mint");
        let pump = pk(PROGRAMS[5]).expect("Pump program");
        let buy = message
            .instructions
            .iter_mut()
            .find(|ix| message.keys.get(ix.program) == Some(&pump))
            .expect("buy instruction");
        buy.data[..8].copy_from_slice(&IX_SELL);
        assert!(
            validate_message(&message, &payer, &mint, Action::Buy, &request, &response).is_err()
        );

        let (mut message, request, response) = parsed_buy_fixture();
        let buy = message
            .instructions
            .iter_mut()
            .find(|ix| message.keys.get(ix.program) == Some(&pump))
            .expect("buy instruction");
        buy.accounts[2] = 1;
        assert!(
            validate_message(&message, &payer, &mint, Action::Buy, &request, &response).is_err()
        );
    }
    #[test]
    fn verifier_rejects_direct_token_debits_and_excessive_fees() {
        let (mut message, request, response) = parsed_buy_fixture();
        let payer = pk(USER).expect("payer");
        let mint = pk(BOND_MINT).expect("mint");
        let token_2022 = pk(PROGRAMS[4]).expect("Token-2022 program");
        let token_index = message
            .keys
            .iter()
            .position(|key| key == &token_2022)
            .expect("Token-2022 key");
        message.instructions.push(Ix {
            program: token_index,
            accounts: vec![0, 1, 0],
            data: vec![3, 1, 0, 0, 0, 0, 0, 0, 0],
        });
        assert!(
            validate_message(&message, &payer, &mint, Action::Buy, &request, &response).is_err()
        );

        let (mut message, request, response) = parsed_buy_fixture();
        let price = message
            .instructions
            .iter_mut()
            .find(|ix| ix.data.first() == Some(&3))
            .expect("compute price");
        price.data[1..].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            validate_message(&message, &payer, &mint, Action::Buy, &request, &response).is_err()
        );
    }
    #[test]
    fn request_validation_is_closed_and_shareholders_are_unique() {
        let mut unknown = json!({"mint":BOND_MINT,"amount":"1","surprise":true})
            .as_object()
            .expect("request")
            .clone();
        assert!(normalize(Action::Buy, USER, &mut unknown).is_err());

        let mut duplicate = json!({
            "mint":BOND_MINT,
            "shareholders":[
                {"address":USER,"bps":5000},
                {"address":USER,"bps":5000}
            ]
        })
        .as_object()
        .expect("request")
        .clone();
        assert!(normalize(Action::Sharing, USER, &mut duplicate).is_err());
    }
    #[test]
    fn public_session_has_no_signing_reference() {
        let session = Session {
            schema: "bloom.pumpfun_session.v1".into(),
            wallet: "wallet".into(),
            id: "session".into(),
            address: USER.into(),
            duration_ms: 60_000,
            created_ms: 1,
            expires_ms: 60_001,
            stopped: false,
        };
        let encoded = serde_json::to_value(session).expect("serialize session");
        assert!(encoded.get("key_ref_jcs").is_none());
    }
}
