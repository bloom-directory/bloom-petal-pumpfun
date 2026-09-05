use base64::{Engine, engine::general_purpose::STANDARD as B64};
use petal::{
    Ctx, DispatchResponse, HostStatus, HttpRequest, PayloadSignRequest, SdkError, SignOutcome,
    SignSelector,
};
use serde::{Deserialize, Serialize};
pub use serde_json::json;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const MAX: usize = 131072;
const MAX_TX: usize = 1232;
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
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnHqucxnX1Lpw",
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
    "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
    "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ",
    "AgenTMiC2hvxGebTsgmsD4HHBa8WEcqGFf87iwRRxLo7",
];
const PUMPS: [&str; 4] = [PROGRAMS[5], PROGRAMS[6], PROGRAMS[7], PROGRAMS[8]];

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
    v.to_string().chars().take(2048).collect()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    schema: String,
    wallet: String,
    id: String,
    pub address: String,
    pub key_ref_jcs: Vec<u8>,
    created_ms: u64,
    expires_ms: u64,
    pub stopped: bool,
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
    let life = r.duration_ms.unwrap_or(3_600_000).clamp(60_000, 86_400_000);
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
        key_ref_jcs,
        created_ms: now,
        expires_ms: now + life,
        stopped: false,
    };
    let k = sk(&w, &id, "session.json");
    match get::<Session>(&k) {
        Ok(Some(x)) if x.address == v.address => DispatchResponse::Write,
        Ok(Some(_)) => bad("session id already used"),
        Ok(None) => match put_new(&k, &v, false) {
            Ok(()) => DispatchResponse::Write,
            Err(e) => e,
        },
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
    status: String,
    signature: Option<String>,
    approval: Option<String>,
}
#[derive(Serialize)]
struct Public<'a> {
    schema: &'static str,
    action: &'a str,
    status: &'a str,
    signature: &'a Option<String>,
    api: &'a Value,
    updated_ms: u64,
}
pub fn execute(c: &Ctx, a: Action, w: String, s: String, b: &[u8]) -> DispatchResponse {
    let sess = match get::<Session>(&sk(&w, &s, "session.json")) {
        Ok(Some(v)) => v,
        Ok(None) => return bad("session not found"),
        Err(e) => return e,
    };
    if sess.stopped || sess.expires_ms <= petal::sdk::now_ms() {
        return deny("session stopped or expired");
    }
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
    let canonical = serde_jcs::to_vec(&r).unwrap();
    let digest = hex::encode(Sha256::digest([a.class().as_bytes(), &canonical].concat()));
    let key = sec(&w, &s, &op);
    let mut p = match get_secret::<Pending>(&key) {
        Ok(Some(v)) => {
            if v.digest != digest {
                return bad("operationId already bound");
            };
            v
        }
        Ok(None) => {
            let v = match post(&format!("{BUILD}{}", a.path()), &Value::Object(r.clone())) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let Some(tx) = v.get("transaction").and_then(Value::as_str) else {
                return fail("builder omitted transaction");
            };
            if let Err(e) = validate_tx(tx, &sess.address, a, &r, &v) {
                return fail(format!("unsafe builder transaction: {e}"));
            }
            let mut api = v.clone();
            api.as_object_mut().unwrap().remove("transaction");
            let p = Pending {
                digest,
                tx: tx.into(),
                api,
                front: r
                    .get("frontRunningProtection")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                status: "built".into(),
                signature: None,
                approval: None,
            };
            if let Err(e) = put_new(&key, &p, true) {
                return e;
            }
            p
        }
        Err(e) => return e,
    };
    if matches!(p.status.as_str(), "submitted" | "broadcast_attempted") {
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
    let batch = petal::payload_batch_digest(&[petal::PayloadSignItem {
        preimage: env.message.to_vec(),
        claimed_hash: hash,
    }])
    .unwrap();
    let claim = json!({"package_hash":c.package_hash,"route":route,"operation_class":a.class(),"crypto_suite":"ed25519-message","payload_digest":hex::encode(batch),"ordered_hashes":[hex::encode(hash)],"declared_debits":effects(a,&r),"declared_destinations":[],"declared_fee":{"kind":"network-plus-declared-tip"},"nonce":&hex::encode(Sha256::digest([p.digest.as_bytes(),&env.blockhash].concat()))[..32],"claim_assurance":{"kind":"machine_asserted"}});
    let sig = match petal::sdk::sign_payload(&PayloadSignRequest {
        wallet: w.clone(),
        preimage: env.message.to_vec(),
        claimed_hash: hash,
        signature_algorithm: "ed25519-message".into(),
        operation_class: a.class().into(),
        petal_use_claim_jcs: serde_jcs::to_vec(&claim).unwrap(),
        claim_assurance_evidence: None,
        approval_hint: p.approval.clone(),
        action: None,
        advisory: None,
        selector: SignSelector::Reusable,
        key_ref_jcs: Some(sess.key_ref_jcs),
    }) {
        Ok(SignOutcome::Signature(v)) => v,
        Ok(SignOutcome::ApprovalPending {
            action_id,
            expires_ms,
        }) => {
            p.approval = Some(action_id.clone());
            if let Err(e) = put(&key, &p, true) {
                return e;
            }
            return deny(format!(
                "approval required: {}",
                json!({"action_id":action_id,"expires_ms":expires_ms,"operationId":op})
            ));
        }
        Err(e) => return deny(e.message()),
    };
    if sig.len() != 64 {
        return fail("non-Ed25519 signature");
    }
    let mut signed = raw.clone();
    signed[env.sig_offset..env.sig_offset + 64].copy_from_slice(&sig);
    let tx = B64.encode(signed);
    let signature = bs58::encode(sig).into_string();
    if let Err(e) = simulate(&tx) {
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
    r.insert("user".into(), json!(user));
    r.insert("encoding".into(), json!("base64"));
    if matches!(a, Action::Create | Action::Buy | Action::Sell) {
        r.insert("feePayer".into(), json!(user));
    }
    let fr = r
        .get("frontRunningProtection")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let tip = r.get("tipAmount").and_then(Value::as_f64).unwrap_or(0.0);
    if !tip.is_finite() || !(0.0..=0.01).contains(&tip) || (!fr && tip != 0.0) {
        return Err(bad("invalid tip/front-running combination"));
    }
    match a {
        Action::Create => {
            text(r, "name", 1, 64)?;
            text(r, "symbol", 1, 16)?;
            text(r, "uri", 1, 512)?;
            number(r, "solLamports", 0)?;
            r.insert("creator".into(), json!(user));
            if r.get("tokenizedAgent") == Some(&Value::Bool(true))
                && r.get("solLamports").and_then(Value::as_str) == Some("0")
            {
                return Err(bad("tokenizedAgent requires initial buy"));
            }
        }
        Action::Buy | Action::Sell => {
            let mint = text(r, "mint", 32, 64)?;
            pk(&mint).map_err(bad)?;
            let amount = number(r, "amount", 1)?;
            let slip = r.get("slippagePct").and_then(Value::as_f64).unwrap_or(2.0);
            if !slip.is_finite() || !(0.0..=50.0).contains(&slip) {
                return Err(bad("slippagePct must be 0..=50"));
            }
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
            let Some(Value::Array(v)) = r.get("shareholders") else {
                return Err(bad("shareholders required"));
            };
            if v.is_empty() || v.len() > 10 {
                return Err(bad("1..=10 shareholders required"));
            }
            let mut total = 0;
            for x in v {
                let o = x.as_object().ok_or_else(|| bad("invalid shareholder"))?;
                pk(o.get("address")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("shareholder address required"))?)
                .map_err(bad)?;
                total += o
                    .get("bps")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| bad("shareholder bps required"))?
            }
            if total != 10000 {
                return Err(bad("shareholder bps must total 10000"));
            }
        }
    }
    Ok(())
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
fn effects(a: Action, r: &Map<String, Value>) -> Vec<Value> {
    match a {
        Action::Buy => vec![json!({"asset":"SOL","amount":r.get("amount")})],
        Action::Sell => vec![json!({"asset":r.get("inputMint"),"amount":r.get("amount")})],
        Action::Create => vec![json!({"asset":"SOL","amount":r.get("solLamports")})],
        _ => vec![],
    }
}
fn publish(w: &str, s: &str, o: &str, a: Action, p: &Pending) -> Result<(), DispatchResponse> {
    put(
        &sk(w, s, &format!("operations/{o}.json")),
        &Public {
            schema: "bloom.pumpfun_operation.v1",
            action: a.class(),
            status: &p.status,
            signature: &p.signature,
            api: &p.api,
            updated_ms: petal::sdk::now_ms(),
        },
        false,
    )
}
pub fn read_operation(w: &str, s: &str, o: &str) -> DispatchResponse {
    match get::<Value>(&sk(w, s, &format!("operations/{o}.json"))) {
        Ok(Some(v)) => petal::read_json_value(&v),
        Ok(None) => bad("operation not found"),
        Err(e) => e,
    }
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
fn rpc(m: &str, p: Value) -> Value {
    json!({"jsonrpc":"2.0","id":"bloom-pumpfun","method":m,"params":p})
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
        keys.push(b.get(o..o + 32).ok_or("truncated key")?.try_into().unwrap());
        o += 32
    }
    let blockhash = b
        .get(o..o + 32)
        .ok_or("truncated blockhash")?
        .try_into()
        .unwrap();
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
fn validate_tx(
    t: &str,
    user: &str,
    a: Action,
    r: &Map<String, Value>,
    response: &Value,
) -> Result<(), String> {
    let raw = B64.decode(t).map_err(|_| "invalid base64")?;
    let e = envelope(&raw)?;
    let m = message(e.message)?;
    if m.keys.first() != Some(&pk(user)?) {
        return Err("payer is not session key".into());
    }
    if matches!(a, Action::Create) {
        let mint = pk(response
            .get("mintPublicKey")
            .and_then(Value::as_str)
            .ok_or("mint missing")?)?;
        if m.keys.get(1) != Some(&mint) {
            return Err("mint signer mismatch".into());
        }
    }
    let wanted = r
        .get("mint")
        .or_else(|| r.get("inputMint"))
        .or_else(|| r.get("outputMint"))
        .and_then(Value::as_str)
        .filter(|m| *m != SOL);
    if let Some(x) = wanted
        && !m.keys.contains(&pk(x)?)
    {
        return Err("requested mint absent".into());
    }
    let allowed: Vec<_> = PROGRAMS.iter().map(|x| pk(x).unwrap()).collect();
    let pumps: Vec<_> = PUMPS.iter().map(|x| pk(x).unwrap()).collect();
    let mut pump = false;
    for ix in &m.instructions {
        let p = m.keys.get(ix.program).ok_or("program loaded indirectly")?;
        if !allowed.contains(p) {
            return Err(format!(
                "unapproved program {}",
                bs58::encode(p).into_string()
            ));
        }
        pump |= pumps.contains(p)
    }
    validate_system_transfers(&m, &pk(user)?, r)?;
    if !pump {
        return Err("no Pump program invoked".into());
    }
    Ok(())
}
fn validate_system_transfers(
    m: &Msg,
    payer: &[u8; 32],
    r: &Map<String, Value>,
) -> Result<(), String> {
    let system = pk(PROGRAMS[1])?;
    let token = pk(PROGRAMS[3])?;
    let tips: [&str; 8] = [
        "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5",
        "HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe",
        "Cw8CFyM9FkoMi7K7Crf6HNQqf4uEMzpKw6QNghXLvLkY",
        "ADaUMid9yfUytqMBgopwjb2DTLSokTSzL1zt6iGPaS49",
        "DfXygSm4jCyNCybVYYK6DwvWqjKee8pbDmJGcLWNDXjh",
        "ADuUkR4vqLUMWXxW9gh6D6L8pMSawimctcNZ5pGwDcEt",
        "DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL",
        "3AVi9Tg9Uo68tJfuvoKvqKNWKkC5wPdSSdeBnizKZ6jT",
    ];
    let tips: Vec<_> = tips.iter().map(|x| pk(x).unwrap()).collect();
    for ix in &m.instructions {
        if m.keys.get(ix.program) != Some(&system) {
            continue;
        }
        if ix.data.len() != 12 || ix.data[..4] != 2u32.to_le_bytes() || ix.accounts.len() != 2 {
            return Err("unsupported direct System instruction".into());
        }
        let from = m
            .keys
            .get(ix.accounts[0] as usize)
            .ok_or("System source loaded indirectly")?;
        let to = m
            .keys
            .get(ix.accounts[1] as usize)
            .ok_or("System destination loaded indirectly")?;
        if from != payer {
            return Err("System debit is not from session key".into());
        }
        let amount = u64::from_le_bytes(ix.data[4..].try_into().unwrap());
        if tips.contains(to) {
            let expected =
                (r.get("tipAmount").and_then(Value::as_f64).unwrap_or(0.0) * 1e9).floor() as u64;
            if amount != expected {
                return Err("Jito tip differs from request".into());
            }
            continue;
        }
        let closes = m.instructions.iter().any(|close| {
            m.keys.get(close.program) == Some(&token)
                && close.data == [9]
                && close.accounts.len() >= 3
                && m.keys.get(close.accounts[0] as usize) == Some(to)
                && m.keys.get(close.accounts[1] as usize) == Some(payer)
                && m.keys.get(close.accounts[2] as usize) == Some(payer)
        });
        if !closes {
            return Err("SOL transfer destination is neither a Jito tip nor a session-owned wrapped-SOL account".into());
        }
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
    #[test]
    fn keys() {
        assert!(pk(SOL).is_ok());
        assert!(PROGRAMS.iter().all(|p| pk(p).is_ok()));
        assert!(pk("bad").is_err())
    }
    #[test]
    fn ids() {
        assert!(ident("op-1", "id").is_ok());
        assert!(ident("../x", "id").is_err())
    }
}
