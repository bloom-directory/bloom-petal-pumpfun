use base64::{Engine, engine::general_purpose::STANDARD as B64};
use curve25519_dalek::edwards::CompressedEdwardsY;
use petal::{
    Ctx, DispatchResponse, HostStatus, HttpRequest, PayloadSignRequest, SdkError, SignOutcome,
    SignSelector,
};
use serde::{Deserialize, Serialize};
pub use serde_json::json;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX: usize = 131072;
const MAX_TX: usize = 1232;
const MAX_SESSION_MS: u64 = 86_400_000;
const MAX_PRIORITY_FEE_LAMPORTS: u64 = 5_000_000;
const ATA_RENT_ALLOWANCE_LAMPORTS: u64 = 2_100_000;
const CREATE_RENT_ALLOWANCE_LAMPORTS: u64 = 20_000_000;
const BUILD: &str = "https://fun-block.pump.fun";
const COINS: &str = "https://frontend-api-v3.pump.fun/coins-v2";
const RPC: &str = "https://rpc.solanatracker.io/public";
const RPC_VERIFY: &str = "https://api.mainnet-beta.solana.com";
const JITO: &str = "https://mainnet.block-engine.jito.wtf/api/v1/transactions";
const SOL: &str = "So11111111111111111111111111111111111111112";
#[cfg(not(test))]
const ADDRESS_LOOKUP_TABLE_PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";
const ROUTES: [&str; 8] = [
    "ROUTE_CREATE",
    "ROUTE_BUY",
    "ROUTE_SELL",
    "ROUTE_FEES",
    "ROUTE_SHARING",
    "ROUTE_CLOSE_TOKEN_ACCOUNT",
    "ROUTE_SWEEP",
    "ROUTE_NEW",
];
const CLASSES: [&str; 7] = [
    "pumpfun.create",
    "pumpfun.buy",
    "pumpfun.sell",
    "pumpfun.collect_fees",
    "pumpfun.sharing_config",
    "pumpfun.close_token_account",
    "pumpfun.sweep",
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
fn dispatch_message(e: &DispatchResponse) -> String {
    match e {
        DispatchResponse::Error { message, .. } => message.clone(),
        _ => "unexpected non-error response".into(),
    }
}
fn sdk_message(e: &petal::SdkError) -> String {
    e.message()
}

#[cfg(test)]
mod fake_host;

/// This crate's only boundary to the Bloom host.
///
/// Every host call goes through one of these functions. A release build
/// forwards straight to the pinned SDK; a test build dispatches to the
/// recording fake host in `fake_host`, which is what lets a test drive a real
/// route flow and then assert on the requests that actually left the Petal.
mod host {
    #[cfg(not(test))]
    use petal::{
        HttpRequest, HttpResponse, PayloadSignRequest, PetalKeyOutcome, SdkError, SignOutcome,
    };

    #[cfg(not(test))]
    pub fn http(request: &HttpRequest, max_bytes: usize) -> Result<HttpResponse, SdkError> {
        petal::sdk::http_fetch(request, max_bytes)
    }
    #[cfg(not(test))]
    pub fn store_get(key: &str, max_bytes: usize) -> Result<Vec<u8>, SdkError> {
        petal::sdk::store_get(key, max_bytes)
    }
    #[cfg(not(test))]
    pub fn store_get_secret(key: &str) -> Result<Option<Vec<u8>>, String> {
        petal::bindings::bloom::store::kv::get("secrets", key)
    }
    #[cfg(not(test))]
    pub fn store_put(key: &str, value: &[u8], secret: bool) -> Result<(), SdkError> {
        petal::sdk::store_put(key, value, secret)
    }
    #[cfg(not(test))]
    pub fn store_put_new(key: &str, value: &[u8], secret: bool) -> Result<(), SdkError> {
        petal::sdk::store_put_new(key, value, secret)
    }
    #[cfg(not(test))]
    pub fn store_list(prefix: &str, max_bytes: usize) -> Result<Vec<String>, SdkError> {
        petal::sdk::store_list(prefix, max_bytes)
    }
    #[cfg(not(test))]
    pub fn derive_key(request_jcs: &[u8]) -> Result<PetalKeyOutcome, SdkError> {
        let outcome = petal::sdk::request_key(request_jcs)?;
        serde_json::from_slice(&outcome)
            .map_err(|error| SdkError::Message(format!("decode Petal key outcome: {error}")))
    }
    #[cfg(not(test))]
    pub fn sign_payload(request: &PayloadSignRequest) -> Result<SignOutcome, SdkError> {
        petal::sdk::sign_payload(request)
    }
    #[cfg(not(test))]
    pub fn now_ms() -> u64 {
        petal::sdk::now_ms()
    }

    #[cfg(test)]
    pub use crate::fake_host::{
        derive_key, http, now_ms, sign_payload, store_get, store_get_secret, store_list, store_put,
        store_put_new,
    };
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
/// Which account a session belongs to: where its records live and which key
/// slot it derives. The flat `/petals/…` mount and `wallets/<w>/0/petals/…`
/// are the same owner and share the wallet-scoped records and slots. A
/// numbered account `n > 0` keeps its own record tree and hashes `n` into its
/// slot, so one session id on two accounts is two sessions with two keys.
///
/// The scope is the account number because Bloom injects `bloom.account` on
/// every account-mounted route, whereas `bloom.owner_key_fingerprint` is
/// omitted from routes that derive no key when the account holds more than
/// one key family — every route here except `new.json`.
#[derive(Clone, Debug, PartialEq)]
pub struct SessionOwner {
    wallet: String,
    account: u32,
}

impl SessionOwner {
    pub fn scope(ctx: &Ctx, wallet: &str) -> Result<Self, DispatchResponse> {
        Self::from_params(
            wallet,
            petal::route_param(ctx, "bloom.wallet"),
            petal::route_param(ctx, "bloom.account"),
        )
        .map_err(bad)
    }

    fn from_params(
        wallet: &str,
        mounted_wallet: Option<&str>,
        account: Option<&str>,
    ) -> Result<Self, String> {
        if let Some(mounted) = mounted_wallet
            && mounted != wallet
        {
            return Err(format!(
                "session wallet {wallet:?} is not the mounted wallet {mounted:?}"
            ));
        }
        let account = match account {
            None => 0,
            Some(raw) => raw
                .parse::<u32>()
                .map_err(|error| format!("bloom.account must be a u32: {error}"))?,
        };
        Ok(Self {
            wallet: wallet.to_owned(),
            account,
        })
    }
}

/// The per-account root under both the public and secret namespaces; its
/// children are wallets.
fn sessions_root(account: u32) -> String {
    if account == 0 {
        "sessions/".into()
    } else {
        format!("account-sessions/{account}/")
    }
}
fn sessions_prefix(owner: &SessionOwner) -> String {
    format!("{}{}/", sessions_root(owner.account), owner.wallet)
}
fn account_number(c: &Ctx) -> Result<u32, DispatchResponse> {
    petal::route_param(c, "bloom.account")
        .map_or(Ok(0), |raw| raw.parse::<u32>())
        .map_err(|error| bad(format!("bloom.account must be a u32: {error}")))
}
fn session_key_slot(owner: &SessionOwner, id: &str) -> String {
    let mut input = id.as_bytes().to_vec();
    input.push(0);
    if owner.account != 0 {
        input.extend_from_slice(owner.account.to_string().as_bytes());
        input.push(0);
    }
    format!("pumpfun-{}", &hex::encode(Sha256::digest(&input))[..40])
}
fn sk(owner: &SessionOwner, s: &str, x: &str) -> String {
    format!("state/{}{s}/{x}", sessions_prefix(owner))
}
fn sec(owner: &SessionOwner, s: &str, o: &str) -> String {
    format!("{}{s}/operations/{o}.json", sessions_prefix(owner))
}
fn session_sec(owner: &SessionOwner, s: &str) -> String {
    format!("{}{s}/session.json", sessions_prefix(owner))
}
fn put<T: Serialize + ?Sized>(k: &str, v: &T, secret: bool) -> Result<(), DispatchResponse> {
    host::store_put(
        k,
        &serde_json::to_vec(v).map_err(|e| fail(e.to_string()))?,
        secret,
    )
    .map_err(|e| fail(sdk_message(&e)))
}
fn put_new<T: Serialize + ?Sized>(k: &str, v: &T, secret: bool) -> Result<(), DispatchResponse> {
    host::store_put_new(
        k,
        &serde_json::to_vec(v).map_err(|e| fail(e.to_string()))?,
        secret,
    )
    .map_err(|e| fail(sdk_message(&e)))
}
fn get<T: for<'a> Deserialize<'a>>(k: &str) -> Result<Option<T>, DispatchResponse> {
    match host::store_get(k, MAX) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| fail(e.to_string())),
        Err(SdkError::Host(HostStatus::NotFound)) => Ok(None),
        Err(e) => Err(fail(sdk_message(&e))),
    }
}
fn get_secret<T: for<'a> Deserialize<'a>>(k: &str) -> Result<Option<T>, DispatchResponse> {
    match host::store_get_secret(k) {
        Ok(Some(b)) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| fail(e.to_string())),
        Ok(None) => Ok(None),
        Err(e) => Err(fail(e)),
    }
}
fn fetch(method: &str, url: String, body: Vec<u8>) -> Result<Value, DispatchResponse> {
    let r = host::http(
        &HttpRequest {
            method: method.into(),
            url,
            headers: vec![("content-type".into(), "application/json".into())],
            body,
        },
        MAX,
    )
    .map_err(|e| fail(sdk_message(&e)))?;
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
    if let Some(error) = v.get("error").filter(|error| error.is_object()) {
        for field in ["code", "message"] {
            if let Some(value) = error.get(field)
                && (value.is_string() || value.is_number() || value.is_boolean())
            {
                safe.insert(field.into(), value.clone());
            }
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
    #[serde(default)]
    approval_value_limits: Vec<Value>,
    created_ms: u64,
    expires_ms: u64,
    pub stopped: bool,
}
#[derive(Serialize, Deserialize)]
struct SessionSecret {
    key_ref_jcs: Vec<u8>,
}
/// When this session's key was first requested. The host's key scope starts
/// no earlier, so `requested_ms + duration` never overstates its authority.
#[derive(Serialize, Deserialize)]
struct SessionRequest {
    requested_ms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct New {
    id: String,
    #[serde(default)]
    duration_ms: Option<u64>,
    max_lamports: String,
    #[serde(default)]
    token_limits: BTreeMap<String, String>,
}
pub fn new_session(owner: SessionOwner, b: &[u8]) -> DispatchResponse {
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
    let mut value_limits = Vec::new();
    for (asset, amount) in
        std::iter::once(("native".to_owned(), r.max_lamports)).chain(r.token_limits)
    {
        if asset != "native" && pk(&asset).is_err() {
            return bad("token_limits keys must be Solana mint addresses");
        }
        let amount = match amount.parse::<u64>() {
            Ok(amount) if amount > 0 => amount,
            _ => return bad("session budgets must be positive decimal strings fitting u64"),
        };
        if value_limits
            .iter()
            .any(|value: &Value| value["asset"]["asset"] == asset)
        {
            return bad("duplicate session budget asset");
        }
        value_limits.push(json!({"asset":{"chain":"solana","asset":asset},
            "lifetime":amount.to_string(),"rolling_windows":[]}));
    }
    let public_key = sk(&owner, &id, "session.json");
    let existing = match get::<Session>(&public_key) {
        Ok(Some(existing))
            if existing.duration_ms != life || existing.approval_value_limits != value_limits =>
        {
            return bad("session id already used with different duration or budgets");
        }
        Ok(existing) => existing,
        Err(e) => return e,
    };
    if existing.as_ref().is_some_and(|session| session.stopped) {
        return DispatchResponse::Write;
    }
    // An existing session repeats the identical key request too. The host
    // binds the session's approval to the wallet policy in force, and this is
    // how a live session picks up a policy change: the same key and lifetime,
    // Pending while the owner approves again.
    let request_key = format!("{}{id}/session-request.json", sessions_prefix(&owner));
    let requested_ms = match get_secret::<SessionRequest>(&request_key) {
        Ok(Some(request)) => request.requested_ms,
        Ok(None) => {
            let request = SessionRequest {
                requested_ms: host::now_ms(),
            };
            if existing.is_none()
                && let Err(e) = put(&request_key, &request, true)
            {
                return e;
            }
            request.requested_ms
        }
        Err(e) => return e,
    };
    let request = match session_key_request(&owner, &id, life, &value_limits) {
        Ok(request) => request,
        Err(error) => return error,
    };
    let out = match host::derive_key(&request) {
        Ok(v) => v,
        Err(e) => return fail(sdk_message(&e)),
    };
    let slot = session_key_slot(&owner, &id);
    let (key_ref_jcs, address) = match out {
        petal::PetalKeyOutcome::Pending {
            operation_id,
            scope_digest,
        } => {
            return deny(format!(
                "session authority pending: the owner must finish this session's steps in Bloom, then retry the same request. The session key's address and any open ceremony are in /wallets/{}/{}/sessions/<pumpfun mount>/{slot}/session.json; if the session will be funded, allow that address as a destination before approving the session. {}",
                owner.wallet,
                owner.account,
                json!({"operation_id":operation_id,"scope_digest":scope_digest,"key_slot":slot})
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
    let secret_key = session_sec(&owner, &id);
    if let Some(existing) = existing {
        return match get_secret::<SessionSecret>(&secret_key) {
            Ok(Some(secret))
                if secret.key_ref_jcs == key_ref_jcs && existing.address == address =>
            {
                DispatchResponse::Write
            }
            Ok(_) => fail("the host returned a different key for this existing session"),
            Err(e) => e,
        };
    }
    let v = Session {
        schema: "bloom.pumpfun_session.v1".into(),
        wallet: owner.wallet.clone(),
        id: id.clone(),
        address,
        duration_ms: life,
        approval_value_limits: value_limits,
        created_ms: host::now_ms(),
        expires_ms: requested_ms + life,
        stopped: false,
    };
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
/// The session's canonical key request. Repeating it is how a session asks
/// Bloom for the current state of its authority.
fn session_key_request(
    owner: &SessionOwner,
    id: &str,
    life: u64,
    value_limits: &[Value],
) -> Result<Vec<u8>, DispatchResponse> {
    let request = petal::PetalKeyRequest {
        wallet_id: owner.wallet.clone(),
        key_slot: session_key_slot(owner, id),
        allowed_routes: ROUTES.iter().map(|x| x.to_string()).collect(),
        allowed_operation_classes: CLASSES.iter().map(|x| x.to_string()).collect(),
        allowed_crypto_suites: vec!["ed25519-message".into()],
        maximum_lifetime_ms: life,
    };
    let budgets: Vec<petal::ApprovalValueLimit> = serde_json::from_value(json!(value_limits))
        .map_err(|error| fail(format!("session budgets: {error}")))?;
    petal::key_request_jcs(&request, &budgets).map_err(fail)
}

/// Before a trade calls the builder, ask Bloom whether it still authorizes
/// the session. Stopping a session in Bloom does not reach this Petal's own
/// record, and the Broker refuses the signature anyway; this only saves the
/// builder call and fails with a clear reason.
fn session_authority(
    owner: &SessionOwner,
    s: &str,
    session: &Session,
) -> Result<(), DispatchResponse> {
    let request = session_key_request(
        owner,
        s,
        session.duration_ms,
        &session.approval_value_limits,
    )?;
    match host::derive_key(&request) {
        Ok(petal::PetalKeyOutcome::Ready { .. }) => Ok(()),
        Ok(petal::PetalKeyOutcome::Pending { .. }) => Err(deny(
            "session authority pending: finish this session's steps in Bloom, then retry",
        )),
        Err(SdkError::Host(HostStatus::Denied)) => Err(deny(
            "Bloom no longer authorizes this session: it was stopped, expired, or used its budget",
        )),
        Err(error) => Err(fail(sdk_message(&error))),
    }
}

pub fn read_session(owner: &SessionOwner, s: &str) -> DispatchResponse {
    match get::<Session>(&sk(owner, s, "session.json")) {
        Ok(Some(v)) => petal::read_json_value(&v),
        Ok(None) => bad("session not found"),
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
    CloseTokenAccount,
    Sweep,
}
impl Action {
    fn class(self) -> &'static str {
        match self {
            Self::Create => CLASSES[0],
            Self::Buy => CLASSES[1],
            Self::Sell => CLASSES[2],
            Self::Fees => CLASSES[3],
            Self::Sharing => CLASSES[4],
            Self::CloseTokenAccount => CLASSES[5],
            Self::Sweep => CLASSES[6],
        }
    }
    fn path(self) -> &'static str {
        match self {
            Self::Create => "/agents/create-coin",
            Self::Buy | Self::Sell => "/agents/swap",
            Self::Fees => "/agents/collect-fees",
            Self::Sharing => "/agents/sharing-config",
            Self::CloseTokenAccount | Self::Sweep => "",
        }
    }
    /// Recovery actions sign with a fresh payload-specific Exact approval,
    /// which survives the session's stop or expiry; trading actions reuse
    /// the session key's approval.
    fn selector(self) -> SignSelector {
        match self {
            Self::CloseTokenAccount | Self::Sweep => SignSelector::Exact,
            Self::Create | Self::Buy | Self::Sell | Self::Fees | Self::Sharing => {
                SignSelector::Reusable
            }
        }
    }
}
#[derive(Serialize, Deserialize)]
struct Pending {
    digest: String,
    tx: String,
    message_sha256: String,
    api: Value,
    front: bool,
    network_fee_lamports: u64,
    status: String,
    signature: Option<String>,
    approval: Option<String>,
    /// Set once any signing call for this message may have produced a
    /// signature, and never cleared: a later refusal or failed simulation
    /// says nothing about an earlier call. While set, the operation keeps
    /// its message and can only sign that message again.
    #[serde(default)]
    may_be_signed: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct Public {
    schema: String,
    action: String,
    status: String,
    signature: Option<String>,
    api: Value,
    message_sha256: String,
    updated_ms: u64,
}

fn active_session(owner: &SessionOwner, s: &str, a: Action) -> Result<Session, DispatchResponse> {
    let session =
        get::<Session>(&sk(owner, s, "session.json"))?.ok_or_else(|| bad("session not found"))?;
    if (session.stopped || session.expires_ms <= host::now_ms())
        && !matches!(a, Action::CloseTokenAccount | Action::Sweep)
    {
        return Err(deny("session stopped or expired"));
    }
    Ok(session)
}
fn build_pending(
    a: Action,
    user: &str,
    request: &Map<String, Value>,
    digest: String,
) -> Result<Pending, DispatchResponse> {
    match a {
        Action::CloseTokenAccount => {
            return build_close_token_account_pending(user, request, digest);
        }
        Action::Sweep => return build_sweep_pending(user, request, digest),
        _ => {}
    }
    let mut builder_request = request.clone();
    builder_request.remove("minOutputAmount");
    builder_request.remove("feeKind");
    let response = post(
        &format!("{BUILD}{}", a.path()),
        &Value::Object(builder_request),
    )?;
    let tx = response
        .get("transaction")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("builder omitted transaction"))?
        .to_owned();
    validate_tx(&tx, user, a, request, &response)?;
    let raw = B64
        .decode(&tx)
        .map_err(|_| fail("builder transaction is not base64"))?;
    let message_sha256 = hex::encode(Sha256::digest(
        envelope(&raw)
            .map_err(|error| fail(format!("unsafe builder transaction: {error}")))?
            .message,
    ));
    let network_fee_lamports = transaction_fee(&tx, request)?;
    let mut api = response;
    api.as_object_mut()
        .ok_or_else(|| fail("builder response must be an object"))?
        .remove("transaction");
    Ok(Pending {
        digest,
        tx,
        message_sha256,
        api,
        front: request
            .get("frontRunningProtection")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        network_fee_lamports,
        status: "built".into(),
        signature: None,
        approval: None,
        may_be_signed: false,
    })
}

fn sweep_message(
    user: &str,
    destination: &str,
    blockhash: &str,
    lamports: u64,
) -> Result<Vec<u8>, DispatchResponse> {
    let payer = pk(user).map_err(bad)?;
    let destination = pk(destination).map_err(bad)?;
    let system = pk(PROGRAMS[1]).map_err(fail)?;
    let blockhash = pk(blockhash).map_err(|_| fail("Solana RPC returned an invalid blockhash"))?;
    let mut message = vec![0x80, 1, 0, 1, 3];
    message.extend_from_slice(&payer);
    message.extend_from_slice(&destination);
    message.extend_from_slice(&system);
    message.extend_from_slice(&blockhash);
    message.extend_from_slice(&[1, 2, 2, 0, 1, 12]);
    message.extend_from_slice(&2u32.to_le_bytes());
    message.extend_from_slice(&lamports.to_le_bytes());
    message.push(0);
    Ok(message)
}

#[derive(Debug, PartialEq)]
struct TokenAccountFact {
    token_program: String,
    mint: String,
    owner: String,
    amount: String,
    lamports: u64,
    close_authority: Option<String>,
}

fn token_account_fact(
    rpc_url: &str,
    token_account: &str,
) -> Result<TokenAccountFact, DispatchResponse> {
    let value = post(
        rpc_url,
        &rpc(
            "getAccountInfo",
            json!([token_account, {"encoding":"jsonParsed","commitment":"finalized"}]),
        ),
    )?;
    let account = value
        .pointer("/result/value")
        .filter(|value| !value.is_null())
        .ok_or_else(|| deny("token account does not exist at finalized commitment"))?;
    let field = |pointer: &str, label: &str| {
        account
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| fail(format!("Solana RPC omitted token account {label}")))
    };
    let token_program = field("/owner", "program owner")?;
    let parsed_program = field("/data/program", "parsed program")?;
    let expected_parsed_program = if token_program == PROGRAMS[3] {
        "spl-token"
    } else if token_program == PROGRAMS[4] {
        "spl-token-2022"
    } else {
        return Err(deny("account is not owned by an allowed SPL Token program"));
    };
    if parsed_program != expected_parsed_program
        || account.pointer("/data/parsed/type").and_then(Value::as_str) != Some("account")
    {
        return Err(fail(
            "Solana RPC returned invalid parsed token account data",
        ));
    }
    Ok(TokenAccountFact {
        token_program,
        mint: field("/data/parsed/info/mint", "mint")?,
        owner: field("/data/parsed/info/owner", "authority")?,
        amount: field("/data/parsed/info/tokenAmount/amount", "balance")?,
        lamports: account
            .get("lamports")
            .and_then(Value::as_u64)
            .ok_or_else(|| fail("Solana RPC omitted token account lamports"))?,
        close_authority: account
            .pointer("/data/parsed/info/closeAuthority")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn close_token_account_message(
    user: &str,
    token_account: &str,
    destination: &str,
    token_program: &str,
    blockhash: &str,
) -> Result<Vec<u8>, DispatchResponse> {
    let keys = [user, token_account, destination, token_program]
        .map(pk)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    let blockhash = pk(blockhash).map_err(|_| fail("Solana RPC returned an invalid blockhash"))?;
    let mut message = vec![0x80, 1, 0, 1, 4];
    for key in keys {
        message.extend_from_slice(&key);
    }
    message.extend_from_slice(&blockhash);
    message.extend_from_slice(&[1, 3, 3, 1, 2, 0, 1, 9, 0]);
    Ok(message)
}

/// Commitment for blockhash, fee, balance and simulation reads and for send
/// preflight. They must agree: a lagging preflight rejects a blockhash the
/// simulation accepted, and `processed` blocks can still be dropped.
const COMMITMENT: &str = "confirmed";

fn quote_message_fee(message: &[u8]) -> Result<u64, DispatchResponse> {
    let response = post(
        RPC,
        &rpc(
            "getFeeForMessage",
            json!([B64.encode(message), {"commitment":COMMITMENT}]),
        ),
    )?;
    response
        .pointer("/result/value")
        .and_then(Value::as_u64)
        .map(|quoted| quoted.max(5_000))
        .ok_or_else(|| fail("Solana RPC did not quote the transaction fee"))
}

fn build_sweep_pending(
    user: &str,
    request: &Map<String, Value>,
    digest: String,
) -> Result<Pending, DispatchResponse> {
    let destination = request
        .get("destination")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("destination required"))?;
    let balance = post(
        RPC,
        &rpc("getBalance", json!([user, {"commitment":COMMITMENT}])),
    )?
    .pointer("/result/value")
    .and_then(Value::as_u64)
    .ok_or_else(|| fail("Solana RPC omitted the session balance"))?;
    let latest = post(
        RPC,
        &rpc("getLatestBlockhash", json!([{"commitment":COMMITMENT}])),
    )?;
    let blockhash = latest
        .pointer("/result/value/blockhash")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("Solana RPC omitted the latest blockhash"))?;
    let last_valid_block_height = latest
        .pointer("/result/value/lastValidBlockHeight")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("Solana RPC omitted lastValidBlockHeight"))?;
    let network_fee_lamports = quote_message_fee(&sweep_message(user, destination, blockhash, 1)?)?;
    let lamports = balance
        .checked_sub(network_fee_lamports)
        .filter(|amount| *amount > 0)
        .ok_or_else(|| deny("session balance does not cover the sweep fee"))?;
    let message = sweep_message(user, destination, blockhash, lamports)?;
    let mut transaction = vec![1];
    transaction.extend_from_slice(&[0; 64]);
    transaction.extend_from_slice(&message);
    let tx = B64.encode(transaction);
    validate_sweep_tx(&tx, user, destination, lamports)?;
    Ok(Pending {
        digest,
        tx,
        message_sha256: hex::encode(Sha256::digest(&message)),
        api: json!({
            "destination": destination,
            "balanceLamports": balance.to_string(),
            "sweepLamports": lamports.to_string(),
            "lastValidBlockHeight": last_valid_block_height,
        }),
        front: false,
        network_fee_lamports,
        status: "built".into(),
        signature: None,
        approval: None,
        may_be_signed: false,
    })
}

fn build_close_token_account_pending(
    user: &str,
    request: &Map<String, Value>,
    digest: String,
) -> Result<Pending, DispatchResponse> {
    let token_account = request
        .get("tokenAccount")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("tokenAccount required"))?;
    let destination = request
        .get("destination")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("destination required"))?;
    let mint = request
        .get("mint")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("mint required"))?;
    let maximum_lamports = request
        .get("maxLamports")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| bad("maxLamports required"))?;
    let fact = token_account_fact(RPC, token_account)?;
    if fact != token_account_fact(RPC_VERIFY, token_account)? {
        return Err(fail("independent RPCs disagree on the token account"));
    }
    if fact.owner != user
        || fact
            .close_authority
            .as_deref()
            .is_some_and(|authority| authority != user)
        || fact.mint != mint
        || fact.amount != "0"
        || fact.lamports > maximum_lamports
    {
        return Err(deny(
            "token account must be session-closeable, match the requested mint, be empty, and stay within maxLamports",
        ));
    }
    let latest = post(
        RPC,
        &rpc("getLatestBlockhash", json!([{"commitment":COMMITMENT}])),
    )?;
    let blockhash = latest
        .pointer("/result/value/blockhash")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("Solana RPC omitted the latest blockhash"))?;
    let last_valid_block_height = latest
        .pointer("/result/value/lastValidBlockHeight")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("Solana RPC omitted lastValidBlockHeight"))?;
    let message = close_token_account_message(
        user,
        token_account,
        destination,
        &fact.token_program,
        blockhash,
    )?;
    let network_fee_lamports = quote_message_fee(&message)?;
    let mut transaction = vec![1];
    transaction.extend_from_slice(&[0; 64]);
    transaction.extend_from_slice(&message);
    let tx = B64.encode(transaction);
    validate_close_token_account_tx(&tx, user, token_account, destination, &fact.token_program)?;
    Ok(Pending {
        digest,
        tx,
        message_sha256: hex::encode(Sha256::digest(&message)),
        api: json!({
            "mint": mint,
            "tokenAccount": token_account,
            "destination": destination,
            "tokenProgram": fact.token_program,
            "accountLamports": fact.lamports.to_string(),
            "lastValidBlockHeight": last_valid_block_height,
        }),
        front: false,
        network_fee_lamports,
        status: "built".into(),
        signature: None,
        approval: None,
        may_be_signed: false,
    })
}
pub fn execute(c: &Ctx, a: Action, owner: SessionOwner, s: String, b: &[u8]) -> DispatchResponse {
    let sess = match active_session(&owner, &s, a) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let session_secret = match get_secret::<SessionSecret>(&session_sec(&owner, &s)) {
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
    let key = sec(&owner, &s, &op);
    let mut p = match get_secret::<Pending>(&key) {
        Ok(Some(mut v)) => {
            if v.digest != digest {
                return bad("operationId already bound");
            };
            // `signing` means a signing call was interrupted before its outcome
            // was stored. `simulation_failed` is written only by earlier
            // versions, which sent the signed transaction to an RPC to simulate
            // it. Either may have left a signature behind.
            if matches!(v.status.as_str(), "signing" | "simulation_failed") {
                v.may_be_signed = true;
            }
            // Only an operation that was never possibly signed is rebuilt after
            // a refusal or a failed unsigned simulation. Once it may have been
            // signed, every retry signs the stored message again, which can
            // only reproduce the same transaction.
            if !v.may_be_signed
                && v.approval.is_none()
                && matches!(v.status.as_str(), "preflight_failed" | "approval_failed")
            {
                if a.selector() == SignSelector::Reusable
                    && let Err(e) = session_authority(&owner, &s, &sess)
                {
                    return e;
                }
                v = match build_pending(a, &sess.address, &r, digest.clone()) {
                    Ok(value) => value,
                    Err(e) => return e,
                };
                if let Err(e) = put(&key, &v, true) {
                    return e;
                }
                if let Err(e) = publish(&owner, &s, &op, a, &v) {
                    return e;
                }
            }
            v
        }
        Ok(None) => {
            if a.selector() == SignSelector::Reusable
                && let Err(e) = session_authority(&owner, &s, &sess)
            {
                return e;
            }
            let p = match build_pending(a, &sess.address, &r, digest) {
                Ok(value) => value,
                Err(e) => return e,
            };
            if let Err(e) = put_new(&key, &p, true) {
                return e;
            }
            if let Err(e) = publish(&owner, &s, &op, a, &p) {
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
    // A reusable approval does not bind the message, so waiting for it may
    // refresh the transaction. An Exact approval binds these exact bytes:
    // they are kept until it signs or simulation shows they can no longer
    // land, which drops the approval and rebuilds under a new one.
    if p.status == "approval_pending"
        && p.approval.is_some()
        && !p.may_be_signed
        && a.selector() == SignSelector::Reusable
    {
        if let Err(e) = session_authority(&owner, &s, &sess) {
            return e;
        }
        let approval = p.approval.clone();
        p = match build_pending(a, &sess.address, &r, p.digest.clone()) {
            Ok(value) => value,
            Err(error) => return error,
        };
        p.status = "approval_pending".into();
        p.approval = approval;
        if let Err(error) = put(&key, &p, true) {
            return error;
        }
        if let Err(error) = publish(&owner, &s, &op, a, &p) {
            return error;
        }
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
        Err(e) => return fail(sdk_message(&e)),
    };
    let parsed_message = match message(env.message) {
        Ok(value) => value,
        Err(e) => return fail(e),
    };
    let debits = match effects(a, &r, &parsed_message) {
        Ok(value) => value,
        Err(e) => return fail(e),
    };
    let claim = json!({"package_hash":c.package_hash,"route":route,"operation_class":a.class(),"crypto_suite":"ed25519-message","payload_digest":hex::encode(batch),"ordered_hashes":[hex::encode(hash)],"declared_debits":debits,"declared_destinations":destinations(a,&parsed_message),"declared_fee":{"kind":"fee","chain":"solana","asset":"native","amount":p.network_fee_lamports.to_string()},"nonce":hex::encode(&Sha256::digest([p.digest.as_bytes(),&env.blockhash].concat())[..16]),"claim_assurance":{"kind":"machine_asserted"}});
    let claim_jcs = match serde_jcs::to_vec(&claim) {
        Ok(value) => value,
        Err(e) => return fail(format!("signing claim cannot be canonicalized: {e}")),
    };
    if let Err(e) = active_session(&owner, &s, a) {
        return e;
    }
    // Simulate before signing: an RPC that receives a signed transaction can
    // broadcast it, so a signature must never leave until this operation will
    // not build another transaction.
    if let Err(e) = simulate(&p.tx) {
        p.status = "preflight_failed".into();
        // A failed simulation says nothing permanent: a state-dependent
        // failure can clear. An Exact approval binds these bytes, so it is
        // given up only once their blockhash has provably expired.
        let keep_exact_approval = p.approval.is_some()
            && a.selector() == SignSelector::Exact
            && !match blockhash_expired(&p) {
                Ok(expired) => expired,
                Err(error) => return error,
            };
        if !p.may_be_signed && !keep_exact_approval {
            p.approval = None;
        }
        if let Err(store_error) = put(&key, &p, true) {
            return store_error;
        }
        if let Err(store_error) = publish(&owner, &s, &op, a, &p) {
            return store_error;
        }
        if p.may_be_signed {
            return fail(format!(
                "{}; this operation may already be signed, so it is never rebuilt: retry to sign the same transaction, or confirm it cannot land before using a new operationId",
                dispatch_message(&e)
            ));
        }
        if keep_exact_approval {
            return fail(format!(
                "{}; the transaction awaiting approval is kept until its blockhash expires, so retry",
                dispatch_message(&e)
            ));
        }
        return e;
    }
    // Recorded before the host call, so an interruption leaves `signing`
    // behind and the next retry treats the message as possibly signed.
    p.status = "signing".into();
    if let Err(e) = put(&key, &p, true) {
        return e;
    }
    let sig = match host::sign_payload(&PayloadSignRequest {
        wallet: owner.wallet.clone(),
        preimage: env.message.to_vec(),
        claimed_hash: hash,
        signature_algorithm: "ed25519-message".into(),
        operation_class: a.class().into(),
        petal_use_claim_jcs: claim_jcs,
        claim_assurance_evidence: None,
        approval_hint: p.approval.clone(),
        action: None,
        advisory: None,
        selector: a.selector(),
        key_ref_jcs: Some(session_secret.key_ref_jcs),
    }) {
        Ok(SignOutcome::Signature(v)) => {
            p.may_be_signed = true;
            v
        }
        Ok(SignOutcome::ApprovalPending {
            action_id,
            expires_ms,
        }) => {
            p.status = "approval_pending".into();
            p.approval = Some(action_id.clone());
            if let Err(e) = put(&key, &p, true) {
                return e;
            }
            if let Err(e) = publish(&owner, &s, &op, a, &p) {
                return e;
            }
            return deny(format!(
                "approval required: {}",
                json!({"action_id":action_id,"expires_ms":expires_ms,"operationId":op})
            ));
        }
        Err(e) => {
            // Only two host classes mean the message was decided against and
            // no signature exists: `denied`, which the host reserves for a
            // Broker failure whose own error contract says it can never be
            // retried and left no durable effect, and `invalid`, which the
            // host raises before the request reaches the Broker at all.
            //
            // Everything else — a backend fault, a dropped response, an
            // unreadable reply — leaves it unknown whether the Signer produced
            // a signature, so it must not be rebuilt. This is a contract with
            // the host, not a guess about it: a host that collapsed an
            // ambiguous Broker outcome into `denied` would license a second
            // signature for one payment here. `route_to_host_contract` below
            // pins which classes mean which, and the Machine's own
            // `petal_signing_host_error` is the other half.
            let refused = matches!(
                e,
                SdkError::Host(HostStatus::Denied) | SdkError::Host(HostStatus::Invalid)
            );
            if refused {
                p.status = "approval_failed".into();
                p.approval = None;
            } else {
                p.status = "signing_uncertain".into();
                p.may_be_signed = true;
            }
            if let Err(store_error) = put(&key, &p, true) {
                return store_error;
            }
            if let Err(store_error) = publish(&owner, &s, &op, a, &p) {
                return store_error;
            }
            if refused {
                return deny(sdk_message(&e));
            }
            return fail(format!(
                "signing did not return an outcome and may already have produced a signature; retry the same operationId with the same request to reconcile it: {}",
                sdk_message(&e)
            ));
        }
    };
    if sig.len() != 64 {
        return fail("non-Ed25519 signature");
    }
    let mut signed = raw.clone();
    signed[env.sig_offset..env.sig_offset + 64].copy_from_slice(&sig);
    let tx = B64.encode(signed);
    let signature = bs58::encode(sig).into_string();
    if let Err(e) = active_session(&owner, &s, a) {
        return e;
    }
    p.status = "broadcast_attempted".into();
    p.signature = Some(signature.clone());
    p.approval = None;
    if let Err(e) = put(&key, &p, true) {
        return e;
    }
    if let Err(e) = publish(&owner, &s, &op, a, &p) {
        return e;
    }
    let result = if p.front {
        post(
            JITO,
            &rpc("sendTransaction", json!([tx, {"encoding":"base64"}])),
        )
    } else {
        // Preflight at the commitment the blockhash was read and simulated at.
        // The finalized default lags and reports young blockhashes as
        // BlockhashNotFound after the transaction is already signed.
        let request = rpc(
            "sendTransaction",
            json!([tx,{"encoding":"base64","skipPreflight":false,"maxRetries":0,"preflightCommitment":COMMITMENT}]),
        );
        match post(RPC, &request) {
            Err(_) => post(RPC_VERIFY, &request),
            result => result,
        }
    };
    match result {
        Ok(v) if v.get("result").and_then(Value::as_str) == Some(&signature) => {
            p.status = "submitted".into();
            if let Err(e) = put(&key, &p, true) {
                return e;
            }
            if let Err(e) = publish(&owner, &s, &op, a, &p) {
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
            "minOutputAmount",
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
            "minOutputAmount",
            "slippagePct",
            "frontRunningProtection",
            "tipAmount",
        ][..],
        Action::Fees => &["mint", "feeKind", "frontRunningProtection", "tipAmount"][..],
        Action::Sharing => &[
            "mint",
            "shareholders",
            "mode",
            "frontRunningProtection",
            "tipAmount",
        ][..],
        Action::CloseTokenAccount => &["mint", "tokenAccount", "destination", "maxLamports"][..],
        Action::Sweep => &["destination"][..],
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
            number(r, "minOutputAmount", 1)?;
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
            number(r, "minOutputAmount", 1)?;
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
            if !matches!(
                r.get("feeKind").and_then(Value::as_str),
                Some("cashback" | "creator" | "sharing_distribution")
            ) {
                return Err(bad(
                    "feeKind must be cashback, creator, or sharing_distribution",
                ));
            }
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
        Action::CloseTokenAccount => {
            let mint = text(r, "mint", 32, 64)?;
            let token_account = text(r, "tokenAccount", 32, 64)?;
            let destination = text(r, "destination", 32, 64)?;
            number(r, "maxLamports", 1)?;
            pk(&mint).map_err(bad)?;
            pk(&token_account).map_err(bad)?;
            pk(&destination).map_err(bad)?;
            if destination == user {
                return Err(bad(
                    "close destination must differ from the session address",
                ));
            }
            if token_account == user || token_account == destination {
                return Err(bad(
                    "tokenAccount must differ from the signer and destination",
                ));
            }
        }
        Action::Sweep => {
            let destination = text(r, "destination", 32, 64)?;
            pk(&destination).map_err(bad)?;
            if destination == user {
                return Err(bad(
                    "sweep destination must differ from the session address",
                ));
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
    let associated = pk(PROGRAMS[2])?;
    let ata_count = message
        .instructions
        .iter()
        .filter(|ix| message.keys.get(ix.program) == Some(&associated))
        .count() as u64;
    let account_rent = ata_count
        .checked_mul(ATA_RENT_ALLOWANCE_LAMPORTS)
        .and_then(|rent| {
            rent.checked_add(if matches!(a, Action::Create) {
                CREATE_RENT_ALLOWANCE_LAMPORTS
            } else {
                0
            })
        })
        .ok_or("account rent allowance exceeds u64")?;
    let mut effects = match a {
        Action::Create | Action::Buy => {
            let trade = message
                .instructions
                .iter()
                .find(|ix| has_discriminator(ix, IX_BUY))
                .ok_or_else(|| "approved buy instruction missing".to_owned())
                .and_then(|ix| instruction_u64(ix, 16))?;
            let total = trade
                .checked_add(tip)
                .and_then(|value| value.checked_add(account_rent))
                .ok_or("native debit exceeds u64")?;
            vec![json!({"asset":{"chain":"solana","asset":"native"},"amount":total.to_string()})]
        }
        Action::Sell => vec![json!({
            "asset":{"chain":"solana","asset":r.get("inputMint").and_then(Value::as_str).ok_or("sell mint missing")?},
            "amount":r.get("amount").and_then(Value::as_str).ok_or("sell amount missing")?
        })],
        Action::Fees | Action::Sharing => vec![],
        Action::CloseTokenAccount => vec![json!({
            "asset":{"chain":"solana","asset":"native"},
            "amount":r.get("maxLamports").and_then(Value::as_str).ok_or("close maxLamports missing")?
        })],
        Action::Sweep => {
            let transfer = message
                .instructions
                .first()
                .ok_or_else(|| "sweep transfer missing".to_owned())
                .and_then(|ix| instruction_u64(ix, 4))?;
            vec![json!({
                "asset":{"chain":"solana","asset":"native"},
                "amount":transfer.to_string()
            })]
        }
    };
    let auxiliary_native = tip
        .checked_add(account_rent)
        .ok_or("native debit exceeds u64")?;
    if auxiliary_native > 0 && !matches!(a, Action::Create | Action::Buy) {
        effects.push(json!({
            "asset":{"chain":"solana","asset":"native"},
            "amount":auxiliary_native.to_string()
        }));
    }
    Ok(effects)
}
fn destinations(action: Action, message: &Msg) -> Vec<Value> {
    let system = pk(PROGRAMS[1]).ok();
    let token_programs = PROGRAMS[3..=4]
        .iter()
        .filter_map(|program| pk(program).ok())
        .collect::<Vec<_>>();
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
            && (tips.contains(destination) || matches!(action, Action::Sweep))
        {
            values.insert(bs58::encode(destination).into_string());
        }
        if matches!(action, Action::CloseTokenAccount)
            && token_programs.contains(program)
            && let Ok(destination) = account(message, ix, 1)
        {
            values.insert(bs58::encode(destination).into_string());
        }
    }
    values
        .into_iter()
        .map(|destination| json!({"chain":"solana","destination":destination}))
        .collect()
}
fn publish(
    owner: &SessionOwner,
    s: &str,
    o: &str,
    a: Action,
    p: &Pending,
) -> Result<(), DispatchResponse> {
    put(
        &sk(owner, s, &format!("operations/{o}.json")),
        &Public {
            schema: "bloom.pumpfun_operation.v1".into(),
            action: a.class().into(),
            status: p.status.clone(),
            signature: p.signature.clone(),
            api: p.api.clone(),
            message_sha256: p.message_sha256.clone(),
            updated_ms: host::now_ms(),
        },
        false,
    )
}
pub fn read_operation(owner: &SessionOwner, s: &str, o: &str) -> DispatchResponse {
    let mut operation = match get::<Public>(&sk(owner, s, &format!("operations/{o}.json"))) {
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
            operation.updated_ms = host::now_ms();
            if let Err(e) = put(
                &sk(owner, s, &format!("operations/{o}.json")),
                &operation,
                false,
            ) {
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

/// The canonical Solana mainnet-beta genesis hash. The Petal is
/// intentionally hardcoded to mainnet-beta; this constant is the one fact
/// the preflight verifies against the live RPC before any ceremony is
/// created.
const MAINNET_BETA_GENESIS_BASE58: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

/// Read-only, ceremony-free preflight for the Pump.fun setup path.
///
/// Never derives a session key, creates an approval, or changes policy. The
/// response separates three different things, and a reader should not confuse
/// them:
///
/// - `checks` — facts the Petal verified itself, and they held;
/// - `blockers` — checks the Petal ran and that failed;
/// - `operator_checks` — facts the Petal cannot see from inside the sandbox,
///   which a person has to confirm before funding. These are not failures.
///
/// `ok` reflects `blockers` only. An empty `blockers` list does not mean the
/// operator checks were done.
pub fn preflight(c: &Ctx, w: String) -> DispatchResponse {
    let mut blockers: Vec<Value> = Vec::new();
    let mut checks: Vec<Value> = Vec::new();
    let mut operator_checks: Vec<Value> = Vec::new();

    let now = host::now_ms();

    // 1. The running Machine artifact is bound to the canonical Pump.fun
    //    Petal package. A missing or wrong hash means the host cannot reach
    //    this Petal at all, and preflight is meaningless.
    let package_hash = c.package_hash.to_string();
    checks.push(json!({"check":"host_petal_binding","package_hash":package_hash}));

    // 2. Trusted time is reachable. The Petal relies on `now_ms` for
    //    session expiry checks; a zero or unreachable clock means every
    //    approval it produces would be malformed.
    if now == 0 {
        blockers.push(json!({
            "blocker":"trusted_clock_unavailable",
            "detail":"host reported zero trusted time; refuse to stage anything with a clock-bound approval window"
        }));
    }
    checks.push(json!({"check":"trusted_clock","now_ms":now}));

    // 3. Verify Solana mainnet-beta genesis against the live RPC. A
    //    mismatch, an unreachable endpoint, or a non-mainnet cluster all
    //    fail closed; the broadcast path is gated on this single fact.
    match verify_mainnet_genesis() {
        GenesisCheck::Ok { observed, endpoint } => {
            checks.push(json!({
                "check":"rpc_mainnet_genesis",
                "endpoint":endpoint,
                "observed_genesis":observed
            }));
        }
        GenesisCheck::Mismatch {
            observed,
            endpoint,
            expected,
        } => {
            blockers.push(json!({
                "blocker":"rpc_genesis_mismatch",
                "endpoint":endpoint,
                "observed_genesis":observed,
                "expected_genesis":expected,
                "detail":"the configured RPC endpoint is not serving Solana mainnet-beta"
            }));
        }
        GenesisCheck::Unreachable { endpoint, error } => {
            blockers.push(json!({
                "blocker":"rpc_unreachable",
                "endpoint":endpoint,
                "detail":error
            }));
        }
    }

    // 4. Verify the Pump.fun builder is reachable. Without it, no buy/sell
    //    transaction can be staged; the user would burn a session key
    //    with no way to spend it.
    match probe_builder() {
        BuilderCheck::Ok { endpoint, status } => {
            checks.push(json!({
                "check":"builder_reachable",
                "endpoint":endpoint,
                "probe_status":status
            }));
        }
        BuilderCheck::Unreachable { endpoint, error } => {
            blockers.push(json!({
                "blocker":"builder_unreachable",
                "endpoint":endpoint,
                "detail":error
            }));
        }
    }

    // 5. Look up an existing session if the caller named one in the URL.
    //    Preflight never derives a new key: the session must already exist,
    //    and any wallet named in the URL must already be known to the host.
    let session_id = c
        .params
        .iter()
        .find_map(|(k, v)| (k == "session").then_some(v.clone()));
    let mut session_block: Option<Value> = None;
    if let Some(sid) = session_id.as_deref() {
        match ident(sid, "session") {
            Ok(_) => match SessionOwner::scope(c, &w) {
                Ok(owner) => match get::<Session>(&sk(&owner, sid, "session.json")) {
                    Ok(Some(s)) => {
                        let expired = s.expires_ms <= now || s.stopped;
                        session_block = Some(json!({
                            "session":sid,
                            "address":s.address,
                            "created_ms":s.created_ms,
                            "expires_ms":s.expires_ms,
                            "duration_ms":s.duration_ms,
                            "stopped":s.stopped,
                            "expired":expired,
                            "remaining_ms": s.expires_ms.saturating_sub(now)
                        }));
                        if expired {
                            blockers.push(json!({
                                    "blocker":"session_expired",
                                    "session":sid,
                                    "detail":"named session is stopped or past its expiry; start a new session"
                                }));
                        }
                    }
                    Ok(None) => {
                        blockers.push(json!({
                            "blocker":"session_unknown",
                            "session":sid,
                            "detail":"no session with this id exists for the wallet"
                        }));
                    }
                    Err(e) => {
                        blockers.push(json!({
                            "blocker":"session_lookup_failed",
                            "session":sid,
                            "detail":format!("session store error: {}", dispatch_message(&e))
                        }));
                    }
                },
                Err(e) => {
                    blockers.push(json!({
                        "blocker":"session_scope_invalid",
                        "session":sid,
                        "detail":dispatch_message(&e)
                    }));
                }
            },
            Err(e) => {
                blockers.push(json!({
                    "blocker":"invalid_session_id",
                    "session":sid,
                    "detail":dispatch_message(&e)
                }));
            }
        }
    }

    // 5c. The Petal cannot see the host's wallet policy from inside the
    // sandbox, so it cannot tell whether the session address is an allowed
    // Solana destination. That is a fact for a person to confirm, not a check
    // this code ran and failed, so it is reported as an operator check.
    if let Some(block) = session_block.as_ref() {
        let session_address = block["address"].as_str().unwrap_or("").to_string();
        if !session_address.is_empty() {
            operator_checks.push(json!({
                "operator_check":"wallet_policy_lists_session_address",
                "session_address":session_address,
                "detail":"confirm the host wallet policy lists this session address under chain \"solana\" before funding it; the Petal cannot read wallet policy and has not checked this either way. An unlisted destination makes the funding transfer fail as an invalid claim after the ceremony is spent."
            }));
        }
    }

    // 5d. Funding is not the only destination wallet policy has to allow.
    // Every write declares the protocol program it routes through, and the
    // exit declares the return address; Bloom checks each against the wallet's
    // allowed destinations as a flat set. Listing them here is the difference
    // between one policy ceremony and discovering the gaps one refused trade
    // at a time. Tips are omitted: a write declares one only when the caller
    // sets `frontRunningProtection`.
    operator_checks.push(json!({
        "operator_check":"wallet_policy_lists_cycle_destinations",
        "required_for_trading": PROGRAMS[5..],
        "required_for_exit":"the owner address named as `destination` by close_token_account and sweep",
        "conditional":"the selected Jito tip account, only for writes that set frontRunningProtection",
        "detail":"every destination a write declares is checked against wallet policy, not just the funding address. Which of the two Pump programs a mint routes through depends on whether it has migrated, and the builder chooses — allow both, or read coins/<mint>.json first. Prepare one policy update covering the whole cycle."
    }));

    // 5e. The scoped signing key's real deadline lives in the Signer grant,
    // not in this Petal. Three expiries are visible during setup and only one
    // of them is that deadline, so name the right one rather than telling the
    // reader to "check the host": the ceremony countdown is clamped to the
    // browser TTL and is normally minutes, which badly understates the key.
    if session_block.is_some() {
        operator_checks.push(json!({
            "operator_check":"signing_scope_deadline_is_host_side",
            "authoritative_source":"the reusable approval's terms expires_at_ms, which Bloom sets to the Signer's petal_scope_expires_at_ms exactly",
            "not_this":"the ceremony expiry on the passkey page, which is min(now + browser ceremony TTL, the terms expiry) and says nothing about how long the key lives",
            "detail":"the session `expires_ms` below is the lifetime this Petal requested, timed from when the derive returned Ready — not the Signer's grant. Read the approval terms expiry, take the earlier of the two, and leave enough time to sell, close the token account, and sweep."
        }));
    }

    let ok = blockers.is_empty();
    let body = json!({
        "schema":"bloom.pumpfun_preflight.v1",
        "ok":ok,
        "wallet":w,
        "network":"solana-mainnet-beta",
        "expected_genesis":MAINNET_BETA_GENESIS_BASE58,
        "now_ms":now,
        "checks":checks,
        "blockers":blockers,
        "operator_checks":operator_checks,
        "session":session_block,
    });
    petal::read_json_value(&body)
}

enum GenesisCheck {
    Ok {
        observed: String,
        endpoint: String,
    },
    Mismatch {
        observed: String,
        endpoint: String,
        expected: String,
    },
    Unreachable {
        endpoint: String,
        error: String,
    },
}

fn verify_mainnet_genesis() -> GenesisCheck {
    let endpoint = RPC_VERIFY.to_string();
    let body = match serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"getGenesisHash"}))
    {
        Ok(v) => v,
        Err(e) => {
            return GenesisCheck::Unreachable {
                endpoint,
                error: format!("encode: {e}"),
            };
        }
    };
    let response = match fetch("POST", endpoint.clone(), body) {
        Ok(v) => v,
        Err(e) => {
            return GenesisCheck::Unreachable {
                endpoint,
                error: dispatch_message(&e),
            };
        }
    };
    let observed = response
        .get("result")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if observed.is_empty() {
        return GenesisCheck::Unreachable {
            endpoint,
            error: "getGenesisHash returned no result".into(),
        };
    }
    if observed != MAINNET_BETA_GENESIS_BASE58 {
        return GenesisCheck::Mismatch {
            observed,
            endpoint,
            expected: MAINNET_BETA_GENESIS_BASE58.into(),
        };
    }
    GenesisCheck::Ok { observed, endpoint }
}

enum BuilderCheck {
    Ok { endpoint: String, status: u16 },
    Unreachable { endpoint: String, error: String },
}

fn builder_probe_status_reachable(status: u16) -> bool {
    (200..300).contains(&status) || status == 400 || status == 422
}

fn probe_builder() -> BuilderCheck {
    let endpoint = format!("{BUILD}/agents/create-coin");
    let body = match serde_json::to_vec(&json!({
        "preflight": true,
        "publicKey": "11111111111111111111111111111111",
        "name": "preflight-probe",
        "symbol": "PREFLIGHT",
        "description": "read-only probe",
        "showName": true,
        "twitter": "",
        "telegram": "",
        "website": "",
        "uri": "https://example.com/preflight.json",
        "creator": null,
    })) {
        Ok(v) => v,
        Err(e) => {
            return BuilderCheck::Unreachable {
                endpoint,
                error: format!("encode: {e}"),
            };
        }
    };
    // This deliberately invalid, non-signing request must never create a
    // coin. A 400/422 validation response proves the exact builder route is
    // live without asking it to produce a transaction. Authentication,
    // routing, and server failures remain blockers.
    match host::http(
        &HttpRequest {
            method: "POST".into(),
            url: endpoint.clone(),
            headers: vec![("content-type".into(), "application/json".into())],
            body,
        },
        MAX,
    ) {
        Ok(response) if builder_probe_status_reachable(response.status) => BuilderCheck::Ok {
            endpoint,
            status: response.status,
        },
        Ok(response) => BuilderCheck::Unreachable {
            endpoint,
            error: format!("builder probe returned HTTP {}", response.status),
        },
        Err(e) => BuilderCheck::Unreachable {
            endpoint,
            error: sdk_message(&e),
        },
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
fn stored_children(prefix: &str, suffix: Option<&str>) -> Result<Vec<String>, DispatchResponse> {
    let keys = host::store_list(prefix, MAX).map_err(|error| fail(error.message()))?;
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
pub fn list_wallets(c: &Ctx) -> Result<Vec<petal::RouteChild>, DispatchResponse> {
    stored_children(
        &format!("state/{}", sessions_root(account_number(c)?)),
        None,
    )
    .map(|children| children.into_iter().map(petal::dir).collect())
}
pub fn list_sessions(c: &Ctx) -> Result<Vec<petal::RouteChild>, DispatchResponse> {
    let owner = SessionOwner::scope(c, &wallet(c)?)?;
    stored_children(&format!("state/{}", sessions_prefix(&owner)), None)
        .map(|children| children.into_iter().map(petal::dir).collect())
}
pub fn list_operations(c: &Ctx) -> Result<Vec<petal::RouteChild>, DispatchResponse> {
    let owner = SessionOwner::scope(c, &wallet(c)?)?;
    let session = session(c)?;
    stored_children(
        &format!("state/{}{session}/operations/", sessions_prefix(&owner)),
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
fn transaction_fee(
    transaction: &str,
    request: &Map<String, Value>,
) -> Result<u64, DispatchResponse> {
    let raw = B64
        .decode(transaction)
        .map_err(|_| fail("builder transaction is not base64"))?;
    let env = envelope(&raw).map_err(fail)?;
    let message = message(env.message).map_err(fail)?;
    let local_floor = local_fee_floor(&message, request).map_err(fail)?;
    let response = post(
        RPC,
        &rpc(
            "getFeeForMessage",
            json!([B64.encode(env.message), {"commitment":COMMITMENT}]),
        ),
    )?;
    let quoted = response
        .pointer("/result/value")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("Solana RPC did not quote the transaction fee"))?;
    Ok(quoted.max(local_floor))
}
/// Whether this transaction's blockhash has provably expired: the cluster's
/// finalized block height is past the `lastValidBlockHeight` recorded when it
/// was built. Transactions without that record are never treated as expired.
fn blockhash_expired(p: &Pending) -> Result<bool, DispatchResponse> {
    let Some(last_valid) = p.api.get("lastValidBlockHeight").and_then(Value::as_u64) else {
        return Ok(false);
    };
    let height = post(
        RPC,
        &rpc("getBlockHeight", json!([{"commitment":"finalized"}])),
    )?
    .get("result")
    .and_then(Value::as_u64)
    .ok_or_else(|| fail("Solana RPC omitted the finalized block height"))?;
    Ok(height > last_valid)
}
fn simulate(tx: &str) -> Result<(), DispatchResponse> {
    let v = post(
        RPC,
        &rpc(
            "simulateTransaction",
            json!([tx,{"encoding":"base64","sigVerify":false,"replaceRecentBlockhash":false,"commitment":COMMITMENT}]),
        ),
    )?;
    simulation_result(&v).map_err(fail)
}
fn simulation_result(v: &Value) -> Result<(), String> {
    match v.pointer("/result/value/err") {
        Some(Value::Null) => Ok(()),
        Some(_) => Err(format!("simulation failed: {}", safe(v))),
        None => Err("Solana RPC omitted the simulation result".into()),
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
    lookups: Vec<Lookup>,
}
struct Lookup {
    table: [u8; 32],
    writable: Vec<u8>,
    readonly: Vec<u8>,
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
    let mut lookups = Vec::with_capacity(nl);
    for _ in 0..nl {
        let table = b
            .get(o..o + 32)
            .ok_or("truncated lookup table key")?
            .try_into()
            .map_err(|_| "invalid lookup table key")?;
        o += 32;
        let w = short(b, &mut o)?;
        let writable = b.get(o..o + w).ok_or("truncated writable lookup")?.to_vec();
        o += w;
        let r = short(b, &mut o)?;
        let readonly = b.get(o..o + r).ok_or("truncated readonly lookup")?.to_vec();
        o += r;
        lookups.push(Lookup {
            table,
            writable,
            readonly,
        });
    }
    if o != b.len() {
        return Err("trailing message bytes".into());
    }
    Ok(Msg {
        keys,
        instructions,
        blockhash,
        required,
        lookups,
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
/// Solana's `find_program_address`: the first bump, counting down from 255,
/// whose hash is not an Ed25519 point.
fn program_address(seeds: &[&[u8]], program: &[u8; 32]) -> Result<[u8; 32], String> {
    (0..=u8::MAX)
        .rev()
        .find_map(|bump| {
            let mut hasher = Sha256::new();
            for seed in seeds {
                hasher.update(seed);
            }
            hasher.update([bump]);
            hasher.update(program);
            hasher.update(b"ProgramDerivedAddress");
            let address: [u8; 32] = hasher.finalize().into();
            CompressedEdwardsY(address)
                .decompress()
                .is_none()
                .then_some(address)
        })
        .ok_or_else(|| "no program address exists for these seeds".into())
}
/// The session's own token account for `mint`: the associated token account
/// under the SPL token program the instruction names at `program_position`.
/// Builder responses are untrusted, so the account that receives or spends a
/// trade's tokens is derived here rather than taken from the transaction.
fn require_payer_token_account(
    m: &Msg,
    ix: &Ix,
    position: usize,
    program_position: usize,
    payer: &[u8; 32],
    mint: &[u8; 32],
    label: &str,
) -> Result<(), String> {
    let token_program = account(m, ix, program_position)?;
    if token_program != &pk(PROGRAMS[3])? && token_program != &pk(PROGRAMS[4])? {
        return Err(format!("{label} token program is not SPL Token"));
    }
    let expected = program_address(&[payer, token_program, mint], &pk(PROGRAMS[2])?)?;
    require_account(m, ix, position, &expected, label)
}
/// The pool Pump creates when a coin graduates: index 0, owned by the Pump
/// program's pool authority for the mint, quoted in wrapped SOL. Anyone can
/// create another pool for the same pair, so only this one is accepted.
fn require_canonical_pool(m: &Msg, ix: &Ix, mint: &[u8; 32]) -> Result<(), String> {
    let authority = program_address(&[b"pool-authority", mint], &pk(PROGRAMS[5])?)?;
    let pool = program_address(
        &[b"pool", &[0, 0], &authority, mint, &pk(SOL)?],
        &pk(PROGRAMS[6])?,
    )?;
    require_account(m, ix, 0, &pool, "AMM pool")
}

fn validate_sweep_tx(
    transaction: &str,
    user: &str,
    destination: &str,
    lamports: u64,
) -> Result<(), DispatchResponse> {
    let raw = B64
        .decode(transaction)
        .map_err(|_| fail("invalid sweep base64"))?;
    let env = envelope(&raw).map_err(fail)?;
    let message = message(env.message).map_err(fail)?;
    let expected_keys = [
        pk(user).map_err(bad)?,
        pk(destination).map_err(bad)?,
        pk(PROGRAMS[1]).map_err(fail)?,
    ];
    if message.required != 1
        || !message.lookups.is_empty()
        || message.keys != expected_keys
        || message.instructions.len() != 1
    {
        return Err(fail("sweep transaction has an unexpected message shape"));
    }
    let ix = &message.instructions[0];
    let mut expected_data = 2u32.to_le_bytes().to_vec();
    expected_data.extend_from_slice(&lamports.to_le_bytes());
    if ix.program != 2 || ix.accounts != [0, 1] || ix.data != expected_data {
        return Err(fail(
            "sweep transaction is not the exact requested System transfer",
        ));
    }
    Ok(())
}

fn validate_close_token_account_tx(
    transaction: &str,
    user: &str,
    token_account: &str,
    destination: &str,
    token_program: &str,
) -> Result<(), DispatchResponse> {
    let raw = B64
        .decode(transaction)
        .map_err(|_| fail("invalid close-account base64"))?;
    let env = envelope(&raw).map_err(fail)?;
    let message = message(env.message).map_err(fail)?;
    let expected_keys = [user, token_account, destination, token_program]
        .map(pk)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    if message.required != 1
        || !message.lookups.is_empty()
        || message.keys != expected_keys
        || message.instructions.len() != 1
    {
        return Err(fail(
            "close-account transaction has an unexpected message shape",
        ));
    }
    let ix = &message.instructions[0];
    if ix.program != 3 || ix.accounts != [1, 2, 0] || ix.data != [9] {
        return Err(fail(
            "transaction is not the exact requested SPL Token CloseAccount",
        ));
    }
    Ok(())
}

fn append_lookup_addresses(message: &mut Msg, tables: &Map<String, Value>) -> Result<(), String> {
    let mut writable = Vec::new();
    let mut readonly = Vec::new();
    for lookup in &message.lookups {
        let table = bs58::encode(lookup.table).into_string();
        let addresses = tables
            .get(&table)
            .ok_or_else(|| format!("lookup table {table} missing"))?;
        let address_at = |index: u8| -> Result<[u8; 32], String> {
            let value = match addresses {
                Value::Array(values) => values.get(index as usize),
                Value::Object(values) => values.get(&index.to_string()),
                _ => None,
            }
            .and_then(Value::as_str)
            .ok_or_else(|| format!("lookup table {table} address {index} missing"))?;
            pk(value)
        };
        writable.extend(
            lookup
                .writable
                .iter()
                .map(|index| address_at(*index))
                .collect::<Result<Vec<_>, _>>()?,
        );
        readonly.extend(
            lookup
                .readonly
                .iter()
                .map(|index| address_at(*index))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    message.keys.extend(writable);
    message.keys.extend(readonly);
    Ok(())
}

fn hydrate_lookups(message: &mut Msg, _response: &Value) -> Result<(), DispatchResponse> {
    if message.lookups.is_empty() {
        return Ok(());
    }
    #[cfg(test)]
    let tables = _response
        .get("_lookupTableAddresses")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(test_lookup_tables);
    #[cfg(not(test))]
    let tables = {
        let mut tables = Map::new();
        for lookup in &message.lookups {
            let table = bs58::encode(lookup.table).into_string();
            let addresses = fetch_lookup_table(RPC, &table)?;
            if addresses != fetch_lookup_table(RPC_VERIFY, &table)? {
                return Err(fail(format!(
                    "independent RPCs disagree on address lookup table {table}"
                )));
            }
            tables.insert(table, Value::Array(addresses));
        }
        tables
    };
    append_lookup_addresses(message, &tables)
        .map_err(|error| fail(format!("unsafe builder transaction: {error}")))
}

#[cfg(not(test))]
fn fetch_lookup_table(url: &str, table: &str) -> Result<Vec<Value>, DispatchResponse> {
    let value = post(
        url,
        &rpc(
            "getAccountInfo",
            json!([table, {"encoding":"jsonParsed","commitment":"finalized"}]),
        ),
    )?;
    if value.pointer("/result/value/owner").and_then(Value::as_str)
        != Some(ADDRESS_LOOKUP_TABLE_PROGRAM)
        || value
            .pointer("/result/value/data/program")
            .and_then(Value::as_str)
            != Some("address-lookup-table")
        || value
            .pointer("/result/value/data/parsed/type")
            .and_then(Value::as_str)
            != Some("lookupTable")
    {
        return Err(fail(format!("invalid address lookup table {table}")));
    }
    value
        .pointer("/result/value/data/parsed/info/addresses")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| fail(format!("address lookup table {table} omitted addresses")))
}

#[cfg(test)]
fn test_lookup_tables() -> Map<String, Value> {
    json!({
        "Hyif6eWb8x88RVrvjPfabsgRYnwkVnyByEXTVTXbUcyP": {
            "0":"6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
            "1":"4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf",
            "3":"Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1",
            "4":"Hq2wp8uJ9jCPsYgNHex8RtqdvMPfVGoYwjvF1ATiwn2Y",
            "5":"pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
            "6":"GS4CU59F31iL7aR2Q8zVS8DRrcRnXX1yjQ66TqNVQnaR",
            "10":"11111111111111111111111111111111",
            "11":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "12":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "13":"ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            "14":"8Wf5TiAheLUqBrKXeYg2JtAFFMWtKdG2BSFgqUcPVwTt",
            "15":"pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ",
            "16":"MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e",
            "18":"13ec7XdrjF3h3YcqBTFDSReRcUFwbCnJaAQspM4j6DDJ",
            "19":"BwWK17cbHxwWBKZkUYvzxLcNQ1YVyaFezduWbtm2de6s",
            "26":"CebN5WGQ4jvEPvsVU4EoHEpgzq1VV7AbicfhtW4xC9iM",
            "27":"FWsW1xNtWscwNmKv6wVsU1iTzRN6wmmk3MjxRP5tT7hz",
            "32":"3BpXnfJaUTiwXnJNe7Ej1rcbzqTTQUvLShZaWazebsVR",
            "36":"A7hAgCzFw14fejgCp387JUJRMNyz4j89JKnhtKU8piqW",
            "41":"8sNeir4QsLsJdYpc9RZacohhK1Y5FLU3nC5LXgYB4aa6",
            "124":"So11111111111111111111111111111111111111112",
            "151":"D6QxXDt6hhcCpto4HiZKkN2YQ2iZRF5R7S3caCHpUsML",
            "154":"ALeLWphFxNVNXpXFEC4Ssf2Jan1Wki72Us8tXMMrQuQZ",
            "155":"HcAR1LpgSGFxeLyb1vkhsCuN6AtxQsww3E2pMMXkwHqx",
            "158":"TSLvdd1pWpHVjahSpsvCXUbgwsL3JAcvokwaKt1eokM"
        }
    })
    .as_object()
    .expect("test lookup fixture object")
    .clone()
}

fn validate_tx(
    transaction: &str,
    user: &str,
    action: Action,
    request: &Map<String, Value>,
    response: &Value,
) -> Result<(), DispatchResponse> {
    let raw = B64
        .decode(transaction)
        .map_err(|_| fail("unsafe builder transaction: invalid base64"))?;
    let env =
        envelope(&raw).map_err(|error| fail(format!("unsafe builder transaction: {error}")))?;
    let mut message = message(env.message)
        .map_err(|error| fail(format!("unsafe builder transaction: {error}")))?;
    hydrate_lookups(&mut message, response)?;
    let payer = pk(user).map_err(fail)?;
    if message.keys.first() != Some(&payer) {
        return Err(fail("unsafe builder transaction: payer is not session key"));
    }
    let mint_text = if matches!(action, Action::Create) {
        response
            .get("mintPublicKey")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("unsafe builder transaction: mint missing"))?
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
            .ok_or_else(|| fail("unsafe builder transaction: requested mint missing"))?
    };
    let mint = pk(mint_text).map_err(fail)?;
    if matches!(action, Action::Create) && message.keys.get(1) != Some(&mint) {
        return Err(fail("unsafe builder transaction: mint signer mismatch"));
    }
    validate_message(&message, &payer, &mint, action, request, response)
        .map_err(|error| fail(format!("unsafe builder transaction: {error}")))
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
fn validate_compute_budget(message: &Msg, request: &Map<String, Value>) -> Result<u64, String> {
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
    u64::try_from(priority_fee).map_err(|_| "priority fee overflows u64".into())
}

fn local_fee_floor(message: &Msg, request: &Map<String, Value>) -> Result<u64, String> {
    let base = u64::try_from(message.required)
        .map_err(|_| "signer count overflows u64")?
        .checked_mul(5_000)
        .ok_or("base fee overflows u64")?;
    base.checked_add(validate_compute_budget(message, request)?)
        .ok_or_else(|| "transaction fee overflows u64".into())
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
    _response: &Value,
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
            if account(message, ix, 4)? != &system {
                return Err("associated-token System program mismatch".into());
            }
            let token_program = account(message, ix, 5)?;
            if token_program != &token && token_program != &token_2022 {
                return Err("unapproved associated-token program".into());
            }
            let mint_allowed = match action {
                Action::Create => account_mint == mint,
                Action::Buy | Action::Sell => account_mint == mint || account_mint == &wrapped_mint,
                Action::Fees | Action::Sharing => account_mint == &wrapped_mint,
                Action::CloseTokenAccount | Action::Sweep => false,
            };
            if !mint_allowed {
                return Err("associated-token mint is unrelated to the request".into());
            }
            if owner != payer {
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
                require_payer_token_account(
                    message,
                    ix,
                    5,
                    8,
                    payer,
                    mint,
                    "initial-buy recipient",
                )?;
                require_account(message, ix, 6, payer, "initial-buy user")?;
                let requested = request_u64(request, "solLamports")?;
                let maximum = u128::from(requested) + (u128::from(requested) * 2).div_ceil(100);
                validate_buy_cost(ix, maximum)?;
                validate_minimum_output(ix, 8, request_u64(request, "minOutputAmount")?)?;
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
                require_payer_token_account(message, ix, 5, 8, payer, mint, "buy recipient")?;
                require_account(message, ix, 6, payer, "buy user")?;
                validate_buy_cost(ix, max_buy_lamports(request)?)?;
                validate_minimum_output(ix, 8, request_u64(request, "minOutputAmount")?)?;
                primary += 1;
            }
            Action::Buy if program == &amm && has_discriminator(ix, IX_BUY) => {
                require_canonical_pool(message, ix, mint)?;
                require_account(message, ix, 1, payer, "AMM buy user")?;
                require_account(message, ix, 3, mint, "AMM buy mint")?;
                require_account(message, ix, 4, &wrapped_mint, "AMM buy quote mint")?;
                require_payer_token_account(message, ix, 5, 11, payer, mint, "AMM buy recipient")?;
                require_payer_token_account(
                    message,
                    ix,
                    6,
                    12,
                    payer,
                    &wrapped_mint,
                    "AMM buy wrapped SOL source",
                )?;
                validate_buy_cost(ix, max_buy_lamports(request)?)?;
                validate_minimum_output(ix, 8, request_u64(request, "minOutputAmount")?)?;
                primary += 1;
            }
            Action::Sell if program == &pump && has_discriminator(ix, IX_SELL) => {
                require_account(message, ix, 2, mint, "sell mint")?;
                require_account(message, ix, 6, payer, "sell user")?;
                validate_sell_amount(ix, request_u64(request, "amount")?)?;
                validate_minimum_output(ix, 16, request_u64(request, "minOutputAmount")?)?;
                primary += 1;
            }
            Action::Sell if program == &amm && has_discriminator(ix, IX_SELL) => {
                require_canonical_pool(message, ix, mint)?;
                require_account(message, ix, 1, payer, "AMM sell user")?;
                require_account(message, ix, 3, mint, "AMM sell mint")?;
                require_account(message, ix, 4, &wrapped_mint, "AMM sell quote mint")?;
                require_payer_token_account(message, ix, 5, 11, payer, mint, "AMM sell source")?;
                require_payer_token_account(
                    message,
                    ix,
                    6,
                    12,
                    payer,
                    &wrapped_mint,
                    "AMM sell recipient",
                )?;
                validate_sell_amount(ix, request_u64(request, "amount")?)?;
                validate_minimum_output(ix, 16, request_u64(request, "minOutputAmount")?)?;
                primary += 1;
            }
            Action::Fees
                if program == &pump
                    && has_discriminator(ix, IX_CLAIM_CASHBACK)
                    && request.get("feeKind").and_then(Value::as_str) == Some("cashback") =>
            {
                require_account(message, ix, 0, payer, "cashback user")?;
                require_account(message, ix, 2, &pk(PROGRAMS[1])?, "cashback System program")?;
                require_account(message, ix, 4, &pump, "cashback program")?;
                primary += 1;
            }
            Action::Fees
                if program == &pump
                    && has_discriminator(ix, IX_COLLECT_CREATOR_FEE)
                    && request.get("feeKind").and_then(Value::as_str) == Some("creator") =>
            {
                require_account(message, ix, 0, payer, "creator fee recipient")?;
                require_account(
                    message,
                    ix,
                    2,
                    &pk(PROGRAMS[1])?,
                    "creator fee System program",
                )?;
                require_account(message, ix, 4, &pump, "creator fee program")?;
                primary += 1;
            }
            Action::Fees
                if program == &pump
                    && has_discriminator(ix, IX_DISTRIBUTE_CREATOR_FEES)
                    && request.get("feeKind").and_then(Value::as_str)
                        == Some("sharing_distribution") =>
            {
                require_account(message, ix, 0, mint, "fee-distribution mint")?;
                primary += 1;
            }
            Action::Fees
                if program == &amm
                    && has_discriminator(ix, IX_CLAIM_CASHBACK)
                    && request.get("feeKind").and_then(Value::as_str) == Some("cashback") =>
            {
                require_account(message, ix, 0, payer, "AMM cashback user")?;
                require_account(message, ix, 2, &wrapped_mint, "AMM cashback quote mint")?;
                require_account(
                    message,
                    ix,
                    3,
                    &pk(PROGRAMS[3])?,
                    "AMM cashback token program",
                )?;
                require_account(
                    message,
                    ix,
                    6,
                    &pk(PROGRAMS[1])?,
                    "AMM cashback System program",
                )?;
                require_account(message, ix, 8, &amm, "AMM cashback program")?;
                primary += 1;
            }
            Action::Fees
                if program == &amm
                    && has_discriminator(ix, IX_AMM_COLLECT_CREATOR_FEE)
                    && request.get("feeKind").and_then(Value::as_str) == Some("creator") =>
            {
                require_account(message, ix, 0, &wrapped_mint, "AMM fee quote mint")?;
                require_account(message, ix, 1, &pk(PROGRAMS[3])?, "AMM fee token program")?;
                require_account(message, ix, 2, payer, "AMM creator fee recipient")?;
                require_account(message, ix, 7, &amm, "AMM creator fee program")?;
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
fn validate_minimum_output(ix: &Ix, offset: usize, requested: u64) -> Result<(), String> {
    if instruction_u64(ix, offset)? >= requested {
        Ok(())
    } else {
        Err("transaction minimum output is below the approved request".into())
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
    let owner = match SessionOwner::scope(c, &w) {
        Ok(owner) => owner,
        Err(e) => return e,
    };
    execute(c, a, owner, s, b)
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
    let owner = match SessionOwner::scope(c, &w) {
        Ok(owner) => owner,
        Err(e) => return e,
    };
    read_session(&owner, &s)
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
    let owner = match SessionOwner::scope(c, &w) {
        Ok(owner) => owner,
        Err(e) => return e,
    };
    read_operation(&owner, &s, &o)
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
    fn session_owner_is_the_mounted_account_number() {
        let account = |n| SessionOwner::from_params(WALLET, Some(WALLET), Some(n)).unwrap();
        // The flat mount and account 0 are one owner.
        assert_eq!(legacy_owner(), account("0"));
        assert_ne!(legacy_owner(), account("1"));
        // A session wallet other than the mounted one never borrows the
        // mounted account's scope.
        assert!(SessionOwner::from_params("other", Some(WALLET), Some("1")).is_err());
        assert!(SessionOwner::from_params(WALLET, Some(WALLET), Some("-1")).is_err());
    }

    #[test]
    fn the_same_session_id_on_two_accounts_yields_two_slots_and_records() {
        let account = |n| SessionOwner::from_params(WALLET, Some(WALLET), Some(n)).unwrap();
        let (flat, zero, one, two) = (legacy_owner(), account("0"), account("1"), account("2"));
        assert_eq!(
            session_key_slot(&flat, SESSION),
            session_key_slot(&zero, SESSION)
        );
        assert_ne!(
            session_key_slot(&zero, SESSION),
            session_key_slot(&one, SESSION)
        );
        assert_ne!(
            session_key_slot(&one, SESSION),
            session_key_slot(&two, SESSION)
        );
        assert_eq!(
            sk(&flat, SESSION, "session.json"),
            format!("state/sessions/{WALLET}/{SESSION}/session.json")
        );
        assert_eq!(
            sk(&one, SESSION, "session.json"),
            format!("state/account-sessions/1/{WALLET}/{SESSION}/session.json")
        );
        assert_eq!(
            session_sec(&two, SESSION),
            format!("account-sessions/2/{WALLET}/{SESSION}/session.json")
        );
        // Each account's listing root holds exactly its own wallet tree.
        for owner in [&flat, &one, &two] {
            let root = format!("state/{}", sessions_root(owner.account));
            for other in [&flat, &one, &two] {
                assert_eq!(
                    sk(other, SESSION, "session.json").starts_with(&format!("{root}{WALLET}/")),
                    owner == other
                );
            }
        }
    }
    #[test]
    fn recovery_actions_request_exact_signing() {
        assert_eq!(Action::CloseTokenAccount.selector(), SignSelector::Exact);
        assert_eq!(Action::Sweep.selector(), SignSelector::Exact);
        for a in [
            Action::Create,
            Action::Buy,
            Action::Sell,
            Action::Fees,
            Action::Sharing,
        ] {
            assert_eq!(a.selector(), SignSelector::Reusable);
        }
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
            json!({"name":"Bloom Fixture","symbol":"BLMF","uri":"https://example.com/pumpfun-fixture.json","solLamports":"1000000","minOutputAmount":"1"}),
        );
        assert_fixture(
            "mayhem",
            Action::Create,
            json!({"name":"Bloom Mayhem Fixture","symbol":"BLMM","uri":"https://example.com/pumpfun-mayhem-fixture.json","solLamports":"1000000","minOutputAmount":"1","mayhemMode":true,"frontRunningProtection":true,"tipAmount":0.0001}),
        );
        assert_fixture(
            "agent",
            Action::Create,
            json!({"name":"Bloom Agent Fixture","symbol":"BLMA","uri":"https://example.com/pumpfun-agent-fixture.json","solLamports":"1000000","minOutputAmount":"1","tokenizedAgent":true,"buybackBps":5000}),
        );
        assert_fixture(
            "buy_bond",
            Action::Buy,
            json!({"mint":BOND_MINT,"amount":"1000000","minOutputAmount":"1","slippagePct":2}),
        );
        assert_fixture(
            "buy_amm",
            Action::Buy,
            json!({"mint":AMM_MINT,"amount":"1000000","minOutputAmount":"1","slippagePct":2}),
        );
        assert_fixture(
            "fees",
            Action::Fees,
            json!({"mint":BOND_MINT,"feeKind":"cashback"}),
        );
        assert_fixture_for(
            "sharing",
            Action::Sharing,
            AMM_CREATOR,
            json!({"mint":AMM_MINT,"shareholders":[{"address":AMM_CREATOR,"bps":10000}]}),
        );
    }
    #[test]
    fn zero_output_sell_quotes_are_rejected() {
        for (fixture_name, mint) in [("sell_bond", BOND_MINT), ("sell_amm", AMM_MINT)] {
            let response = fixture(fixture_name);
            let transaction = response
                .get("transaction")
                .and_then(Value::as_str)
                .expect("fixture transaction");
            let request = normalized(
                Action::Sell,
                json!({"mint":mint,"amount":"1","minOutputAmount":"1","slippagePct":2}),
            );
            assert!(validate_tx(transaction, USER, Action::Sell, &request, &response).is_err());
        }
    }
    #[test]
    fn fee_collection_requires_an_explicit_bound_kind() {
        let mut request = json!({"mint":BOND_MINT}).as_object().unwrap().clone();
        assert!(normalize(Action::Fees, USER, &mut request).is_err());
    }
    #[test]
    fn simulation_requires_an_explicit_result() {
        assert!(simulation_result(&json!({"result":{"value":{"err":null}}})).is_ok());
        assert!(simulation_result(&json!({"result":{"value":{"err":{"code":1}}}})).is_err());
        assert!(simulation_result(&json!({"result":{"value":{}}})).is_err());
        assert!(simulation_result(&json!({})).is_err());
    }
    #[test]
    fn sweep_is_one_exact_system_transfer_and_declares_its_destination() {
        let message_bytes = sweep_message(USER, AMM_CREATOR, BOND_MINT, 123_456).unwrap();
        let mut transaction = vec![1];
        transaction.extend_from_slice(&[0; 64]);
        transaction.extend_from_slice(&message_bytes);
        let encoded = B64.encode(transaction);
        validate_sweep_tx(&encoded, USER, AMM_CREATOR, 123_456).unwrap();

        let parsed = message(&message_bytes).unwrap();
        let request = normalized(Action::Sweep, json!({"destination":AMM_CREATOR}));
        assert_eq!(
            effects(Action::Sweep, &request, &parsed).unwrap(),
            vec![json!({"asset":{"chain":"solana","asset":"native"},"amount":"123456"})]
        );
        assert_eq!(
            destinations(Action::Sweep, &parsed),
            vec![json!({"chain":"solana","destination":AMM_CREATOR})]
        );
        assert!(validate_sweep_tx(&encoded, USER, AMM_CREATOR, 123_455).is_err());
        assert!(
            normalize(
                Action::Sweep,
                USER,
                &mut json!({"destination":USER}).as_object().unwrap().clone()
            )
            .is_err()
        );
    }
    #[test]
    fn close_token_account_is_one_exact_instruction_and_declares_its_destination() {
        let token_account = "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf";
        let message_bytes =
            close_token_account_message(USER, token_account, AMM_CREATOR, PROGRAMS[3], BOND_MINT)
                .unwrap();
        let mut transaction = vec![1];
        transaction.extend_from_slice(&[0; 64]);
        transaction.extend_from_slice(&message_bytes);
        let encoded = B64.encode(transaction);
        validate_close_token_account_tx(&encoded, USER, token_account, AMM_CREATOR, PROGRAMS[3])
            .unwrap();

        let parsed = message(&message_bytes).unwrap();
        let request = normalized(
            Action::CloseTokenAccount,
            json!({"mint":BOND_MINT,"tokenAccount":token_account,"destination":AMM_CREATOR,"maxLamports":"2100000"}),
        );
        assert_eq!(
            effects(Action::CloseTokenAccount, &request, &parsed).unwrap(),
            vec![json!({"asset":{"chain":"solana","asset":"native"},"amount":"2100000"})]
        );
        assert_eq!(
            destinations(Action::CloseTokenAccount, &parsed),
            vec![json!({"chain":"solana","destination":AMM_CREATOR})]
        );

        let mut tampered = B64.decode(encoded).unwrap();
        *tampered.last_mut().unwrap() = 8;
        assert!(
            validate_close_token_account_tx(
                &B64.encode(tampered),
                USER,
                token_account,
                AMM_CREATOR,
                PROGRAMS[3]
            )
            .is_err()
        );
        assert!(
            normalize(
                Action::CloseTokenAccount,
                USER,
                &mut json!({"mint":BOND_MINT,"tokenAccount":token_account,"destination":USER,"maxLamports":"2100000"})
                    .as_object()
                    .unwrap()
                    .clone()
            )
            .is_err()
        );
    }
    #[test]
    fn local_fee_floor_includes_base_and_priority_fees() {
        let response = fixture("buy_bond");
        let raw = B64
            .decode(response.get("transaction").and_then(Value::as_str).unwrap())
            .unwrap();
        let env = envelope(&raw).unwrap();
        let parsed = message(env.message).unwrap();
        let request = normalized(
            Action::Buy,
            json!({"mint":BOND_MINT,"amount":"1000000","minOutputAmount":"1","slippagePct":2}),
        );
        assert!(local_fee_floor(&parsed, &request).unwrap() > 5_000);
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
            json!({"mint":BOND_MINT,"amount":"1000000","minOutputAmount":"1","slippagePct":2}),
        );
        (message, request, response)
    }
    /// Builder transactions are untrusted, so every account that receives or
    /// spends a trade's tokens, the AMM pool, and the token program used to
    /// derive them must be the session's own. Each is swapped for a stranger's
    /// account in an otherwise valid transaction.
    #[test]
    fn verifier_rejects_substituted_trade_accounts_and_pools() {
        let parsed = |name: &str, action: Action, request: Value| {
            let response = fixture(name);
            let raw = B64
                .decode(response.get("transaction").and_then(Value::as_str).unwrap())
                .unwrap();
            let mut message = message(envelope(&raw).unwrap().message).unwrap();
            assert!(hydrate_lookups(&mut message, &response).is_ok());
            (message, normalized(action, request), response)
        };
        let create = json!({"name":"Bloom Fixture","symbol":"BLMF","uri":"https://example.com/pumpfun-fixture.json","solLamports":"1000000","minOutputAmount":"1"});
        let buy =
            |mint| json!({"mint":mint,"amount":"1000000","minOutputAmount":"1","slippagePct":2});
        let sell = json!({"mint":AMM_MINT,"amount":"1","minOutputAmount":"1","slippagePct":2});
        let cases = [
            ("create", Action::Create, create, PROGRAMS[5], vec![5, 8]),
            (
                "buy_bond",
                Action::Buy,
                buy(BOND_MINT),
                PROGRAMS[5],
                vec![5, 8],
            ),
            (
                "buy_amm",
                Action::Buy,
                buy(AMM_MINT),
                PROGRAMS[6],
                vec![0, 5, 6, 11, 12],
            ),
            (
                "sell_amm",
                Action::Sell,
                sell,
                PROGRAMS[6],
                vec![0, 5, 6, 11, 12],
            ),
        ];
        for (name, action, request, program, positions) in cases {
            let response = fixture(name);
            let mint = pk(response["mintPublicKey"]
                .as_str()
                .or(request["mint"].as_str())
                .unwrap())
            .unwrap();
            let program = pk(program).unwrap();
            let payer = pk(USER).unwrap();
            let prepared = || {
                let (mut message, request, response) = parsed(name, action, request.clone());
                let trade = message
                    .instructions
                    .iter()
                    .position(|ix| {
                        message.keys.get(ix.program) == Some(&program)
                            && (has_discriminator(ix, IX_BUY) || has_discriminator(ix, IX_SELL))
                    })
                    .unwrap();
                // The recorded sell quotes zero output, which is refused on its own.
                if matches!(action, Action::Sell) {
                    message.instructions[trade].data[16..24].copy_from_slice(&1u64.to_le_bytes());
                }
                (message, request, response, trade)
            };
            let (message, request, response, _) = prepared();
            validate_message(&message, &payer, &mint, action, &request, &response)
                .unwrap_or_else(|error| panic!("{name}: {error}"));

            for position in positions {
                let (mut message, request, response, trade) = prepared();
                message.keys.push([7; 32]);
                message.instructions[trade].accounts[position] =
                    u8::try_from(message.keys.len() - 1).unwrap();
                assert!(
                    validate_message(&message, &payer, &mint, action, &request, &response).is_err(),
                    "{name}: account {position} was substituted"
                );
            }
        }
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
            approval_value_limits: Vec::new(),
            created_ms: 1,
            expires_ms: 60_001,
            stopped: false,
        };
        let encoded = serde_json::to_value(session).expect("serialize session");
        assert!(encoded.get("key_ref_jcs").is_none());
    }

    // --- route-to-host tests --------------------------------------------
    //
    // These run a real route flow against the recording fake host in
    // `fake_host`, so they observe the requests that actually leave the Petal
    // rather than searching the source for strings.

    use crate::fake_host::{self, FakeHost};
    use petal::{HostStatus, RouteIdentity};

    const WALLET: &str = "main";

    fn legacy_owner() -> SessionOwner {
        SessionOwner::from_params(WALLET, None, None).unwrap()
    }
    const SESSION: &str = "agent-1";
    const NOW_MS: u64 = 1_757_000_000_000;
    const SWAP_URL: &str = "https://fun-block.pump.fun/agents/swap";
    const PROBE_URL: &str = "https://fun-block.pump.fun/agents/create-coin";

    struct TestRoute;
    impl RouteIdentity for TestRoute {
        const PATH: &'static str = "sessions/[wallet]/sessions/[session]/buy.json";
        const CANONICAL_PATH: &'static str = "sessions/[wallet]/sessions/[session]/buy.json";
        const PARAMS: &'static [(&'static str, usize)] = &[];
    }

    fn ctx(params: &[(&str, &str)]) -> Ctx {
        Ctx::bind::<TestRoute>(petal::RawCtx {
            petal_root: "/petals/pumpfun".into(),
            package_hash: "pumpfun-test-package".into(),
            path: "sessions/main/sessions/agent-1/buy.json".into(),
            params: params
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            actor: None,
        })
    }

    fn live_session() -> Session {
        Session {
            schema: "bloom.pumpfun_session.v1".into(),
            wallet: WALLET.into(),
            id: SESSION.into(),
            address: USER.into(),
            duration_ms: 3_600_000,
            approval_value_limits: Vec::new(),
            created_ms: NOW_MS,
            expires_ms: NOW_MS + 3_600_000,
            stopped: false,
        }
    }

    fn test_signature() -> Vec<u8> {
        vec![7u8; 64]
    }

    fn test_signature_base58() -> String {
        bs58::encode(test_signature()).into_string()
    }

    /// A fake host holding a live session and able to serve one whole buy:
    /// builder quote, fee quote, successful simulation, accepted broadcast.
    fn host_serving_a_buy() -> FakeHost {
        let mut host = FakeHost::new(NOW_MS);
        host.seed_state(
            &sk(&legacy_owner(), SESSION, "session.json"),
            &live_session(),
        );
        host.seed_secret(
            &session_sec(&legacy_owner(), SESSION),
            &SessionSecret {
                key_ref_jcs: br#"{"public_key_fingerprint":"test-fingerprint"}"#.to_vec(),
            },
        );
        host.reply(SWAP_URL, fixture("buy_bond"));
        host.reply(
            &format!("{RPC} getFeeForMessage"),
            json!({"result":{"value":5_000}}),
        );
        host.reply(
            &format!("{RPC} simulateTransaction"),
            json!({"result":{"value":{"err":null}}}),
        );
        let accepted = json!({ "result": test_signature_base58() });
        host.reply(&format!("{RPC} sendTransaction"), accepted.clone());
        host.reply(&format!("{JITO} sendTransaction"), accepted);
        host
    }

    fn buy_body(operation: &str, protected: bool) -> Vec<u8> {
        let mut request = json!({
            "operationId": operation,
            "mint": BOND_MINT,
            "amount": "1000000",
            "minOutputAmount": "1",
            "slippagePct": 2,
        });
        if protected {
            request["frontRunningProtection"] = json!(true);
        }
        serde_json::to_vec(&request).expect("request serializes")
    }

    fn run_buy(operation: &str, protected: bool) -> DispatchResponse {
        execute(
            &ctx(&[("bloom.route_id", "ROUTE_BUY")]),
            Action::Buy,
            legacy_owner(),
            SESSION.into(),
            &buy_body(operation, protected),
        )
    }

    fn public_operation(operation: &str) -> Value {
        fake_host::with(|host| {
            host.state_json(&sk(
                &legacy_owner(),
                SESSION,
                &format!("operations/{operation}.json"),
            ))
            .expect("operation projection was published")
        })
    }

    /// A session Bloom no longer authorizes (stopped, expired, or out of
    /// budget) or has not finished approving refuses a trade before the
    /// builder is called, and records nothing.
    #[test]
    fn a_trade_asks_bloom_for_session_authority_before_the_builder() {
        for (outcome, reason) in [
            (
                Err(SdkError::Host(HostStatus::Denied)),
                "no longer authorizes",
            ),
            (
                Ok(petal::PetalKeyOutcome::Pending {
                    operation_id: "key-op".into(),
                    scope_digest: "scope".into(),
                }),
                "pending",
            ),
        ] {
            let mut host = host_serving_a_buy();
            host.derivation(outcome);
            fake_host::install(host);
            let response = run_buy("buy-refused", false);
            assert!(
                dispatch_message(&response).contains(reason),
                "{}",
                dispatch_message(&response)
            );
            fake_host::with(|host| {
                assert!(
                    host.calls.is_empty(),
                    "no builder or RPC call: {:?}",
                    host.rpc_methods()
                );
                assert_eq!(host.key_requests.len(), 1);
                assert!(
                    host.secret_json(&sec(&legacy_owner(), SESSION, "buy-refused"))
                        .is_none()
                );
            });
        }
    }

    #[test]
    fn a_buy_reaches_the_host_as_an_ordinary_send_transaction() {
        fake_host::install(host_serving_a_buy());
        let response = run_buy("buy-1", false);
        assert_eq!(
            response,
            DispatchResponse::Write,
            "{}",
            dispatch_message(&response)
        );

        fake_host::with(|host| {
            assert!(
                !host.rpc_methods().contains(&"bloomPumpfunCanaryStatus"),
                "the Petal must not ask any host for a canary status: {:?}",
                host.rpc_methods()
            );
            let sends = host.calls_for("sendTransaction");
            assert_eq!(sends.len(), 1, "exactly one broadcast attempt");
            let send = sends[0];
            assert_eq!(send.url, RPC, "an unprotected buy uses the public RPC");
            assert_eq!(send.method, "POST");
            assert_eq!(
                send.body.get("jsonrpc").and_then(Value::as_str),
                Some("2.0")
            );
            assert!(
                send.body.get("bloom_canary").is_none(),
                "sendTransaction must be a standard JSON-RPC request: {}",
                send.body
            );
            assert_eq!(
                send.body
                    .as_object()
                    .expect("request object")
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>(),
                vec![
                    "id".to_string(),
                    "jsonrpc".into(),
                    "method".into(),
                    "params".into()
                ]
            );
            let params = send.rpc_params().expect("params");
            assert!(
                params[0].as_str().is_some_and(|tx| !tx.is_empty()),
                "the signed transaction is the first parameter"
            );
            assert_eq!(params[1]["encoding"], json!("base64"));
            assert_eq!(params[1]["skipPreflight"], json!(false));
            assert_eq!(params[1]["preflightCommitment"], json!("confirmed"));
            let simulation = host.calls_for("simulateTransaction")[0]
                .rpc_params()
                .expect("simulation params");
            assert_eq!(simulation[1]["commitment"], json!("confirmed"));
        });

        assert_eq!(public_operation("buy-1")["status"], json!("submitted"));
        assert_eq!(
            public_operation("buy-1")["signature"],
            json!(test_signature_base58())
        );
    }

    #[test]
    fn a_rejected_send_names_the_json_rpc_error_code_and_message() {
        let body = json!({
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": "Internal error: blockhash not found"},
            "id": 73
        });
        let kept = safe(&body);
        let kept: Value = serde_json::from_str(&kept).expect("sanitized body is JSON");
        assert_eq!(kept["code"], json!(-32000));
        assert_eq!(
            kept["message"],
            json!("Internal error: blockhash not found")
        );
        assert!(
            !kept["error"].is_object(),
            "the raw error object must not pass through: {kept}"
        );
    }

    #[test]
    fn an_unprotected_buy_retries_a_rejected_send_once_on_the_verify_rpc() {
        let mut host = host_serving_a_buy();
        host.reply_only(
            &format!("{RPC} sendTransaction"),
            json!({
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "Internal error"},
                "id": 1
            }),
        );
        host.reply(
            &format!("{RPC_VERIFY} sendTransaction"),
            json!({"result": test_signature_base58()}),
        );
        fake_host::install(host);
        let response = run_buy("buy-verify-retry", false);
        assert_eq!(
            response,
            DispatchResponse::Write,
            "{}",
            dispatch_message(&response)
        );

        fake_host::with(|host| {
            let sends = host.calls_for("sendTransaction");
            assert_eq!(sends.len(), 2, "one rejected send, one retry");
            assert_eq!(sends[0].url, RPC);
            assert_eq!(sends[1].url, RPC_VERIFY);
            assert_eq!(
                sends[0].body, sends[1].body,
                "the retry is the identical request"
            );
        });
        assert_eq!(
            public_operation("buy-verify-retry")["status"],
            json!("submitted")
        );
        assert_eq!(
            public_operation("buy-verify-retry")["signature"],
            json!(test_signature_base58())
        );
    }

    #[test]
    fn a_protected_buy_is_sent_to_jito_as_the_same_standard_request() {
        fake_host::install(host_serving_a_buy());
        let response = run_buy("buy-jito", true);
        assert_eq!(
            response,
            DispatchResponse::Write,
            "{}",
            dispatch_message(&response)
        );

        fake_host::with(|host| {
            let sends = host.calls_for("sendTransaction");
            assert_eq!(sends.len(), 1);
            assert_eq!(sends[0].url, JITO);
            assert!(sends[0].body.get("bloom_canary").is_none());
            assert!(!host.rpc_methods().contains(&"bloomPumpfunCanaryStatus"));
        });
    }

    #[test]
    fn a_refused_signature_never_reaches_the_network() {
        let mut host = host_serving_a_buy();
        host.sign_outcome(Err(SdkError::Host(HostStatus::Denied)));
        fake_host::install(host);

        let response = run_buy("buy-denied", false);
        assert!(
            matches!(response, DispatchResponse::Error { code: -2, .. }),
            "a refused signature is a denial: {response:?}"
        );

        fake_host::with(|host| {
            assert!(
                host.calls_for("sendTransaction").is_empty(),
                "nothing may be broadcast when signing was refused"
            );
        });
        assert_eq!(
            public_operation("buy-denied")["status"],
            json!("approval_failed")
        );
        assert_eq!(public_operation("buy-denied")["signature"], Value::Null);
    }

    #[test]
    fn a_pending_approval_records_the_action_and_broadcasts_nothing() {
        let mut host = host_serving_a_buy();
        host.sign_outcome(Ok(SignOutcome::ApprovalPending {
            action_id: "action-42".into(),
            expires_ms: NOW_MS + 600_000,
        }));
        fake_host::install(host);

        let response = run_buy("buy-pending", false);
        let message = dispatch_message(&response);
        assert!(
            message.contains("approval required") && message.contains("action-42"),
            "{message}"
        );

        fake_host::with(|host| {
            assert!(host.calls_for("sendTransaction").is_empty());
            let pending = host
                .secret_json(&sec(&legacy_owner(), SESSION, "buy-pending"))
                .expect("pending operation stored");
            assert_eq!(pending["status"], json!("approval_pending"));
            assert_eq!(pending["approval"], json!("action-42"));
        });
        assert_eq!(
            public_operation("buy-pending")["status"],
            json!("approval_pending")
        );
    }

    fn builder_calls(host: &FakeHost) -> usize {
        host.calls
            .iter()
            .filter(|call| call.url == SWAP_URL)
            .count()
    }

    fn simulation_rejects(host: &mut FakeHost, rejects: bool) {
        let err = if rejects {
            json!({"InstructionError":[0,{"Custom":1}]})
        } else {
            Value::Null
        };
        host.reply_only(
            &format!("{RPC} simulateTransaction"),
            json!({"result":{"value":{"err":err}}}),
        );
    }

    #[test]
    fn an_uncertain_signature_survives_a_failed_preflight() {
        let mut host = host_serving_a_buy();
        host.sign_outcome(Err(SdkError::Host(HostStatus::Backend)));
        fake_host::install(host);
        run_buy("review-uncertain", false);
        assert_eq!(
            public_operation("review-uncertain")["status"],
            json!("signing_uncertain")
        );
        fake_host::with(|host| simulation_rejects(host, true));
        run_buy("review-uncertain", false);
        fake_host::with(|host| simulation_rejects(host, false));
        run_buy("review-uncertain", false);
        fake_host::with(|host| {
            assert_eq!(
                builder_calls(host),
                1,
                "an uncertain signature must never permit a rebuild"
            )
        });
    }

    #[test]
    fn a_legacy_signed_failure_survives_a_later_denial() {
        let mut host = host_serving_a_buy();
        simulation_rejects(&mut host, true);
        fake_host::install(host);
        run_buy("review-legacy", false);
        let key = sec(&legacy_owner(), SESSION, "review-legacy");
        fake_host::with(|host| {
            let mut stored = host.secret_json(&key).unwrap();
            stored["status"] = json!("simulation_failed");
            host.seed_secret(&key, &stored);
            simulation_rejects(host, false);
            host.sign_outcome(Err(SdkError::Host(HostStatus::Denied)));
        });
        run_buy("review-legacy", false);
        run_buy("review-legacy", false);
        fake_host::with(|host| {
            assert_eq!(
                builder_calls(host),
                1,
                "a later denial cannot erase an earlier signed transaction"
            )
        });
    }

    #[test]
    fn an_exact_sweep_retry_preserves_the_approved_message() {
        let mut host = host_serving_a_buy();
        host.reply(
            &format!("{RPC} getBalance"),
            json!({"result":{"value":1_000_000}}),
        );
        host.reply(
            &format!("{RPC} getLatestBlockhash"),
            json!({"result":{"value":{"blockhash":BOND_MINT,"lastValidBlockHeight":1000}}}),
        );
        host.sign_outcome(Ok(SignOutcome::ApprovalPending {
            action_id: "exact-old-message".into(),
            expires_ms: NOW_MS + 60_000,
        }));
        fake_host::install(host);
        let body =
            serde_json::to_vec(&json!({"operationId":"review-sweep","destination":AMM_CREATOR}))
                .unwrap();
        let run = || {
            execute(
                &ctx(&[("bloom.route_id", "ROUTE_SWEEP")]),
                Action::Sweep,
                legacy_owner(),
                SESSION.into(),
                &body,
            )
        };
        assert!(dispatch_message(&run()).contains("approval required"));
        fake_host::with(|host| {
            host.reply_only(
                &format!("{RPC} getLatestBlockhash"),
                json!({"result":{"value":{"blockhash":AMM_MINT,"lastValidBlockHeight":1001}}}),
            );
        });
        run();
        fake_host::with(|host| {
            assert_eq!(host.sign_requests.len(), 2);
            assert_eq!(
                host.sign_requests[1].approval_hint.as_deref(),
                Some("exact-old-message")
            );
            assert!(
                host.sign_requests[0].preimage == host.sign_requests[1].preimage,
                "the same Exact approval hint was attached to a different transaction"
            );
        });
    }

    #[test]
    fn a_failed_simulation_signs_nothing_and_the_same_request_can_be_retried() {
        let mut host = host_serving_a_buy();
        simulation_rejects(&mut host, true);
        fake_host::install(host);

        let first = run_buy("buy-retry", false);
        assert!(
            dispatch_message(&first).contains("simulation failed"),
            "{}",
            dispatch_message(&first)
        );
        fake_host::with(|host| {
            assert!(host.sign_requests.is_empty(), "simulation precedes signing");
            assert!(host.calls_for("sendTransaction").is_empty());
            let simulation = host.calls_for("simulateTransaction")[0]
                .rpc_params()
                .unwrap();
            assert_eq!(simulation[1]["sigVerify"], json!(false));
            let simulated = B64.decode(simulation[0].as_str().unwrap()).unwrap();
            let env = envelope(&simulated).unwrap();
            assert_eq!(
                simulated[env.sig_offset..env.sig_offset + 64],
                [0; 64],
                "only the unsigned transaction reaches the RPC"
            );
        });
        assert_eq!(
            public_operation("buy-retry")["status"],
            json!("preflight_failed")
        );

        // Nothing was signed, so the same operation id and request rebuild
        // and go through once the cluster stops rejecting the transaction.
        fake_host::with(|host| simulation_rejects(host, false));
        let second = run_buy("buy-retry", false);
        assert_eq!(
            second,
            DispatchResponse::Write,
            "{}",
            dispatch_message(&second)
        );
        assert_eq!(public_operation("buy-retry")["status"], json!("submitted"));
        fake_host::with(|host| {
            assert_eq!(builder_calls(host), 2, "the retry rebuilt the transaction");
            assert_eq!(host.sign_requests.len(), 1);
            assert_eq!(host.calls_for("sendTransaction").len(), 1);
        });
    }

    /// Earlier versions signed before simulating, so a stored
    /// `simulation_failed` operation may have a signed transaction on an RPC
    /// that can still land. It must never be rebuilt into a second
    /// executable transaction; a retry may only sign its stored message again.
    #[test]
    fn a_signed_simulation_failure_is_never_rebuilt() {
        let mut host = host_serving_a_buy();
        simulation_rejects(&mut host, true);
        fake_host::install(host);
        run_buy("buy-legacy", false);
        let key = sec(&legacy_owner(), SESSION, "buy-legacy");
        let stored = fake_host::with(|host| {
            let mut stored = host.secret_json(&key).unwrap();
            stored["status"] = json!("simulation_failed");
            host.seed_secret(&key, &stored);
            stored
        });

        let retry = run_buy("buy-legacy", false);
        assert!(dispatch_message(&retry).contains("may already be signed"));
        fake_host::with(|host| {
            assert_eq!(builder_calls(host), 1, "a failed retry does not rebuild");
            assert!(host.sign_requests.is_empty());
            assert_eq!(
                host.secret_json(&key).unwrap()["may_be_signed"],
                json!(true)
            );
        });

        fake_host::with(|host| simulation_rejects(host, false));
        assert_eq!(run_buy("buy-legacy", false), DispatchResponse::Write);
        fake_host::with(|host| {
            assert_eq!(
                builder_calls(host),
                1,
                "a successful retry does not rebuild"
            );
            let raw = B64.decode(stored["tx"].as_str().unwrap()).unwrap();
            assert_eq!(
                host.sign_requests[0].preimage,
                envelope(&raw).unwrap().message,
                "only the stored message is signed"
            );
            assert_eq!(host.calls_for("sendTransaction").len(), 1);
        });
    }

    #[test]
    fn the_same_operation_id_with_changed_economics_is_refused() {
        fake_host::install(host_serving_a_buy());
        assert_eq!(run_buy("buy-bound", false), DispatchResponse::Write);

        let changed = serde_json::to_vec(&json!({
            "operationId":"buy-bound",
            "mint":BOND_MINT,
            "amount":"2000000",
            "minOutputAmount":"1",
            "slippagePct":2,
        }))
        .expect("request serializes");
        let response = execute(
            &ctx(&[("bloom.route_id", "ROUTE_BUY")]),
            Action::Buy,
            legacy_owner(),
            SESSION.into(),
            &changed,
        );
        assert!(
            dispatch_message(&response).contains("operationId already bound"),
            "{}",
            dispatch_message(&response)
        );
        fake_host::with(|host| {
            assert_eq!(
                host.calls_for("sendTransaction").len(),
                1,
                "a changed request under a used id must not produce a second payment"
            );
        });
    }

    #[test]
    fn a_recorded_broadcast_is_never_rebuilt_into_a_second_payment() {
        fake_host::install(host_serving_a_buy());
        assert_eq!(run_buy("buy-once", false), DispatchResponse::Write);

        // Replaying the identical write — the shape a retry after a lost
        // response takes — must reconcile the recorded attempt, not build and
        // sign a second transaction.
        assert_eq!(run_buy("buy-once", false), DispatchResponse::Write);
        assert_eq!(run_buy("buy-once", false), DispatchResponse::Write);

        fake_host::with(|host| {
            assert_eq!(
                host.calls_for("sendTransaction").len(),
                1,
                "one economic intent, one broadcast"
            );
            assert_eq!(
                host.sign_requests.len(),
                1,
                "a settled operation must not be signed again"
            );
        });
    }

    #[test]
    fn signing_asks_for_the_session_key_under_its_reusable_grant() {
        fake_host::install(host_serving_a_buy());
        assert_eq!(run_buy("buy-claim", false), DispatchResponse::Write);

        fake_host::with(|host| {
            let request = host.sign_requests.first().expect("one signing request");
            assert_eq!(request.wallet, WALLET);
            assert_eq!(request.operation_class, "pumpfun.buy");
            assert_eq!(request.signature_algorithm, "ed25519-message");
            assert!(
                matches!(request.selector, SignSelector::Reusable),
                "Pump.fun signs under the session's reusable grant"
            );
            assert!(
                request.key_ref_jcs.is_some(),
                "the scoped session key must be named explicitly"
            );
            let claim: Value =
                serde_json::from_slice(&request.petal_use_claim_jcs).expect("claim is JSON");
            // bloom-rpc-wire RequestNonce is 16 bytes encoded as lowercase
            // hex. A 32-byte digest is valid JSON but the real host rejects it
            // before Broker signing; the recording host alone cannot catch it.
            let nonce = claim["nonce"].as_str().expect("claim nonce is a string");
            assert_eq!(hex::decode(nonce).expect("hex nonce").len(), 16);
            assert_eq!(nonce, nonce.to_ascii_lowercase());
            assert_eq!(claim["operation_class"], json!("pumpfun.buy"));
            assert_eq!(claim["route"], json!("ROUTE_BUY"));
            assert_eq!(claim["package_hash"], json!("pumpfun-test-package"));
            assert!(
                claim["declared_debits"]
                    .as_array()
                    .is_some_and(|debits| !debits.is_empty()),
                "the claim must declare what the transaction spends"
            );
        });
    }

    #[test]
    fn a_session_requires_explicit_positive_asset_budgets() {
        fake_host::install(FakeHost::new(NOW_MS));
        for body in [
            json!({"id":"agent-1"}),
            json!({"id":"agent-1","max_lamports":"0"}),
            json!({"id":"agent-1","max_lamports":"-1"}),
            json!({"id":"agent-1","max_lamports":"18446744073709551616"}),
            json!({"id":"agent-1","max_lamports":"1","token_limits":{"invalid":"1"}}),
            json!({"id":"agent-1","max_lamports":"1","token_limits":{"native":"1"}}),
            json!({"id":"agent-1","max_lamports":"1","token_limits":{USER:"0"}}),
        ] {
            assert_ne!(
                new_session(legacy_owner(), &serde_json::to_vec(&body).unwrap()),
                DispatchResponse::Write
            );
        }
        fake_host::with(|host| assert!(host.key_requests.is_empty()));
    }

    #[test]
    fn a_pending_key_ceremony_creates_no_session_and_no_deadline() {
        let mut host = FakeHost::new(NOW_MS);
        host.derivation(Ok(petal::PetalKeyOutcome::Pending {
            operation_id: "key-op-1".into(),
            scope_digest: "scope-digest-1".into(),
        }));
        fake_host::install(host);

        let response = new_session(
            legacy_owner(),
            br#"{"id":"agent-1","duration_ms":3600000,"max_lamports":"20000000"}"#,
        );
        let message = dispatch_message(&response);
        assert!(
            message.contains("session authority pending")
                && message.contains("key-op-1")
                && message.contains(&session_key_slot(&legacy_owner(), SESSION)),
            "{message}"
        );
        fake_host::with(|host| {
            assert!(
                host.state_json(&sk(&legacy_owner(), SESSION, "session.json"))
                    .is_none(),
                "a session must not exist before its key does"
            );
            assert!(
                host.secret_json(&session_sec(&legacy_owner(), SESSION))
                    .is_none()
            );
            assert_eq!(
                host.key_requests[0]["approval_value_limits"],
                json!([
                    {"asset":{"chain":"solana","asset":"native"},
                     "lifetime":"20000000","rolling_windows":[]}
                ])
            );
            // The SDK's own request type carries the budgets, so the request
            // goes through `sdk::request_key` like any other key request.
            let budgets: Vec<petal::ApprovalValueLimit> =
                serde_json::from_value(host.key_requests[0]["approval_value_limits"].clone())
                    .unwrap();
            assert_eq!(budgets.len(), 1);
        });
    }

    #[test]
    fn a_session_deadline_never_outlasts_the_hosts_key() {
        // The host's key scope starts when its derivation ceremony completes,
        // which is no earlier than the first request. Counting the lifetime
        // from that request never overstates the session's authority.
        let mut host = FakeHost::new(NOW_MS);
        host.derivation(Ok(petal::PetalKeyOutcome::Pending {
            operation_id: "key-op-2".into(),
            scope_digest: "scope-digest-2".into(),
        }));
        host.derivation(Ok(petal::PetalKeyOutcome::Ready {
            operation_id: "key-op-2".into(),
            scope_digest: "scope-digest-2".into(),
            key_ref_jcs: br#"{"public_key_fingerprint":"test-fingerprint"}"#.to_vec(),
            addresses: vec![USER.into()],
        }));
        fake_host::install(host);
        let body = br#"{"id":"agent-1","duration_ms":3600000,"max_lamports":"20000000"}"#;
        assert_ne!(new_session(legacy_owner(), body), DispatchResponse::Write);

        let derive_completed_ms = NOW_MS + 900_000;
        fake_host::with(|host| host.now_ms = derive_completed_ms);
        let response = new_session(legacy_owner(), body);
        assert_eq!(
            response,
            DispatchResponse::Write,
            "{}",
            dispatch_message(&response)
        );

        let stored = fake_host::with(|host| {
            host.state_json(&sk(&legacy_owner(), SESSION, "session.json"))
                .expect("session recorded")
        });
        assert_ne!(
            new_session(
                legacy_owner(),
                br#"{"id":"agent-1","duration_ms":3600000,"max_lamports":"20000001"}"#
            ),
            DispatchResponse::Write,
            "a retry cannot increase the session budget"
        );
        fake_host::with(|host| assert_eq!(host.key_requests.len(), 2));
        assert_eq!(stored["approval_value_limits"][0]["lifetime"], "20000000");
        assert_eq!(stored["address"], json!(USER));
        assert_eq!(stored["created_ms"], json!(derive_completed_ms));
        assert_eq!(
            stored["expires_ms"],
            json!(NOW_MS + 3_600_000),
            "the deadline counts from the first request, not from ceremony completion"
        );
        assert!(
            stored.get("key_ref_jcs").is_none(),
            "the signing reference must stay out of the readable record"
        );
        fake_host::with(|host| {
            assert!(
                host.secret_json(&session_sec(&legacy_owner(), SESSION))
                    .is_some(),
                "the signing reference belongs in the secret namespace"
            );
        });
    }

    /// A policy change makes the host restage an existing session's approval.
    /// Repeating new.json reaches that reconciliation with the same key
    /// request and reports Pending, without replacing the key or resetting
    /// the session's lifetime.
    #[test]
    fn an_existing_session_reconciles_its_authority_without_resetting() {
        let ready = || {
            Ok(petal::PetalKeyOutcome::Ready {
                operation_id: "key-op-3".into(),
                scope_digest: "scope-digest-3".into(),
                key_ref_jcs: br#"{"public_key_fingerprint":"test-fingerprint"}"#.to_vec(),
                addresses: vec![USER.into()],
            })
        };
        let mut host = FakeHost::new(NOW_MS);
        host.derivation(ready());
        host.derivation(Ok(petal::PetalKeyOutcome::Pending {
            operation_id: "key-op-3".into(),
            scope_digest: "scope-digest-3".into(),
        }));
        host.derivation(ready());
        host.derivation(Ok(petal::PetalKeyOutcome::Ready {
            operation_id: "key-op-3".into(),
            scope_digest: "scope-digest-3".into(),
            key_ref_jcs: br#"{"public_key_fingerprint":"another-key"}"#.to_vec(),
            addresses: vec![USER.into()],
        }));
        fake_host::install(host);
        let body = br#"{"id":"agent-1","duration_ms":3600000,"max_lamports":"20000000"}"#;
        assert_eq!(new_session(legacy_owner(), body), DispatchResponse::Write);
        let created = fake_host::with(|host| {
            host.now_ms = NOW_MS + 600_000;
            host.state_json(&sk(&legacy_owner(), SESSION, "session.json"))
                .unwrap()
        });

        let pending = new_session(legacy_owner(), body);
        assert!(dispatch_message(&pending).contains("session authority pending"));
        assert_eq!(new_session(legacy_owner(), body), DispatchResponse::Write);
        assert_ne!(
            new_session(legacy_owner(), body),
            DispatchResponse::Write,
            "a different key for the same session is refused"
        );
        fake_host::with(|host| {
            assert_eq!(host.key_requests.len(), 4);
            assert!(
                host.key_requests
                    .iter()
                    .all(|request| *request == host.key_requests[0])
            );
            assert_eq!(
                host.state_json(&sk(&legacy_owner(), SESSION, "session.json"))
                    .unwrap(),
                created,
                "reconciliation never rewrites the session record"
            );
        });
    }

    /// Which host error classes may rebuild a payment, and which may not.
    ///
    /// The host collapses a whole Broker error registry into these few
    /// classes, so this is the entire contract the retry logic above rests on.
    /// The Machine's `petal_signing_host_error` is the other half: it sends
    /// `denied` only for a Broker failure that can never be retried and left
    /// no durable effect, and `backend` for everything less certain —
    /// `AMBIGUOUS_PROVIDER_EFFECT`, `SERVICE_UNAVAILABLE`,
    /// `OPERATION_ID_CONFLICT`, rate limits, clock faults. If that mapping
    /// ever widens `denied`, this test still passes and the Petal starts
    /// rebuilding payments whose signing outcome is unknown, so the two have
    /// to be changed together.
    #[test]
    fn route_to_host_contract() {
        for (index, (class, expected)) in [
            // The Broker decided against this message. Nothing was signed.
            (HostStatus::Denied, "approval_failed"),
            // The host refused it before the Broker ever saw it.
            (HostStatus::Invalid, "approval_failed"),
            // A fault. The Signer may hold a signature over this message.
            (HostStatus::Backend, "signing_uncertain"),
            (HostStatus::NotFound, "signing_uncertain"),
            (
                HostStatus::BufferTooSmall { needed: 1 },
                "signing_uncertain",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let operation = format!("buy-class-{index}");
            let mut host = host_serving_a_buy();
            host.sign_outcome(Err(SdkError::Host(class.clone())));
            fake_host::install(host);

            let response = run_buy(&operation, false);
            assert!(
                matches!(response, DispatchResponse::Error { .. }),
                "{class:?} did not sign: {response:?}"
            );
            assert_eq!(
                public_operation(&operation)["status"],
                json!(expected),
                "host class {class:?}"
            );
            fake_host::with(|host| {
                assert!(
                    host.calls_for("sendTransaction").is_empty(),
                    "{class:?} must not broadcast"
                );
            });
        }
    }

    /// The exact case the contract above exists for: a Broker outcome that may
    /// already have produced a signature reaches the guest as a backend fault,
    /// and the Petal must keep the message rather than quote a new one.
    #[test]
    fn an_ambiguous_broker_outcome_keeps_the_message_and_the_approval() {
        let mut host = host_serving_a_buy();
        // What the Machine sends for AMBIGUOUS_PROVIDER_EFFECT.
        host.sign_outcome(Err(SdkError::Host(HostStatus::Backend)));
        fake_host::install(host);

        let response = run_buy("buy-ambiguous", false);
        assert!(matches!(response, DispatchResponse::Error { .. }));

        let staged = fake_host::with(|host| {
            assert_eq!(
                host.calls
                    .iter()
                    .filter(|call| call.url == SWAP_URL)
                    .count(),
                1,
                "an unknown outcome must not ask the builder for a fresh quote"
            );
            assert!(host.calls_for("sendTransaction").is_empty());
            host.secret_json(&sec(&legacy_owner(), SESSION, "buy-ambiguous"))
                .expect("pending operation stored")
        });
        assert_eq!(staged["status"], json!("signing_uncertain"));
        assert_eq!(
            public_operation("buy-ambiguous")["status"],
            json!("signing_uncertain")
        );
    }

    #[test]
    fn a_lost_signing_response_is_recorded_as_uncertain_not_as_a_refusal() {
        let mut host = host_serving_a_buy();
        // The Signer may or may not have signed; the answer never came back.
        host.sign_outcome(Err(SdkError::Host(HostStatus::Backend)));
        fake_host::install(host);

        let response = run_buy("buy-lost", false);
        let message = dispatch_message(&response);
        assert!(
            message.contains("may already have produced a signature"),
            "an unknown signing outcome must be reported as unknown: {message}"
        );

        fake_host::with(|host| {
            assert!(host.calls_for("sendTransaction").is_empty());
            assert_eq!(host.sign_requests.len(), 1);
        });
        assert_eq!(
            public_operation("buy-lost")["status"],
            json!("signing_uncertain"),
            "an unknown outcome must not be published as a refusal"
        );
    }

    #[test]
    fn retrying_an_uncertain_signature_reuses_the_same_message_and_approval() {
        let mut host = host_serving_a_buy();
        host.sign_outcome(Err(SdkError::Host(HostStatus::Backend)));
        fake_host::install(host);

        assert!(matches!(
            run_buy("buy-recover", false),
            DispatchResponse::Error { .. }
        ));
        let staged = fake_host::with(|host| {
            host.secret_json(&sec(&legacy_owner(), SESSION, "buy-recover"))
                .expect("pending operation stored")
        });

        // Restart shape: the same request under the same operation id.
        let response = run_buy("buy-recover", false);
        assert_eq!(
            response,
            DispatchResponse::Write,
            "{}",
            dispatch_message(&response)
        );

        fake_host::with(|host| {
            assert_eq!(host.sign_requests.len(), 2, "the retry re-enters signing");
            let (first, second) = (&host.sign_requests[0], &host.sign_requests[1]);
            assert_eq!(
                first.preimage, second.preimage,
                "the retry must ask for a signature over the same message, not a new payment"
            );
            assert_eq!(first.claimed_hash, second.claimed_hash);
            assert_eq!(first.petal_use_claim_jcs, second.petal_use_claim_jcs);
            assert_eq!(
                host.calls
                    .iter()
                    .filter(|call| call.url == SWAP_URL)
                    .count(),
                1,
                "the builder must not be asked to quote a second transaction"
            );
            assert_eq!(host.calls_for("sendTransaction").len(), 1);
        });

        let settled = fake_host::with(|host| {
            host.secret_json(&sec(&legacy_owner(), SESSION, "buy-recover"))
                .expect("pending operation stored")
        });
        assert_eq!(
            staged["digest"], settled["digest"],
            "the economic intent is unchanged across the recovery"
        );
        assert_eq!(staged["message_sha256"], settled["message_sha256"]);
        assert_eq!(
            public_operation("buy-recover")["status"],
            json!("submitted")
        );
    }

    #[test]
    fn a_definite_refusal_starts_a_fresh_approval_for_the_same_intent() {
        let mut host = host_serving_a_buy();
        host.sign_outcome(Err(SdkError::Host(HostStatus::Denied)));
        fake_host::install(host);

        assert!(matches!(
            run_buy("buy-refused", false),
            DispatchResponse::Error { code: -2, .. }
        ));
        let refused = fake_host::with(|host| {
            host.secret_json(&sec(&legacy_owner(), SESSION, "buy-refused"))
                .expect("pending operation stored")
        });
        assert_eq!(refused["approval"], Value::Null, "the hint is dropped");

        let response = run_buy("buy-refused", false);
        assert_eq!(
            response,
            DispatchResponse::Write,
            "{}",
            dispatch_message(&response)
        );
        let settled = fake_host::with(|host| {
            host.secret_json(&sec(&legacy_owner(), SESSION, "buy-refused"))
                .expect("pending operation stored")
        });
        assert_eq!(
            refused["digest"], settled["digest"],
            "a refusal does not change the economic intent that is retried"
        );
        fake_host::with(|host| {
            assert!(
                host.sign_requests[1].approval_hint.is_none(),
                "a refused operation asks for a new approval, not the dead one"
            );
        });
    }

    #[test]
    fn a_crash_before_the_durable_broadcast_record_never_broadcasts() {
        let mut host = host_serving_a_buy();
        // Let the writes that stage the operation and record the signing
        // attempt land, then fail the write that records the broadcast
        // attempt. The send must not happen.
        host.fail_store_after = Some(3);
        fake_host::install(host);

        let response = run_buy("buy-crash", false);
        assert!(
            matches!(response, DispatchResponse::Error { .. }),
            "a store failure must surface, not be swallowed: {response:?}"
        );
        fake_host::with(|host| {
            assert_eq!(host.sign_requests.len(), 1, "the signature was produced");
            assert!(
                host.calls_for("sendTransaction").is_empty(),
                "a broadcast may not precede its durable record"
            );
            host.fail_store_after = None;
        });

        // The signature exists but was never recorded; only the `signing`
        // marker survived. The retry must sign the same message, not rebuild.
        assert_eq!(run_buy("buy-crash", false), DispatchResponse::Write);
        fake_host::with(|host| {
            assert_eq!(builder_calls(host), 1);
            assert_eq!(
                host.sign_requests[0].preimage,
                host.sign_requests[1].preimage
            );
            assert_eq!(host.calls_for("sendTransaction").len(), 1);
        });
    }

    /// A signing call can outlive its process. When a signature comes back
    /// for an operation that was waiting on its approval and nothing after it
    /// is recorded, the retry must not refresh the transaction as if the
    /// approval were still pending.
    #[test]
    fn a_signature_interrupted_after_an_approval_wait_is_never_rebuilt() {
        let mut host = host_serving_a_buy();
        host.sign_outcome(Ok(SignOutcome::ApprovalPending {
            action_id: "session-approval".into(),
            expires_ms: NOW_MS + 60_000,
        }));
        fake_host::install(host);
        assert!(dispatch_message(&run_buy("buy-interrupted", false)).contains("approval required"));

        // Refresh, publish, and the signing marker land; the broadcast record does not.
        fake_host::with(|host| host.fail_store_after = Some(host.puts + 3));
        assert!(matches!(
            run_buy("buy-interrupted", false),
            DispatchResponse::Error { .. }
        ));
        fake_host::with(|host| {
            assert_eq!(host.sign_requests.len(), 2);
            assert!(host.calls_for("sendTransaction").is_empty());
            host.fail_store_after = None;
        });

        assert_eq!(run_buy("buy-interrupted", false), DispatchResponse::Write);
        fake_host::with(|host| {
            assert_eq!(
                builder_calls(host),
                2,
                "the interrupted signature is not rebuilt"
            );
            assert_eq!(
                host.sign_requests[1].preimage,
                host.sign_requests[2].preimage
            );
            assert_eq!(host.calls_for("sendTransaction").len(), 1);
        });
    }

    /// Blockhash expiry settles only an unsigned transaction. A sweep that may
    /// already be signed could have landed before its blockhash expired, so
    /// neither a failed simulation nor expiry makes it rebuildable.
    #[test]
    fn expiry_never_makes_a_possibly_signed_sweep_rebuildable() {
        let mut host = host_serving_a_buy();
        host.reply(
            &format!("{RPC} getBalance"),
            json!({"result":{"value":1_000_000}}),
        );
        host.reply(
            &format!("{RPC} getLatestBlockhash"),
            json!({"result":{"value":{"blockhash":BOND_MINT,"lastValidBlockHeight":1000}}}),
        );
        host.reply(&format!("{RPC} getBlockHeight"), json!({"result": 5000}));
        host.sign_outcome(Err(SdkError::Host(HostStatus::Backend)));
        host.sign_outcome(Err(SdkError::Host(HostStatus::Denied)));
        fake_host::install(host);
        let body =
            serde_json::to_vec(&json!({"operationId":"sweep-uncertain","destination":AMM_CREATOR}))
                .unwrap();
        let run = || {
            execute(
                &ctx(&[("bloom.route_id", "ROUTE_SWEEP")]),
                Action::Sweep,
                legacy_owner(),
                SESSION.into(),
                &body,
            )
        };
        assert!(dispatch_message(&run()).contains("may already have produced a signature"));
        fake_host::with(|host| simulation_rejects(host, true));
        assert!(dispatch_message(&run()).contains("may already be signed"));
        fake_host::with(|host| simulation_rejects(host, false));
        run();
        run();
        fake_host::with(|host| {
            assert_eq!(
                host.calls_for("getLatestBlockhash").len(),
                1,
                "never rebuilt"
            );
            assert!(
                host.sign_requests
                    .windows(2)
                    .all(|pair| pair[0].preimage == pair[1].preimage)
            );
        });
    }

    /// An Exact approval is never carried onto new bytes, and a failed
    /// simulation is not proof that its transaction can no longer land. The
    /// approval is kept until the finalized block height passes the
    /// transaction's last valid height; only then does a retry rebuild and
    /// ask for a new approval.
    #[test]
    fn an_exact_sweep_gives_up_its_approval_only_after_its_blockhash_expires() {
        let mut host = host_serving_a_buy();
        host.reply(
            &format!("{RPC} getBalance"),
            json!({"result":{"value":1_000_000}}),
        );
        host.reply(
            &format!("{RPC} getLatestBlockhash"),
            json!({"result":{"value":{"blockhash":BOND_MINT,"lastValidBlockHeight":1000}}}),
        );
        host.sign_outcome(Ok(SignOutcome::ApprovalPending {
            action_id: "exact-pending".into(),
            expires_ms: NOW_MS + 60_000,
        }));
        host.sign_outcome(Ok(SignOutcome::ApprovalPending {
            action_id: "exact-pending".into(),
            expires_ms: NOW_MS + 60_000,
        }));
        fake_host::install(host);
        let body =
            serde_json::to_vec(&json!({"operationId":"sweep-slow","destination":AMM_CREATOR}))
                .unwrap();
        let run = || {
            execute(
                &ctx(&[("bloom.route_id", "ROUTE_SWEEP")]),
                Action::Sweep,
                legacy_owner(),
                SESSION.into(),
                &body,
            )
        };
        let block_height = |height: u64| {
            fake_host::with(|host| {
                host.reply_only(&format!("{RPC} getBlockHeight"), json!({"result": height}));
            });
        };
        assert!(dispatch_message(&run()).contains("approval required"));

        // A state-dependent failure while the blockhash is still valid keeps
        // the approval and the exact bytes it binds.
        fake_host::with(|host| simulation_rejects(host, true));
        block_height(1000);
        assert!(dispatch_message(&run()).contains("kept until its blockhash expires"));
        fake_host::with(|host| simulation_rejects(host, false));
        assert!(dispatch_message(&run()).contains("approval required"));
        fake_host::with(|host| {
            assert_eq!(host.sign_requests.len(), 2);
            assert_eq!(
                host.sign_requests[0].preimage,
                host.sign_requests[1].preimage
            );
            assert_eq!(
                host.sign_requests[1].approval_hint.as_deref(),
                Some("exact-pending")
            );
        });

        // Once the finalized height passes the last valid height, the bytes
        // can never land: the approval is dropped and the retry rebuilds.
        fake_host::with(|host| simulation_rejects(host, true));
        block_height(1001);
        assert!(dispatch_message(&run()).contains("simulation failed"));
        assert_eq!(
            public_operation("sweep-slow")["status"],
            json!("preflight_failed")
        );
        fake_host::with(|host| {
            simulation_rejects(host, false);
            host.reply_only(
                &format!("{RPC} getLatestBlockhash"),
                json!({"result":{"value":{"blockhash":AMM_MINT,"lastValidBlockHeight":1200}}}),
            );
        });
        run();
        fake_host::with(|host| {
            assert_eq!(host.sign_requests.len(), 3);
            assert_ne!(
                host.sign_requests[1].preimage,
                host.sign_requests[2].preimage
            );
            assert_eq!(
                host.sign_requests[2].approval_hint, None,
                "a rebuilt Exact payload needs its own approval"
            );
        });
    }

    #[test]
    fn a_submitted_operation_polls_to_a_definite_chain_outcome() {
        fake_host::install(host_serving_a_buy());
        assert_eq!(run_buy("buy-poll", false), DispatchResponse::Write);

        // A lost status response leaves the recorded attempt alone.
        fake_host::with(|host| {
            host.reply(
                &format!("{RPC} getSignatureStatuses"),
                json!({"error":{"code":-32000,"message":"node behind"}}),
            );
        });
        let _ = read_operation(&legacy_owner(), SESSION, "buy-poll");
        assert_eq!(
            public_operation("buy-poll")["status"],
            json!("submitted"),
            "a lost status response cannot unwind a recorded submission"
        );

        fake_host::with(|host| {
            host.reply_only(
                &format!("{RPC} getSignatureStatuses"),
                json!({"result":{"value":[{"err":null,"confirmationStatus":"finalized"}]}}),
            );
        });
        let _ = read_operation(&legacy_owner(), SESSION, "buy-poll");
        assert_eq!(public_operation("buy-poll")["status"], json!("finalized"));

        fake_host::with(|host| {
            assert_eq!(
                host.calls_for("sendTransaction").len(),
                1,
                "polling never re-broadcasts"
            );
        });
    }

    #[test]
    fn an_expired_session_cannot_sign_or_broadcast() {
        let mut host = host_serving_a_buy();
        let mut expired = live_session();
        expired.expires_ms = NOW_MS - 1;
        host.seed_state(&sk(&legacy_owner(), SESSION, "session.json"), &expired);
        fake_host::install(host);

        let response = run_buy("buy-expired", false);
        assert!(
            matches!(response, DispatchResponse::Error { code: -2, .. }),
            "{response:?}"
        );
        fake_host::with(|host| {
            assert!(host.sign_requests.is_empty());
            assert!(host.calls_for("sendTransaction").is_empty());
        });
    }

    #[test]
    fn preflight_reports_what_it_cannot_check_separately_from_what_failed() {
        let mut host = FakeHost::new(NOW_MS);
        host.seed_state(
            &sk(&legacy_owner(), SESSION, "session.json"),
            &live_session(),
        );
        host.reply(
            &format!("{RPC_VERIFY} getGenesisHash"),
            json!({ "result": MAINNET_BETA_GENESIS_BASE58 }),
        );
        host.reply(PROBE_URL, json!({"statusCode":400,"message":"invalid"}));
        fake_host::install(host);

        let response = preflight(
            &ctx(&[("wallet", WALLET), ("session", SESSION)]),
            WALLET.into(),
        );
        let DispatchResponse::Read(body) = response else {
            panic!("preflight is a read: {response:?}");
        };
        let body: Value = serde_json::from_slice(&body).expect("preflight body is JSON");

        assert_eq!(
            body["blockers"],
            json!([]),
            "every check the Petal actually ran passed"
        );
        assert_eq!(body["ok"], json!(true));

        let operator_checks = body["operator_checks"]
            .as_array()
            .expect("operator_checks array");
        let names: Vec<&str> = operator_checks
            .iter()
            .filter_map(|check| check["operator_check"].as_str())
            .collect();
        assert!(
            names.contains(&"wallet_policy_lists_session_address"),
            "the unverifiable wallet-policy fact is an operator check, not a blocker: {names:?}"
        );
        assert!(names.contains(&"signing_scope_deadline_is_host_side"));
        assert!(
            names.contains(&"wallet_policy_lists_cycle_destinations"),
            "the exit and the protocol programs need policy entries too, not just funding: {names:?}"
        );
        let destinations = operator_checks
            .iter()
            .find(|check| {
                check["operator_check"] == json!("wallet_policy_lists_cycle_destinations")
            })
            .expect("the destination check");
        for program in &PROGRAMS[5..] {
            assert!(
                destinations["required_for_trading"]
                    .as_array()
                    .expect("program list")
                    .contains(&json!(program)),
                "{program} is declared by a write and must be named"
            );
        }
        assert_eq!(
            operator_checks[0]["session_address"],
            json!(USER),
            "the operator is told exactly which address to look for"
        );

        fake_host::with(|host| {
            assert!(
                !host.rpc_methods().contains(&"bloomPumpfunCanaryStatus"),
                "preflight must not probe for a removed host method: {:?}",
                host.rpc_methods()
            );
        });
    }

    #[test]
    fn preflight_still_fails_closed_on_the_facts_it_can_check() {
        let mut host = FakeHost::new(NOW_MS);
        host.reply(
            &format!("{RPC_VERIFY} getGenesisHash"),
            json!({"result":"4ufDAAhSoL5kzi9QRyKscye3wV3RGQ9VQjm7jZyVu1pV"}),
        );
        host.reply(PROBE_URL, json!({"statusCode":400}));
        fake_host::install(host);

        let response = preflight(&ctx(&[("wallet", WALLET)]), WALLET.into());
        let DispatchResponse::Read(body) = response else {
            panic!("preflight is a read: {response:?}");
        };
        let body: Value = serde_json::from_slice(&body).expect("preflight body is JSON");
        assert_eq!(body["ok"], json!(false));
        assert_eq!(
            body["blockers"][0]["blocker"],
            json!("rpc_genesis_mismatch")
        );
    }

    #[test]
    fn preflight_labels_a_bad_session_scope_as_a_scope_blocker() {
        let mut host = FakeHost::new(NOW_MS);
        host.reply(
            &format!("{RPC_VERIFY} getGenesisHash"),
            json!({ "result": MAINNET_BETA_GENESIS_BASE58 }),
        );
        host.reply(PROBE_URL, json!({"statusCode":200}));
        fake_host::install(host);

        let response = preflight(
            &ctx(&[
                ("wallet", WALLET),
                ("session", SESSION),
                ("bloom.wallet", "other"),
                ("bloom.account", "1"),
            ]),
            WALLET.into(),
        );
        let DispatchResponse::Read(body) = response else {
            panic!("preflight is a read: {response:?}");
        };
        let body: Value = serde_json::from_slice(&body).expect("preflight body is JSON");
        assert_eq!(
            body["blockers"],
            json!([{
                "blocker": "session_scope_invalid",
                "session": SESSION,
                "detail": format!("session wallet {WALLET:?} is not the mounted wallet {:?}", "other")
            }]),
            "a dispatch naming another wallet's tree is a scope mistake, not a store failure"
        );
    }

    #[test]
    fn preflight_genesis_constant_is_canonical_mainnet_beta() {
        // The preflight path compares the configured RPC's live genesis
        // against this constant; a wrong constant means every preflight
        // misclassifies the broadcast target.
        assert_eq!(
            MAINNET_BETA_GENESIS_BASE58,
            "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
        );
    }

    #[test]
    fn builder_probe_accepts_only_success_or_validation_responses() {
        for status in [200, 204, 299, 400, 422] {
            assert!(builder_probe_status_reachable(status), "{status}");
        }
        for status in [300, 401, 403, 404, 429, 500, 503] {
            assert!(!builder_probe_status_reachable(status), "{status}");
        }
    }
}
