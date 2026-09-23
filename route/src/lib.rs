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
use std::collections::BTreeSet;

const MAX: usize = 131072;
const MAX_TX: usize = 1232;
const MAX_PRIORITY_FEE_LAMPORTS: u64 = 5_000_000;
const ATA_RENT_ALLOWANCE_LAMPORTS: u64 = 2_100_000;
const BUILD: &str = "https://fun-block.pump.fun";
const COINS: &str = "https://frontend-api-v3.pump.fun/coins-v2";
const RPC: &str = "https://rpc.solanatracker.io/public";
const RPC_VERIFY: &str = "https://api.mainnet-beta.solana.com";
const JITO: &str = "https://mainnet.block-engine.jito.wtf/api/v1/transactions";
const SOL: &str = "So11111111111111111111111111111111111111112";
#[cfg(not(test))]
const ADDRESS_LOOKUP_TABLE_PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";
const CLASSES: [&str; 3] = ["pumpfun.buy", "pumpfun.sell", "pumpfun.close_token_account"];
/// Every program a supported transaction may call. Coin creation, fee
/// collection and fee sharing were removed with their routes, and their
/// programs went with them: `pfeeUxB6…` (fee sharing) and `AgenTMiC…`
/// (tokenized agent) are no longer reachable from any instruction this Petal
/// will sign.
const PROGRAMS: [&str; 7] = [
    "ComputeBudget111111111111111111111111111111",
    "11111111111111111111111111111111",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
    "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
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
    use petal::{HttpRequest, HttpResponse, PayloadSignRequest, SdkError, SignOutcome};

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
    pub fn sign_payload(request: &PayloadSignRequest) -> Result<SignOutcome, SdkError> {
        petal::sdk::sign_payload(request)
    }
    /// The trader's public Solana address, read from the account's own public
    /// wallet view. This is a public read of host-owned metadata, not a key
    /// request: the Petal never derives, names, or holds a key.
    #[cfg(not(test))]
    pub fn vfs_read(path: &str, max_bytes: usize) -> Result<Vec<u8>, SdkError> {
        petal::sdk::vfs_read(path, max_bytes)
    }
    #[cfg(not(test))]
    pub fn now_ms() -> u64 {
        petal::sdk::now_ms()
    }

    #[cfg(test)]
    pub use crate::fake_host::{
        http, now_ms, sign_payload, store_get, store_get_secret, store_list, store_put,
        store_put_new, vfs_read,
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
/// Which Bloom account trades: the wallet from the route path and the account
/// number the host injected. Both halves identify the signing key, so both
/// scope the operation records — two accounts of one wallet never share an
/// operation id.
///
/// `bloom.wallet` and `bloom.account` are host-supplied route parameters
/// (`petal::route_param`), never path segments, so a guest cannot forge them
/// by naming a directory. When the host injects no account the number is 0,
/// which is the account Bloom resolves for a root-mounted Petal.
#[derive(Clone, Debug, PartialEq)]
pub struct TradeOwner {
    wallet: String,
    account: u32,
}

impl TradeOwner {
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
                "route wallet {wallet:?} is not the mounted wallet {mounted:?}"
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

    /// The account's public Solana address. It is read from
    /// `wallets/<w>/<n>/address.sol`, which Bloom renders from the same
    /// Broker projection its Exact signing path resolves
    /// `m/44'/501'/<n>'/0'` from, so the address handed to the builder and
    /// the key the host signs with are the same account by construction.
    fn address(&self) -> Result<String, DispatchResponse> {
        let path = format!("wallets/{}/{}/address.sol", self.wallet, self.account);
        let bytes = host::vfs_read(&path, 128).map_err(|error| {
            fail(format!(
                "account {} of wallet {} has no readable Solana address: {}",
                self.account,
                self.wallet,
                sdk_message(&error)
            ))
        })?;
        let address = std::str::from_utf8(&bytes)
            .map_err(|_| fail("account Solana address is not UTF-8"))?
            .trim()
            .to_owned();
        pk(&address)
            .map_err(|error| fail(format!("account Solana address is unusable: {error}")))?;
        Ok(address)
    }
}

/// The operation record root for one account of one wallet, under both the
/// public and secret namespaces. Records written by the removed session
/// routes live under `sessions/` and `account-sessions/` and are left where
/// they are; nothing here reads or writes them.
fn trades_prefix(owner: &TradeOwner) -> String {
    format!("trades/{}/{}/", owner.account, owner.wallet)
}
fn account_number(c: &Ctx) -> Result<u32, DispatchResponse> {
    petal::route_param(c, "bloom.account")
        .map_or(Ok(0), |raw| raw.parse::<u32>())
        .map_err(|error| bad(format!("bloom.account must be a u32: {error}")))
}
fn public_key(owner: &TradeOwner, o: &str) -> String {
    format!("state/{}operations/{o}.json", trades_prefix(owner))
}
fn secret_key(owner: &TradeOwner, o: &str) -> String {
    format!("{}operations/{o}.json", trades_prefix(owner))
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

#[derive(Clone, Copy)]
pub enum Action {
    Buy,
    Sell,
    CloseTokenAccount,
}
impl Action {
    fn class(self) -> &'static str {
        match self {
            Self::Buy => CLASSES[0],
            Self::Sell => CLASSES[1],
            Self::CloseTokenAccount => CLASSES[2],
        }
    }
    fn path(self) -> &'static str {
        match self {
            Self::Buy | Self::Sell => "/agents/swap",
            Self::CloseTokenAccount => "",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Buy => "Buy",
            Self::Sell => "Sell",
            Self::CloseTokenAccount => "Close token account",
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
    /// The approval this operation gave up when it rebuilt. Bloom takes it as
    /// the hint on the next signing call: a wallet holds one live ceremony, so
    /// without it the abandoned ceremony blocks the rebuilt transaction until
    /// it expires on its own.
    #[serde(default)]
    superseded: Option<String>,
    /// Set once any signing call for this message may have produced a
    /// signature, and never cleared: a later refusal or failed simulation
    /// says nothing about an earlier call. While set, the operation keeps
    /// its message and can only sign that message again.
    #[serde(default)]
    may_be_signed: bool,
    /// The review the owner is shown, frozen with the bytes it describes.
    /// Every fact in it is read out of the parsed transaction that was just
    /// validated, so it cannot drift from what signing will produce; the host
    /// hashes it into the approval's canonical facts, so changing it cannot
    /// reuse an approval prepared for the old text.
    #[serde(default)]
    review: Vec<String>,
    /// The last block height at which the built transaction can still land,
    /// as the RPC reported it when the blockhash was read. Only close builds
    /// it locally; a builder-supplied swap has no such figure and stores 0.
    #[serde(default)]
    last_valid_block_height: u64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Public {
    schema: String,
    action: String,
    status: String,
    signature: Option<String>,
    api: Value,
    message_sha256: String,
    review: Vec<String>,
    updated_ms: u64,
}

fn build_pending(
    a: Action,
    trader: &Trader<'_>,
    request: &Map<String, Value>,
    digest: String,
) -> Result<Pending, DispatchResponse> {
    let user = trader.address;
    if matches!(a, Action::CloseTokenAccount) {
        return build_close_token_account_pending(trader, request, digest);
    }
    let mut builder_request = request.clone();
    builder_request.remove("minOutputAmount");
    let response = post(
        &format!("{BUILD}{}", a.path()),
        &Value::Object(builder_request),
    )?;
    let tx = response
        .get("transaction")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("builder omitted transaction"))?
        .to_owned();
    let parsed = validate_tx(&tx, user, a, request, &response)?;
    let raw = B64
        .decode(&tx)
        .map_err(|_| fail("builder transaction is not base64"))?;
    let message_sha256 = hex::encode(Sha256::digest(
        envelope(&raw)
            .map_err(|error| fail(format!("unsafe builder transaction: {error}")))?
            .message,
    ));
    let network_fee_lamports = transaction_fee(&tx, request)?;
    let mint = match a {
        Action::Buy => request.get("outputMint"),
        _ => request.get("inputMint"),
    }
    .and_then(Value::as_str)
    .ok_or_else(|| fail("normalized swap mint missing"))?;
    let review = swap_review(
        trader,
        a,
        request,
        &parsed,
        network_fee_lamports,
        verified_mint_decimals(mint),
    )
    .map_err(|error| fail(format!("cannot describe the built transaction: {error}")))?;
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
        superseded: None,
        may_be_signed: false,
        review,
        last_valid_block_height: 0,
    })
}

/// SOL has nine decimals. Anything else is presented in raw units with its
/// mint spelled out, because the only decimals the Petal could quote for a
/// Pump.fun token come from the same upstream that built the transaction.
fn lamports_display(lamports: u64) -> String {
    let whole = lamports / 1_000_000_000;
    let fraction = format!("{:09}", lamports % 1_000_000_000);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{whole} SOL")
    } else {
        format!("{whole}.{fraction} SOL")
    }
}
/// A token amount. With a scale two independent RPCs agree on, this is a
/// figure a person can compare against a price; without one it stays in raw
/// units and says so. The mint is always spelled out and its name and symbol
/// never are: those are metadata the coin's creator chooses, and a review that
/// repeated them would be quoting the counterparty.
fn token_display(amount: u64, mint: &str, decimals: Option<u8>) -> String {
    let Some(decimals) = decimals else {
        return format!("{amount} raw units of {mint} (scale unverified)");
    };
    let scale = 10_u64.pow(u32::from(decimals));
    let whole = amount / scale;
    let fraction = format!("{:0width$}", amount % scale, width = usize::from(decimals));
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{whole} of {mint}")
    } else {
        format!("{whole}.{fraction} of {mint}")
    }
}

/// The mint's decimal scale, taken only when two independent RPCs agree. Any
/// disagreement, absence or implausible value yields `None`, and the amount is
/// then shown in raw units rather than at a scale that might be wrong: a
/// misplaced decimal point is worse than an ugly number.
fn verified_mint_decimals(mint: &str) -> Option<u8> {
    let read = |url: &str| -> Option<u8> {
        let value = post(
            url,
            &rpc(
                "getAccountInfo",
                json!([mint, {"encoding":"jsonParsed","commitment":"finalized"}]),
            ),
        )
        .ok()?;
        let account = value.pointer("/result/value")?;
        let owner = account.get("owner").and_then(Value::as_str)?;
        if owner != PROGRAMS[3] && owner != PROGRAMS[4] {
            return None;
        }
        let parsed = account.pointer("/data/parsed")?;
        if parsed.get("type").and_then(Value::as_str) != Some("mint") {
            return None;
        }
        u8::try_from(parsed.pointer("/info/decimals").and_then(Value::as_u64)?)
            .ok()
            .filter(|decimals| *decimals <= 18)
    };
    let primary = read(RPC)?;
    (primary == read(RPC_VERIFY)?).then_some(primary)
}

/// Who the transaction spends from, named both the way the owner selected it
/// in Bloom and the way the chain names it. An address alone does not tell the
/// owner which of their accounts is about to pay.
struct Trader<'a> {
    wallet: &'a str,
    account: u32,
    address: &'a str,
}

impl Trader<'_> {
    fn line(&self) -> String {
        format!(
            "Trading account: Bloom wallet \"{}\" account {} ({})",
            self.wallet, self.account, self.address
        )
    }
}

/// The input ceiling and guaranteed output floor the swap instruction itself
/// carries. These are the numbers the program enforces, not the builder's
/// quote: a buy cannot spend more than the first, and a sell cannot receive
/// less than the second, or the transaction fails on chain.
fn swap_instruction_amounts(message: &Msg, action: Action) -> Result<(u64, u64), String> {
    let pump = pk(PROGRAMS[5])?;
    let amm = pk(PROGRAMS[6])?;
    let discriminator = match action {
        Action::Buy => IX_BUY,
        Action::Sell => IX_SELL,
        Action::CloseTokenAccount => return Err("close has no swap instruction".into()),
    };
    let swap = message
        .instructions
        .iter()
        .find(|ix| {
            message
                .keys
                .get(ix.program)
                .is_some_and(|program| program == &pump || program == &amm)
                && has_discriminator(ix, discriminator)
        })
        .ok_or("validated swap instruction missing")?;
    match action {
        Action::Buy => Ok((instruction_u64(swap, 16)?, instruction_u64(swap, 8)?)),
        _ => Ok((instruction_u64(swap, 8)?, instruction_u64(swap, 16)?)),
    }
}

/// What the owner is asked to approve, in the units the program enforces.
/// Every figure is read back out of the transaction that was just validated,
/// so the review and the bytes cannot disagree.
fn swap_review(
    trader: &Trader<'_>,
    action: Action,
    request: &Map<String, Value>,
    message: &Msg,
    network_fee_lamports: u64,
    decimals: Option<u8>,
) -> Result<Vec<String>, String> {
    let (input, minimum_output) = swap_instruction_amounts(message, action)?;
    let mint = match action {
        Action::Buy => request.get("outputMint"),
        _ => request.get("inputMint"),
    }
    .and_then(Value::as_str)
    .ok_or("normalized swap mint missing")?;
    let tip = tip_lamports(request).map_err(|_| "invalid normalized tipAmount")?;
    let associated = pk(PROGRAMS[2])?;
    let ata_count = message
        .instructions
        .iter()
        .filter(|ix| message.keys.get(ix.program) == Some(&associated))
        .count() as u64;
    let account_rent = ata_count
        .checked_mul(ATA_RENT_ALLOWANCE_LAMPORTS)
        .ok_or("account rent allowance exceeds u64")?;
    // A Pump buy names a token amount and a ceiling on the SOL in, and only
    // the ceiling moves with slippage. So the spend is the figure that can
    // move against the owner between approving and landing, and the one they
    // are here to bound. A sell is the other way round: it names the tokens
    // that leave and a floor under the SOL that returns. Every line is read
    // out of the instruction, and none asserts anything about the program
    // beyond the field it names — in particular a buy's token amount is the
    // amount the instruction names, not a promise of delivery.
    let (assets, amounts, fee_note) = match action {
        Action::Buy => (
            [
                "Paying with: SOL".to_owned(),
                format!("Buying token: {mint}"),
            ],
            [
                format!(
                    "Maximum spent on the trade: {} (the pool sets the real cost, up to this)",
                    lamports_display(input)
                ),
                format!(
                    "Tokens the instruction names: {}",
                    token_display(minimum_output, mint, decimals)
                ),
            ],
            "Pump's own trading fee comes out of that maximum, not on top of it",
        ),
        _ => (
            [
                format!("Selling token: {mint}"),
                "Receiving: SOL".to_owned(),
            ],
            [
                format!("Sold: {}", token_display(input, mint, decimals)),
                format!(
                    "Least SOL this may return: {}",
                    lamports_display(minimum_output)
                ),
            ],
            "Pump's own trading fee is already taken out of that minimum",
        ),
    };
    let mut review = vec![format!("{} on Pump.fun", action.label()), trader.line()];
    review.extend(assets);
    review.extend(amounts);
    review.push(fee_note.to_owned());
    review.push(format!(
        "Estimated network fee: {} (a cap, charged as used)",
        lamports_display(network_fee_lamports)
    ));
    if account_rent > 0 {
        review.push(format!(
            "Rent for {ata_count} new token account(s), up to {}; recoverable by closing them while empty",
            lamports_display(account_rent)
        ));
    }
    if tip > 0 {
        review.push(format!(
            "Front-running protection tip: {}",
            lamports_display(tip)
        ));
    }
    // Both sides end with the whole SOL bound, because both have one. A sell
    // spends no SOL on the trade itself, but its fee and any new token account
    // are still real money leaving the account, and a review that totalled
    // only buys would leave the owner to add those up.
    let overhead = tip
        .checked_add(account_rent)
        .and_then(|value| value.checked_add(network_fee_lamports))
        .ok_or("native cost exceeds u64")?;
    review.push(if matches!(action, Action::Buy) {
        let total = input
            .checked_add(overhead)
            .ok_or("total native cost exceeds u64")?;
        format!("Most this can cost in total: {}", lamports_display(total))
    } else {
        format!(
            "Most this can cost in SOL: {} (fee, tip and rent; the trade itself returns SOL)",
            lamports_display(overhead)
        )
    });
    Ok(review)
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

/// A v0 message with exactly three keys: the trading account (signer, and the
/// rent destination), the token account being closed, and the token program.
/// The rent destination is not a parameter — it is key 0, the account that
/// owns the token account and signs — so there is nowhere for the reclaimed
/// rent to go but back.
fn close_token_account_message(
    user: &str,
    token_account: &str,
    token_program: &str,
    blockhash: &str,
) -> Result<Vec<u8>, DispatchResponse> {
    let keys = [user, token_account, token_program]
        .map(pk)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    let blockhash = pk(blockhash).map_err(|_| fail("Solana RPC returned an invalid blockhash"))?;
    let mut message = vec![0x80, 1, 0, 1, 3];
    for key in keys {
        message.extend_from_slice(&key);
    }
    message.extend_from_slice(&blockhash);
    // One CloseAccount through key 2, over accounts [token account,
    // destination, authority] = [1, 0, 0], with no address lookups.
    message.extend_from_slice(&[1, 2, 3, 1, 0, 0, 1, 9, 0]);
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

fn build_close_token_account_pending(
    trader: &Trader<'_>,
    request: &Map<String, Value>,
    digest: String,
) -> Result<Pending, DispatchResponse> {
    let user = trader.address;
    let token_account = request
        .get("tokenAccount")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("tokenAccount required"))?;
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
            "token account must be owned and closeable by the trading account, match the requested mint, be empty, and stay within maxLamports",
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
    let message = close_token_account_message(user, token_account, &fact.token_program, blockhash)?;
    let network_fee_lamports = quote_message_fee(&message)?;
    let mut transaction = vec![1];
    transaction.extend_from_slice(&[0; 64]);
    transaction.extend_from_slice(&message);
    let tx = B64.encode(transaction);
    validate_close_token_account_tx(&tx, user, token_account, &fact.token_program)?;
    let review = vec![
        "Close an empty Pump.fun token account".to_owned(),
        trader.line(),
        format!("Token account: {token_account}"),
        format!("Token: {mint}"),
        "Token balance: 0 (the account is empty, and closing a non-empty one is refused)"
            .to_owned(),
        format!(
            "Rent returned to the trading account: {}",
            lamports_display(fact.lamports)
        ),
        format!(
            "Estimated network fee: {} (a cap, charged as used)",
            lamports_display(network_fee_lamports)
        ),
    ];
    Ok(Pending {
        digest,
        tx,
        message_sha256: hex::encode(Sha256::digest(&message)),
        api: json!({
            "mint": mint,
            "tokenAccount": token_account,
            "destination": user,
            "tokenProgram": fact.token_program,
            "accountLamports": fact.lamports.to_string(),
            "lastValidBlockHeight": last_valid_block_height,
        }),
        front: false,
        network_fee_lamports,
        status: "built".into(),
        signature: None,
        approval: None,
        superseded: None,
        may_be_signed: false,
        review,
        last_valid_block_height,
    })
}
pub fn execute(c: &Ctx, a: Action, owner: TradeOwner, b: &[u8]) -> DispatchResponse {
    let user = match owner.address() {
        Ok(value) => value,
        Err(e) => return e,
    };
    let trader = Trader {
        wallet: &owner.wallet,
        account: owner.account,
        address: &user,
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
    if let Err(e) = normalize(a, &user, &mut r) {
        return e;
    }
    let canonical = match serde_jcs::to_vec(&r) {
        Ok(value) => value,
        Err(e) => return bad(format!("request cannot be canonicalized: {e}")),
    };
    // The trading account is part of the operation's identity, not only of
    // its storage key: the same body under the same id on a different
    // account is a different payment and must not adopt the stored bytes.
    let digest = hex::encode(Sha256::digest(
        [a.class().as_bytes(), user.as_bytes(), &canonical].concat(),
    ));
    let key = secret_key(&owner, &op);
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
                let superseded = v.superseded.take();
                v = match build_pending(a, &trader, &r, digest.clone()) {
                    Ok(value) => value,
                    Err(e) => return e,
                };
                // The rebuilt transaction still has to tell Bloom which
                // approval it replaced.
                v.superseded = superseded;
                if let Err(e) = put(&key, &v, true) {
                    return e;
                }
                if let Err(e) = publish(&owner, &op, a, &v) {
                    return e;
                }
            }
            v
        }
        Ok(None) => {
            let p = match build_pending(a, &trader, &r, digest) {
                Ok(value) => value,
                Err(e) => return e,
            };
            if let Err(e) = put_new(&key, &p, true) {
                return e;
            }
            if let Err(e) = publish(&owner, &op, a, &p) {
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
    // Every approval here is Exact: it binds these bytes and this review.
    // Waiting for the owner therefore never refreshes the transaction, and a
    // pending operation keeps exactly what was described to them.
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
    // Simulate before signing: an RPC that receives a signed transaction can
    // broadcast it, so a signature must never leave until this operation will
    // not build another transaction.
    if let Err(e) = simulate(&p.tx) {
        p.status = "preflight_failed".into();
        // A failed simulation says nothing permanent: a state-dependent
        // failure can clear. An Exact approval binds these bytes, so it is
        // given up only once their blockhash has provably expired.
        let keep_exact_approval = p.approval.is_some()
            && !match blockhash_expired(&p) {
                Ok(expired) => expired,
                Err(error) => return error,
            };
        if !p.may_be_signed && !keep_exact_approval {
            // Give the approval up, and tell Bloom on the next call: the
            // rebuilt transaction cannot be offered while this one's ceremony
            // is still live.
            p.superseded = p.approval.take().or(p.superseded);
        }
        if let Err(store_error) = put(&key, &p, true) {
            return store_error;
        }
        if let Err(store_error) = publish(&owner, &op, a, &p) {
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
    // Every write on this Petal is reviewed. A stored operation from an
    // older build, or a build path that failed to describe its transaction,
    // must not reach a ceremony that shows the owner nothing: refuse here,
    // before any signature can exist.
    if p.review.is_empty() {
        return fail(
            "this operation has no owner review, so it will not be signed; retry under a new operationId to rebuild it",
        );
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
        // Either this operation's own approval artifact, or — when it has
        // rebuilt — the tagged form that tells Bloom the earlier attempt is
        // given up. The two are deliberately distinct strings: a stale
        // artifact id can never be read as permission to abandon anything.
        approval_hint: p
            .approval
            .clone()
            .or_else(|| p.superseded.as_deref().map(|id| format!("supersedes:{id}"))),
        action: None,
        // The review the owner reads, frozen with these bytes. The host
        // hashes it into the approval's canonical facts, so an approval
        // prepared for one review cannot sign a different one.
        advisory: Some(review_advisory(&p.review)),
        // Exact, always: this approval covers these bytes and nothing else.
        // No delegated key is named, so Bloom selects the mounted account's
        // own signing key.
        selector: SignSelector::Exact,
        key_ref_jcs: None,
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
            p.superseded = None;
            if let Err(e) = put(&key, &p, true) {
                return e;
            }
            if let Err(e) = publish(&owner, &op, a, &p) {
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
                p.superseded = p.approval.take().or(p.superseded);
            } else {
                p.status = "signing_uncertain".into();
                p.may_be_signed = true;
            }
            if let Err(store_error) = put(&key, &p, true) {
                return store_error;
            }
            if let Err(store_error) = publish(&owner, &op, a, &p) {
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
    // The host, not this Petal, chooses which key signs. Verify the signature
    // against the address that went to the builder before the signed bytes
    // leave: if they disagree the transaction is unspendable anyway, and
    // saying so here names the real fault instead of an RPC rejection.
    if let Err(error) = verify_ed25519(&user, env.message, &sig) {
        p.status = "signing_uncertain".into();
        if let Err(store_error) = put(&key, &p, true) {
            return store_error;
        }
        if let Err(store_error) = publish(&owner, &op, a, &p) {
            return store_error;
        }
        return fail(format!(
            "the host signed with a key that is not the trading account {user}, so this transaction can never execute: {error}. The signature is kept and this operation is never rebuilt; check which account the route is mounted for, then use a new operationId"
        ));
    }
    let mut signed = raw.clone();
    signed[env.sig_offset..env.sig_offset + 64].copy_from_slice(&sig);
    let tx = B64.encode(signed);
    let signature = bs58::encode(sig).into_string();
    p.status = "broadcast_attempted".into();
    p.signature = Some(signature.clone());
    p.approval = None;
    if let Err(e) = put(&key, &p, true) {
        return e;
    }
    if let Err(e) = publish(&owner, &op, a, &p) {
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
            if let Err(e) = publish(&owner, &op, a, &p) {
                return e;
            }
            DispatchResponse::Write
        }
        Ok(_) => fail("RPC signature mismatch"),
        Err(e) => e,
    }
}

/// The Petal's review, as the bytes the host forwards to the ceremony. It is
/// a small versioned object rather than free text so the Broker can bound and
/// attribute it instead of rendering whatever a Petal sends.
fn review_advisory(items: &[String]) -> Vec<u8> {
    serde_jcs::to_vec(&json!({"schema":"bloom.petal.review.v1","items":items}))
        .unwrap_or_else(|_| b"{\"items\":[],\"schema\":\"bloom.petal.review.v1\"}".to_vec())
}

/// Ed25519 verification against a base58 Solana address: reject `S` outside
/// the group order, then check `[S]B == R + [k]A` for
/// `k = SHA-512(R ‖ A ‖ M)`. Small-order and non-canonical points are left to
/// the cofactorless equation rather than an extra rule, because the only
/// question asked here is whether the host signed with the key the builder
/// was given.
fn verify_ed25519(address: &str, message: &[u8], signature: &[u8]) -> Result<(), String> {
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use sha2::Sha512;

    let encoded = pk(address)?;
    let public = CompressedEdwardsY(encoded)
        .decompress()
        .ok_or("account address is not a valid Ed25519 point")?;
    let r_bytes: [u8; 32] = signature
        .get(..32)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("signature is too short")?;
    let s_bytes: [u8; 32] = signature
        .get(32..64)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("signature is too short")?;
    let r = CompressedEdwardsY(r_bytes)
        .decompress()
        .ok_or("signature R is not a valid Ed25519 point")?;
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or("signature S is not a canonical scalar")?;
    let mut hash = Sha512::new();
    hash.update(r_bytes);
    hash.update(encoded);
    hash.update(message);
    let k = Scalar::from_bytes_mod_order_wide(&hash.finalize().into());
    if EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-public), &s) == r {
        Ok(())
    } else {
        Err("signature does not verify against the account address".into())
    }
}

fn normalize(a: Action, user: &str, r: &mut Map<String, Value>) -> Result<(), DispatchResponse> {
    let allowed = match a {
        Action::Buy | Action::Sell => &[
            "mint",
            "amount",
            "minOutputAmount",
            "slippagePct",
            "frontRunningProtection",
            "tipAmount",
        ][..],
        Action::CloseTokenAccount => &["mint", "tokenAccount", "maxLamports"][..],
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
    if matches!(a, Action::Buy | Action::Sell) {
        r.insert("feePayer".into(), json!(user));
    }
    match a {
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
        Action::CloseTokenAccount => {
            let mint = text(r, "mint", 32, 64)?;
            let token_account = text(r, "tokenAccount", 32, 64)?;
            number(r, "maxLamports", 1)?;
            pk(&mint).map_err(bad)?;
            pk(&token_account).map_err(bad)?;
            // Rent always returns to the trading account, so the body cannot
            // name a destination. The account being closed is a token
            // account, never the trader's own address.
            if token_account == user {
                return Err(bad("tokenAccount must differ from the trading account"));
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
        .ok_or("account rent allowance exceeds u64")?;
    let mut effects = match a {
        Action::Buy => {
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
        // Closing returns rent rather than spending it. The ceiling the body
        // named is declared as the debit so the approval still carries a
        // bound for the only native amount the transaction touches.
        Action::CloseTokenAccount => vec![json!({
            "asset":{"chain":"solana","asset":"native"},
            "amount":r.get("maxLamports").and_then(Value::as_str).ok_or("close maxLamports missing")?
        })],
    };
    let auxiliary_native = tip
        .checked_add(account_rent)
        .ok_or("native debit exceeds u64")?;
    if auxiliary_native > 0 && !matches!(a, Action::Buy) {
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
            && tips.contains(destination)
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
fn publish(owner: &TradeOwner, o: &str, a: Action, p: &Pending) -> Result<(), DispatchResponse> {
    put(
        &public_key(owner, o),
        &Public {
            schema: "bloom.pumpfun_operation.v1".into(),
            action: a.class().into(),
            status: p.status.clone(),
            signature: p.signature.clone(),
            api: p.api.clone(),
            message_sha256: p.message_sha256.clone(),
            review: p.review.clone(),
            updated_ms: host::now_ms(),
        },
        false,
    )
}
pub fn read_operation(owner: &TradeOwner, o: &str) -> DispatchResponse {
    let mut operation = match get::<Public>(&public_key(owner, o)) {
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
            if let Err(e) = put(&public_key(owner, o), &operation, false) {
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
        "writes":"owner-approved, one approval per transaction"
    }))
}

/// The canonical Solana mainnet-beta genesis hash. The Petal is
/// intentionally hardcoded to mainnet-beta; this constant is the one fact
/// the preflight verifies against the live RPC before any ceremony is
/// created.
const MAINNET_BETA_GENESIS_BASE58: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

/// Read-only, ceremony-free preflight for direct Pump.fun trading.
///
/// It creates no approval, signs nothing, and changes no policy. The response
/// separates three different things, and a reader should not confuse them:
///
/// - `checks` — facts the Petal verified itself, and they held;
/// - `blockers` — checks the Petal ran and that failed;
/// - `operator_checks` — facts the Petal cannot see from inside the sandbox,
///   which a person has to confirm. These are not failures.
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

    // 2. Trusted time is reachable. A zero clock means the operation records
    //    this Petal writes would carry meaningless timestamps.
    if now == 0 {
        blockers.push(json!({
            "blocker":"trusted_clock_unavailable",
            "detail":"host reported zero trusted time"
        }));
    }
    checks.push(json!({"check":"trusted_clock","now_ms":now}));

    // 3. The trading account resolves to a readable Solana address. Without
    //    it nothing can be built, and the failure is worth naming here rather
    //    than at the first buy.
    let mut account_block: Option<Value> = None;
    match TradeOwner::scope(c, &w).and_then(|owner| {
        owner
            .address()
            .map(|address| (owner.account, address))
            .inspect_err(|error| {
                blockers.push(json!({
                    "blocker":"account_address_unavailable",
                    "detail":dispatch_message(error)
                }));
            })
    }) {
        Ok((number, address)) => {
            account_block = Some(json!({"account":number,"address":address}));
            checks.push(json!({"check":"trading_account_address","account":number}));
        }
        Err(error) => {
            if blockers.is_empty() {
                blockers.push(json!({
                    "blocker":"account_scope_invalid",
                    "detail":dispatch_message(&error)
                }));
            }
        }
    }

    // 4. Verify Solana mainnet-beta genesis against the live RPC. A
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

    // 5. Verify the Pump.fun builder is reachable. Without it no buy or sell
    //    can be built, and the owner would be asked to approve nothing.
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

    // 6. Every write declares the protocol program it routes through, and
    //    Bloom checks each declared destination against the wallet policy as
    //    a flat set. Listing them here is the difference between one policy
    //    ceremony and discovering the gaps one refused trade at a time.
    //    Nothing here funds a second wallet: the trading account is the
    //    account the owner already selected.
    operator_checks.push(json!({
        "operator_check":"wallet_policy_lists_trade_destinations",
        "required_for_trading": PROGRAMS[5..],
        "conditional":"the selected Jito tip account, only for writes that set frontRunningProtection",
        "detail":"which of the two Pump programs a mint routes through depends on whether it has migrated, and the builder chooses — allow both, or read coins/<mint>.json first. Closing a token account returns its rent to the trading account and declares no external destination."
    }));

    let ok = blockers.is_empty();
    let body = json!({
        "schema":"bloom.pumpfun_preflight.v2",
        "ok":ok,
        "wallet":w,
        "network":"solana-mainnet-beta",
        "expected_genesis":MAINNET_BETA_GENESIS_BASE58,
        "now_ms":now,
        "checks":checks,
        "blockers":blockers,
        "operator_checks":operator_checks,
        "account":account_block,
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
    // The swap route, because it is the only builder route this package is
    // allowed to reach. Probing /agents/create-coin — which this release
    // removed — asks the sandbox for a host the manifest does not permit, so
    // the call is denied before it leaves the machine and every preflight
    // reports the builder unreachable. The unit tests did not catch it: their
    // fake host answers whatever URL it is given.
    let endpoint = format!("{BUILD}{}", Action::Buy.path());
    let body = match serde_json::to_vec(&json!({
        "preflight": true,
        "inputMint": "11111111111111111111111111111111",
        "outputMint": "11111111111111111111111111111111",
        "amount": "0",
        "user": "11111111111111111111111111111111",
        "feePayer": "11111111111111111111111111111111",
        "encoding": "base64",
    })) {
        Ok(v) => v,
        Err(e) => {
            return BuilderCheck::Unreachable {
                endpoint,
                error: format!("encode: {e}"),
            };
        }
    };
    // A deliberately invalid request: identical mints and a zero amount, so
    // the builder must reject it rather than quote anything. A 400/422
    // validation response proves the route is live without asking it to build
    // a transaction. Authentication, routing and server failures stay blockers.
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
    stored_children(&format!("state/trades/{}/", account_number(c)?), None)
        .map(|children| children.into_iter().map(petal::dir).collect())
}
pub fn list_operations(c: &Ctx) -> Result<Vec<petal::RouteChild>, DispatchResponse> {
    let owner = TradeOwner::scope(c, &wallet(c)?)?;
    stored_children(
        &format!("state/{}operations/", trades_prefix(&owner)),
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

fn validate_close_token_account_tx(
    transaction: &str,
    user: &str,
    token_account: &str,
    token_program: &str,
) -> Result<(), DispatchResponse> {
    let raw = B64
        .decode(transaction)
        .map_err(|_| fail("invalid close-account base64"))?;
    let env = envelope(&raw).map_err(fail)?;
    let message = message(env.message).map_err(fail)?;
    let expected_keys = [user, token_account, token_program]
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
    if ix.program != 2 || ix.accounts != [1, 0, 0] || ix.data != [9] {
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
) -> Result<Msg, DispatchResponse> {
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
        return Err(fail(
            "unsafe builder transaction: payer is not the trading account",
        ));
    }
    let mint_text = request
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
        .ok_or_else(|| fail("unsafe builder transaction: requested mint missing"))?;
    let mint = pk(mint_text).map_err(fail)?;
    validate_message(&message, &payer, &mint, action, request)
        .map_err(|error| fail(format!("unsafe builder transaction: {error}")))?;
    Ok(message)
}
fn validate_message(
    message: &Msg,
    payer: &[u8; 32],
    mint: &[u8; 32],
    action: Action,
    request: &Map<String, Value>,
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
    validate_auxiliary_instructions(message, payer, mint, action, &wrapped_accounts)?;
    validate_protocol_instructions(message, payer, mint, action, request)
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
            return Err("System debit is not from the trading account".into());
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
                Action::Buy | Action::Sell => account_mint == mint || account_mint == &wrapped_mint,
                Action::CloseTokenAccount => false,
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
                            "CloseAccount is not for a wrapped-SOL account this transaction owns"
                                .into(),
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
            return Err(
                "wrapped-SOL account must be synced and closed to the trading account".into(),
            );
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
) -> Result<(), String> {
    let pump = pk(PROGRAMS[5])?;
    let amm = pk(PROGRAMS[6])?;
    let wrapped_mint = pk(SOL)?;
    let mut primary = 0usize;
    for ix in &message.instructions {
        let program = message
            .keys
            .get(ix.program)
            .ok_or("program is lookup-loaded")?;
        match action {
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
            _ if [pump, amm].contains(program) => {
                return Err("protocol instruction is incompatible with requested action".into());
            }
            _ => {}
        }
    }
    if matches!(action, Action::Buy | Action::Sell) && primary != 1 {
        return Err("swap transaction must contain exactly one matching swap".into());
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
pub fn route_action(c: &Ctx, b: &[u8], a: Action) -> DispatchResponse {
    if let Err(e) = body(b) {
        return e;
    }
    let w = match wallet(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let owner = match TradeOwner::scope(c, &w) {
        Ok(owner) => owner,
        Err(e) => return e,
    };
    execute(c, a, owner, b)
}
pub fn route_operation(c: &Ctx) -> DispatchResponse {
    let w = match wallet(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let o = match operation(c) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let owner = match TradeOwner::scope(c, &w) {
        Ok(owner) => owner,
        Err(e) => return e,
    };
    read_operation(&owner, &o)
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

    /// The trading account in every test. Its private key is the fake host's
    /// signing seed, and the builder fixtures name it as their payer, so a
    /// test exercises a signature that really does belong to this account.
    const USER: &str = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF";
    const BOND_MINT: &str = "C8CMvu8FXZruHrNjFaixaDJjiveG6gKmUvT5BrK5pump";
    const AMM_MINT: &str = "H3m3TD2mwmU5zkUTHRDoLU7RdxbWp6BEgoQa3s9wpump";

    /// A trader on a non-zero account, so a review that silently assumed
    /// account 0 would fail rather than look right.
    fn trader() -> Trader<'static> {
        Trader {
            wallet: "w",
            account: 3,
            address: USER,
        }
    }
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
        assert!(result.is_ok(), "{name}: {:?}", result.err());
    }

    #[test]
    fn a_trade_owner_is_the_mounted_wallet_and_account_number() {
        let account = |n| TradeOwner::from_params(WALLET, Some(WALLET), Some(n)).unwrap();
        // A root mount injects no account, and Bloom resolves account 0 for
        // it, so the two are one owner.
        assert_eq!(owner(), account("0"));
        assert_ne!(owner(), account("1"));
        // A route wallet other than the mounted one never borrows the
        // mounted account's scope.
        assert!(TradeOwner::from_params("other", Some(WALLET), Some("1")).is_err());
        assert!(TradeOwner::from_params(WALLET, Some(WALLET), Some("-1")).is_err());
    }

    #[test]
    fn two_accounts_of_one_wallet_never_share_an_operation_record() {
        let account = |n| TradeOwner::from_params(WALLET, Some(WALLET), Some(n)).unwrap();
        let (flat, zero, one, two) = (owner(), account("0"), account("1"), account("2"));
        assert_eq!(public_key(&flat, "op-1"), public_key(&zero, "op-1"));
        assert_eq!(
            public_key(&one, "op-1"),
            format!("state/trades/1/{WALLET}/operations/op-1.json")
        );
        assert_eq!(
            secret_key(&two, "op-1"),
            format!("trades/2/{WALLET}/operations/op-1.json")
        );
        // Each account's listing root holds exactly its own wallet tree.
        for listed in [&flat, &one, &two] {
            let root = format!("state/trades/{}/", listed.account);
            for other in [&flat, &one, &two] {
                assert_eq!(
                    public_key(other, "op-1").starts_with(&format!("{root}{WALLET}/")),
                    listed == other
                );
            }
        }
        // Records the removed session routes wrote are left where they are.
        assert!(!public_key(&flat, "op-1").starts_with("state/sessions/"));
    }

    #[test]
    fn the_address_a_trade_uses_is_the_mounted_accounts_own() {
        fake_host::install(FakeHost::new(NOW_MS));
        fake_host::with(|host| {
            host.seed_vfs(
                &format!("wallets/{WALLET}/0/address.sol"),
                &format!("{USER}\n"),
            );
            host.seed_vfs(
                &format!("wallets/{WALLET}/1/address.sol"),
                &format!("{AMM_CREATOR}\n"),
            );
        });
        let account = |n| TradeOwner::from_params(WALLET, Some(WALLET), Some(n)).unwrap();
        assert_eq!(owner().address().unwrap(), USER);
        assert_eq!(account("1").address().unwrap(), AMM_CREATOR);
        // An account Bloom projects no Solana address for cannot trade, and
        // the Petal never substitutes another one.
        assert!(account("2").address().is_err());
    }

    #[test]
    fn an_address_that_is_not_a_solana_key_is_refused() {
        fake_host::install(FakeHost::new(NOW_MS));
        fake_host::with(|host| {
            host.seed_vfs(&format!("wallets/{WALLET}/0/address.sol"), "0xdeadbeef\n");
        });
        assert!(owner().address().is_err());
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
            "buy_bond",
            Action::Buy,
            json!({"mint":BOND_MINT,"amount":"1000000","minOutputAmount":"1","slippagePct":2}),
        );
        assert_fixture(
            "buy_amm",
            Action::Buy,
            json!({"mint":AMM_MINT,"amount":"1000000","minOutputAmount":"1","slippagePct":2}),
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
    fn a_swap_review_states_the_account_the_bound_and_the_worst_case_cost() {
        let response = fixture("buy_bond");
        let transaction = response["transaction"].as_str().unwrap();
        let request = normalized(
            Action::Buy,
            json!({"mint":BOND_MINT,"amount":"1000000","minOutputAmount":"1","slippagePct":2}),
        );
        let parsed = validate_tx(transaction, USER, Action::Buy, &request, &response).unwrap();
        let review =
            swap_review(&trader(), Action::Buy, &request, &parsed, 5_000, Some(6)).unwrap();
        let joined = review.join("\n");
        assert!(joined.starts_with("Buy on Pump.fun"), "{joined}");
        // The owner selected an account in Bloom, not an address. Naming only
        // the address leaves them to recognise which of their accounts pays.
        assert!(
            joined.contains(&format!(
                "Trading account: Bloom wallet \"w\" account 3 ({USER})"
            )),
            "{joined}"
        );
        // Direction is stated as assets, not left to the verb alone.
        assert!(joined.contains("Paying with: SOL"), "{joined}");
        assert!(
            joined.contains(&format!("Buying token: {BOND_MINT}")),
            "{joined}"
        );
        // A buy names a token amount and a ceiling on the spend. The amount is
        // reported as what the instruction names, because that is all these
        // bytes establish; the enforced protection is the ceiling.
        let (input, tokens) = swap_instruction_amounts(&parsed, Action::Buy).unwrap();
        assert!(
            joined.contains(&format!(
                "Tokens the instruction names: {}",
                token_display(tokens, BOND_MINT, Some(6))
            )),
            "{joined}"
        );
        assert!(
            joined.contains(&format!(
                "Maximum spent on the trade: {}",
                lamports_display(input)
            )),
            "{joined}"
        );
        // Pump takes a fee. It is inside the ceiling, but an owner cannot know
        // that from a line that never mentions it.
        assert!(
            joined.contains("Pump's own trading fee comes out of that maximum"),
            "{joined}"
        );
        assert!(joined.contains("Most this can cost in total:"), "{joined}");
        // A sell states what leaves and guarantees what returns, the other
        // way round. The sell fixture quotes a zero floor, which validation
        // rejects, so its message is parsed directly here.
        let response = fixture("sell_bond");
        let raw = B64
            .decode(response["transaction"].as_str().unwrap())
            .unwrap();
        let parsed = message(envelope(&raw).unwrap().message).unwrap();
        let request = normalized(
            Action::Sell,
            json!({"mint":BOND_MINT,"amount":"1","minOutputAmount":"1","slippagePct":2}),
        );
        // No verified scale here, so the amount stays in raw units and says so
        // rather than implying a decimal point the Petal could not check.
        let review = swap_review(&trader(), Action::Sell, &request, &parsed, 5_000, None)
            .unwrap()
            .join("\n");
        let (sold, minimum) = swap_instruction_amounts(&parsed, Action::Sell).unwrap();
        assert!(
            review.contains(&format!("Selling token: {BOND_MINT}")),
            "{review}"
        );
        assert!(review.contains("Receiving: SOL"), "{review}");
        assert!(
            review.contains(&format!(
                "Sold: {sold} raw units of {BOND_MINT} (scale unverified)"
            )),
            "{review}"
        );
        assert!(
            review.contains(&format!(
                "Least SOL this may return: {}",
                lamports_display(minimum)
            )),
            "{review}"
        );
        assert!(
            review.contains("Pump's own trading fee is already taken out of that minimum"),
            "{review}"
        );
        // A sell spends no SOL on the trade, but its fee and any new token
        // account are still money leaving the account, and they are totalled.
        assert!(review.contains("Most this can cost in SOL:"), "{review}");
    }

    /// Token amounts read at a scale two RPCs agreed on, or not at all.
    #[test]
    fn a_token_amount_is_scaled_only_when_its_mint_decimals_were_verified() {
        assert_eq!(
            token_display(92_767_093_907, AMM_MINT, Some(6)),
            format!("92767.093907 of {AMM_MINT}")
        );
        // Trailing zeros go, and a whole amount keeps no point at all.
        assert_eq!(
            token_display(1_500_000, AMM_MINT, Some(6)),
            format!("1.5 of {AMM_MINT}")
        );
        assert_eq!(
            token_display(2_000_000, AMM_MINT, Some(6)),
            format!("2 of {AMM_MINT}")
        );
        // A zero-decimal mint is still a whole number, not a raw-unit string.
        assert_eq!(
            token_display(7, AMM_MINT, Some(0)),
            format!("7 of {AMM_MINT}")
        );
        // Unverified stays raw and admits it.
        assert_eq!(
            token_display(92_767_093_907, AMM_MINT, None),
            format!("92767093907 raw units of {AMM_MINT} (scale unverified)")
        );
    }
    #[test]
    fn lamports_render_as_whole_sol_without_trailing_zeros() {
        assert_eq!(lamports_display(0), "0 SOL");
        assert_eq!(lamports_display(1), "0.000000001 SOL");
        assert_eq!(lamports_display(5_000), "0.000005 SOL");
        assert_eq!(lamports_display(1_000_000_000), "1 SOL");
        assert_eq!(lamports_display(1_500_000_000), "1.5 SOL");
    }
    #[test]
    fn simulation_requires_an_explicit_result() {
        assert!(simulation_result(&json!({"result":{"value":{"err":null}}})).is_ok());
        assert!(simulation_result(&json!({"result":{"value":{"err":{"code":1}}}})).is_err());
        assert!(simulation_result(&json!({"result":{"value":{}}})).is_err());
        assert!(simulation_result(&json!({})).is_err());
    }
    #[test]
    fn a_close_is_one_exact_instruction_that_returns_rent_to_the_trading_account() {
        let token_account = "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf";
        let message_bytes =
            close_token_account_message(USER, token_account, PROGRAMS[3], BOND_MINT).unwrap();
        let mut transaction = vec![1];
        transaction.extend_from_slice(&[0; 64]);
        transaction.extend_from_slice(&message_bytes);
        let encoded = B64.encode(transaction);
        validate_close_token_account_tx(&encoded, USER, token_account, PROGRAMS[3]).unwrap();

        let parsed = message(&message_bytes).unwrap();
        // The rent destination is key 0 — the trading account that signs —
        // so the only destination the transaction can name is that account.
        assert_eq!(parsed.keys.len(), 3);
        assert_eq!(
            destinations(Action::CloseTokenAccount, &parsed),
            vec![json!({"chain":"solana","destination":USER})]
        );
        let request = normalized(
            Action::CloseTokenAccount,
            json!({"mint":BOND_MINT,"tokenAccount":token_account,"maxLamports":"2100000"}),
        );
        assert_eq!(
            effects(Action::CloseTokenAccount, &request, &parsed).unwrap(),
            vec![json!({"asset":{"chain":"solana","asset":"native"},"amount":"2100000"})]
        );

        let mut tampered = B64.decode(encoded).unwrap();
        *tampered.last_mut().unwrap() = 8;
        assert!(
            validate_close_token_account_tx(
                &B64.encode(tampered),
                USER,
                token_account,
                PROGRAMS[3]
            )
            .is_err()
        );
        // A close cannot name a rent destination at all, and cannot be
        // pointed at the trading account's own address as the thing to close.
        for body in [
            json!({"mint":BOND_MINT,"tokenAccount":token_account,"destination":AMM_CREATOR,"maxLamports":"2100000"}),
            json!({"mint":BOND_MINT,"tokenAccount":USER,"maxLamports":"2100000"}),
        ] {
            assert!(
                normalize(
                    Action::CloseTokenAccount,
                    USER,
                    &mut body.as_object().unwrap().clone()
                )
                .is_err(),
                "{body}"
            );
        }
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
        // The builder response is kept only so callers can re-run
        // `validate_tx`; validation itself no longer reads it.
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
        let buy =
            |mint| json!({"mint":mint,"amount":"1000000","minOutputAmount":"1","slippagePct":2});
        let sell = json!({"mint":AMM_MINT,"amount":"1","minOutputAmount":"1","slippagePct":2});
        let cases = [
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
            let (message, request, _, _) = prepared();
            validate_message(&message, &payer, &mint, action, &request)
                .unwrap_or_else(|error| panic!("{name}: {error}"));

            for position in positions {
                let (mut message, request, _, trade) = prepared();
                message.keys.push([7; 32]);
                message.instructions[trade].accounts[position] =
                    u8::try_from(message.keys.len() - 1).unwrap();
                assert!(
                    validate_message(&message, &payer, &mint, action, &request).is_err(),
                    "{name}: account {position} was substituted"
                );
            }
        }
    }
    #[test]
    fn verifier_rejects_wrong_action_and_unused_requested_mint() {
        let (mut message, request, _response) = parsed_buy_fixture();
        let payer = pk(USER).expect("payer");
        let mint = pk(BOND_MINT).expect("mint");
        let pump = pk(PROGRAMS[5]).expect("Pump program");
        let buy = message
            .instructions
            .iter_mut()
            .find(|ix| message.keys.get(ix.program) == Some(&pump))
            .expect("buy instruction");
        buy.data[..8].copy_from_slice(&IX_SELL);
        assert!(validate_message(&message, &payer, &mint, Action::Buy, &request).is_err());

        let (mut message, request, _response) = parsed_buy_fixture();
        let buy = message
            .instructions
            .iter_mut()
            .find(|ix| message.keys.get(ix.program) == Some(&pump))
            .expect("buy instruction");
        buy.accounts[2] = 1;
        assert!(validate_message(&message, &payer, &mint, Action::Buy, &request).is_err());
    }
    #[test]
    fn verifier_rejects_direct_token_debits_and_excessive_fees() {
        let (mut message, request, _response) = parsed_buy_fixture();
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
        assert!(validate_message(&message, &payer, &mint, Action::Buy, &request).is_err());

        let (mut message, request, _response) = parsed_buy_fixture();
        let price = message
            .instructions
            .iter_mut()
            .find(|ix| ix.data.first() == Some(&3))
            .expect("compute price");
        price.data[1..].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(validate_message(&message, &payer, &mint, Action::Buy, &request).is_err());
    }
    #[test]
    fn request_validation_is_closed() {
        for (action, body) in [
            (
                Action::Buy,
                json!({"mint":BOND_MINT,"amount":"1","minOutputAmount":"1","surprise":true}),
            ),
            (
                Action::CloseTokenAccount,
                json!({"mint":BOND_MINT,"tokenAccount":AMM_CREATOR,"maxLamports":"1","feeKind":"cashback"}),
            ),
        ] {
            assert!(
                normalize(action, USER, &mut body.as_object().unwrap().clone()).is_err(),
                "{body}"
            );
        }
    }

    // --- route-to-host tests --------------------------------------------
    //
    // These run a real route flow against the recording fake host in
    // `fake_host`, so they observe the requests that actually leave the Petal
    // rather than searching the source for strings.

    use crate::fake_host::{self, FakeHost};
    use petal::{HostStatus, RouteIdentity};

    const WALLET: &str = "main";
    const NOW_MS: u64 = 1_757_000_000_000;
    const SWAP_URL: &str = "https://fun-block.pump.fun/agents/swap";
    const PROBE_URL: &str = "https://fun-block.pump.fun/agents/swap";

    fn owner() -> TradeOwner {
        TradeOwner::from_params(WALLET, None, None).unwrap()
    }

    struct TestRoute;
    impl RouteIdentity for TestRoute {
        const PATH: &'static str = "trade/[wallet]/buy.json";
        const CANONICAL_PATH: &'static str = "trade/[wallet]/buy.json";
        const PARAMS: &'static [(&'static str, usize)] = &[];
    }

    fn ctx(params: &[(&str, &str)]) -> Ctx {
        Ctx::bind::<TestRoute>(petal::RawCtx {
            petal_root: "/petals/pumpfun".into(),
            package_hash: "pumpfun-test-package".into(),
            path: "trade/main/buy.json".into(),
            params: params
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            actor: None,
        })
    }

    /// The signature the host produces for a stored pending operation.
    fn expected_signature_base58(operation: &str) -> String {
        let pending: Value = fake_host::with(|host| {
            host.secret_json(&secret_key(&owner(), operation))
                .expect("pending operation was stored")
        });
        let raw = B64
            .decode(pending["tx"].as_str().expect("stored transaction"))
            .expect("stored base64");
        let env = envelope(&raw).expect("stored envelope");
        bs58::encode(fake_host::sign_message(env.message)).into_string()
    }

    /// A fake host able to serve one whole buy for the selected account:
    /// address, builder quote, fee quote, successful simulation, accepted
    /// broadcast.
    fn host_serving_a_buy() -> FakeHost {
        let mut host = FakeHost::new(NOW_MS);
        host.seed_vfs(
            &format!("wallets/{WALLET}/0/address.sol"),
            &format!("{USER}\n"),
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
        let accepted = json!({ "result": "$signature" });
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
            owner(),
            &buy_body(operation, protected),
        )
    }

    const TOKEN_ACCOUNT: &str = "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf";
    const RENT_LAMPORTS: u64 = 2_039_280;

    fn empty_token_account() -> Value {
        json!({"result":{"value":{
            "owner": PROGRAMS[3],
            "lamports": RENT_LAMPORTS,
            "data": {
                "program": "spl-token",
                "parsed": {"type":"account","info":{
                    "mint": BOND_MINT,
                    "owner": USER,
                    "tokenAmount": {"amount":"0"}
                }}
            }
        }}})
    }

    /// A fake host able to serve one whole close of an empty token account.
    fn host_serving_a_close() -> FakeHost {
        let mut host = host_serving_a_buy();
        host.reply(&format!("{RPC} getAccountInfo"), empty_token_account());
        host.reply(
            &format!("{RPC_VERIFY} getAccountInfo"),
            empty_token_account(),
        );
        host.reply(
            &format!("{RPC} getLatestBlockhash"),
            json!({"result":{"value":{"blockhash":BOND_MINT,"lastValidBlockHeight":1000}}}),
        );
        host
    }

    fn close_body(operation: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "operationId": operation,
            "mint": BOND_MINT,
            "tokenAccount": TOKEN_ACCOUNT,
            "maxLamports": RENT_LAMPORTS.to_string(),
        }))
        .expect("request serializes")
    }

    fn run_close(operation: &str) -> DispatchResponse {
        execute(
            &ctx(&[("bloom.route_id", "ROUTE_CLOSE")]),
            Action::CloseTokenAccount,
            owner(),
            &close_body(operation),
        )
    }

    fn public_operation(operation: &str) -> Value {
        fake_host::with(|host| {
            host.state_json(&public_key(&owner(), operation))
                .expect("operation projection was published")
        })
    }

    /// A session Bloom no longer authorizes (stopped, expired, or out of
    /// budget) or has not finished approving refuses a trade before the
    /// builder is called, and records nothing.

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
            json!(expected_signature_base58("buy-1")),
            "the recorded signature is the one the host produced"
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
            json!({"result": "$signature"}),
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
            json!(expected_signature_base58("buy-verify-retry"))
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
                .secret_json(&secret_key(&owner(), "buy-pending"))
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
        let key = secret_key(&owner(), "review-legacy");
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

    /// An Exact approval binds the bytes it was prepared for. Waiting for the
    /// owner never rebuilds the transaction, even when the chain has moved on
    /// and a fresh build would produce different bytes.
    #[test]
    fn a_pending_approval_never_rebuilds_the_transaction_it_binds() {
        let mut host = host_serving_a_close();
        host.sign_outcome(Ok(SignOutcome::ApprovalPending {
            action_id: "exact-old-message".into(),
            expires_ms: NOW_MS + 60_000,
        }));
        fake_host::install(host);
        assert!(dispatch_message(&run_close("review-close")).contains("approval required"));
        fake_host::with(|host| {
            host.reply_only(
                &format!("{RPC} getLatestBlockhash"),
                json!({"result":{"value":{"blockhash":AMM_MINT,"lastValidBlockHeight":1001}}}),
            );
        });
        run_close("review-close");
        fake_host::with(|host| {
            assert_eq!(host.sign_requests.len(), 2);
            assert_eq!(
                host.sign_requests[1].approval_hint.as_deref(),
                Some("exact-old-message")
            );
            assert_eq!(
                host.sign_requests[0].preimage, host.sign_requests[1].preimage,
                "the same Exact approval hint was attached to a different transaction"
            );
            assert_eq!(
                host.calls_for("getLatestBlockhash").len(),
                1,
                "a pending approval does not rebuild"
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
        let key = secret_key(&owner(), "buy-legacy");
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
            owner(),
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
    fn signing_asks_for_an_exact_approval_and_names_no_delegated_key() {
        fake_host::install(host_serving_a_buy());
        assert_eq!(run_buy("buy-claim", false), DispatchResponse::Write);

        fake_host::with(|host| {
            let request = host.sign_requests.first().expect("one signing request");
            assert_eq!(request.wallet, WALLET);
            assert_eq!(request.operation_class, "pumpfun.buy");
            assert_eq!(request.signature_algorithm, "ed25519-message");
            assert!(
                matches!(request.selector, SignSelector::Exact),
                "every Pump.fun write binds the exact bytes the owner approved"
            );
            assert_eq!(
                request.key_ref_jcs, None,
                "no delegated key is named; Bloom selects the mounted account's own key"
            );
            // The review the owner reads travels with the payload, so the
            // host can hash it into the approval it prepares.
            let advisory: Value = serde_json::from_slice(
                request
                    .advisory
                    .as_deref()
                    .expect("the review is forwarded"),
            )
            .expect("the review is JSON");
            assert_eq!(advisory["schema"], json!("bloom.petal.review.v1"));
            let items: Vec<&str> = advisory["items"]
                .as_array()
                .expect("review items")
                .iter()
                .filter_map(Value::as_str)
                .collect();
            assert!(items[0].starts_with("Buy on Pump.fun"), "{items:?}");
            assert!(
                items.iter().any(|item| item.contains(USER)),
                "the review names the account that pays: {items:?}"
            );
            assert!(
                items
                    .iter()
                    .any(|item| item.starts_with("Maximum spent on the trade:")),
                "the review bounds what the trade can spend: {items:?}"
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
            host.secret_json(&secret_key(&owner(), "buy-ambiguous"))
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
            host.secret_json(&secret_key(&owner(), "buy-recover"))
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
            host.secret_json(&secret_key(&owner(), "buy-recover"))
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
            host.secret_json(&secret_key(&owner(), "buy-refused"))
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
            host.secret_json(&secret_key(&owner(), "buy-refused"))
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

        // The signing marker lands; the broadcast record does not. An Exact
        // approval never refreshes the transaction, so there is no rebuild to
        // account for here.
        fake_host::with(|host| host.fail_store_after = Some(host.puts + 1));
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
                1,
                "the interrupted signature is not rebuilt"
            );
            assert_eq!(
                host.sign_requests[1].preimage,
                host.sign_requests[2].preimage
            );
            assert_eq!(host.calls_for("sendTransaction").len(), 1);
        });
    }

    /// Blockhash expiry settles only an unsigned transaction. A close that may
    /// already be signed could have landed before its blockhash expired, so
    /// neither a failed simulation nor expiry makes it rebuildable.
    #[test]
    fn expiry_never_makes_a_possibly_signed_operation_rebuildable() {
        let mut host = host_serving_a_close();
        host.reply(&format!("{RPC} getBlockHeight"), json!({"result": 5000}));
        host.sign_outcome(Err(SdkError::Host(HostStatus::Backend)));
        host.sign_outcome(Err(SdkError::Host(HostStatus::Denied)));
        fake_host::install(host);
        let run = || run_close("close-uncertain");
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
    fn an_exact_approval_is_given_up_only_after_its_blockhash_expires() {
        let mut host = host_serving_a_close();
        for _ in 0..2 {
            host.sign_outcome(Ok(SignOutcome::ApprovalPending {
                action_id: "exact-pending".into(),
                expires_ms: NOW_MS + 60_000,
            }));
        }
        fake_host::install(host);
        let run = || run_close("close-slow");
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
            public_operation("close-slow")["status"],
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
            // A rebuilt payload needs its own approval, and names the one it
            // gave up so Bloom can end that ceremony: a wallet holds one live
            // ceremony, so otherwise the rebuild cannot be offered until the
            // abandoned one expires.
            assert_eq!(
                host.sign_requests[2].approval_hint.as_deref(),
                Some("supersedes:exact-pending")
            );
        });
    }

    /// Which approval a rebuild says it has given up is the Petal's assertion:
    /// Bloom scopes it to this package, route, wallet, class and key, but
    /// within that scope it does not second-guess which operation is meant. So
    /// the Petal has to name only its own operation's previous attempt. Two
    /// operations that differ by nothing but their id, expiring and rebuilding
    /// together, must never name each other's.
    #[test]
    fn a_rebuild_names_only_its_own_operations_previous_attempt() {
        let mut host = host_serving_a_close();
        for action in ["exact-a", "exact-b", "rebuilt-b", "rebuilt-a"] {
            host.sign_outcome(Ok(SignOutcome::ApprovalPending {
                action_id: action.into(),
                expires_ms: NOW_MS + 60_000,
            }));
        }
        fake_host::install(host);
        let block_height = |height: u64| {
            fake_host::with(|host| {
                host.reply_only(&format!("{RPC} getBlockHeight"), json!({"result": height}));
            });
        };

        for op in ["close-a", "close-b"] {
            assert!(dispatch_message(&run_close(op)).contains("approval required"));
        }

        // Both deadlines pass. Each gives its own approval up, and neither
        // signs: two writes each, and the order between them is interleaved on
        // purpose.
        fake_host::with(|host| simulation_rejects(host, true));
        block_height(1001);
        for op in ["close-b", "close-a"] {
            run_close(op);
        }
        fake_host::with(|host| {
            simulation_rejects(host, false);
            host.reply_only(
                &format!("{RPC} getLatestBlockhash"),
                json!({"result":{"value":{"blockhash":AMM_MINT,"lastValidBlockHeight":1200}}}),
            );
        });
        for op in ["close-b", "close-a"] {
            run_close(op);
        }

        fake_host::with(|host| {
            let hints = host
                .sign_requests
                .iter()
                .map(|request| request.approval_hint.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                hints,
                vec![
                    None,
                    None,
                    Some("supersedes:exact-b".into()),
                    Some("supersedes:exact-a".into()),
                ],
                "each rebuild gives up its own operation's approval and no other"
            );
        });
        fake_host::with(|host| {
            for (op, expected) in [("close-a", "rebuilt-a"), ("close-b", "rebuilt-b")] {
                let stored = host.secret_json(&secret_key(&owner(), op)).expect("stored");
                assert_eq!(
                    stored["approval"],
                    json!(expected),
                    "{op} holds the approval prepared for its own rebuild"
                );
                assert_eq!(stored["superseded"], Value::Null);
            }
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
        let _ = read_operation(&owner(), "buy-poll");
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
        let _ = read_operation(&owner(), "buy-poll");
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
    fn preflight_reports_what_it_cannot_check_separately_from_what_failed() {
        let mut host = FakeHost::new(NOW_MS);
        host.seed_vfs(
            &format!("wallets/{WALLET}/0/address.sol"),
            &format!("{USER}\n"),
        );
        host.reply(
            &format!("{RPC_VERIFY} getGenesisHash"),
            json!({ "result": MAINNET_BETA_GENESIS_BASE58 }),
        );
        host.reply(PROBE_URL, json!({"statusCode":400,"message":"invalid"}));
        fake_host::install(host);

        let response = preflight(&ctx(&[("wallet", WALLET)]), WALLET.into());
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
        assert_eq!(
            body["account"],
            json!({"account":0,"address":USER}),
            "preflight names the account that will trade, and never provisions another"
        );

        let operator_checks = body["operator_checks"]
            .as_array()
            .expect("operator_checks array");
        let names: Vec<&str> = operator_checks
            .iter()
            .filter_map(|check| check["operator_check"].as_str())
            .collect();
        assert!(
            names.contains(&"wallet_policy_lists_trade_destinations"),
            "the unverifiable wallet-policy fact is an operator check, not a blocker: {names:?}"
        );
        // Nothing here asks the owner to allow a funding destination or to
        // reason about a session deadline; there is neither.
        for gone in [
            "wallet_policy_lists_session_address",
            "signing_scope_deadline_is_host_side",
        ] {
            assert!(!names.contains(&gone), "{gone} should be gone: {names:?}");
        }
        let destinations = operator_checks
            .iter()
            .find(|check| {
                check["operator_check"] == json!("wallet_policy_lists_trade_destinations")
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
    }

    /// An account Bloom projects no Solana address for cannot trade, and
    /// preflight says so rather than letting the first buy discover it.
    #[test]
    fn preflight_blocks_when_the_account_has_no_solana_address() {
        let mut host = FakeHost::new(NOW_MS);
        host.reply(
            &format!("{RPC_VERIFY} getGenesisHash"),
            json!({ "result": MAINNET_BETA_GENESIS_BASE58 }),
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
            json!("account_address_unavailable")
        );
        assert_eq!(body["account"], Value::Null);
    }

    #[test]
    fn preflight_still_fails_closed_on_the_facts_it_can_check() {
        let mut host = FakeHost::new(NOW_MS);
        host.seed_vfs(
            &format!("wallets/{WALLET}/0/address.sol"),
            &format!("{USER}\n"),
        );
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

    /// A write is reviewed or it is not signed. An operation record written
    /// by an older build carries no review, and reaching a ceremony with
    /// nothing to show the owner is worse than failing.
    #[test]
    fn an_operation_with_no_review_is_never_signed() {
        let mut host = host_serving_a_buy();
        host.sign_outcome(Ok(SignOutcome::ApprovalPending {
            action_id: "never-used".into(),
            expires_ms: NOW_MS + 60_000,
        }));
        fake_host::install(host);
        assert!(dispatch_message(&run_buy("buy-unreviewed", false)).contains("approval required"));

        // Strip the review the way a record from a build that predates it
        // would arrive.
        fake_host::with(|host| {
            let key = secret_key(&owner(), "buy-unreviewed");
            let mut stored = host.secret_json(&key).expect("pending operation");
            stored["review"] = json!([]);
            host.seed_secret(&key, &stored);
        });

        let response = run_buy("buy-unreviewed", false);
        assert!(
            dispatch_message(&response).contains("no owner review"),
            "{}",
            dispatch_message(&response)
        );
        fake_host::with(|host| {
            assert_eq!(
                host.sign_requests.len(),
                1,
                "the unreviewed retry must not reach the host at all"
            );
            assert!(host.calls_for("sendTransaction").is_empty());
        });
    }

    /// The host chooses the signing key, not the Petal. If it returns a
    /// signature that does not belong to the address the builder was given,
    /// the transaction cannot execute, and saying so here names the real
    /// fault instead of leaving an RPC rejection to be interpreted.
    #[test]
    fn a_signature_from_the_wrong_key_never_reaches_the_network() {
        let mut host = host_serving_a_buy();
        for _ in 0..2 {
            host.sign_outcome(Ok(SignOutcome::Signature(vec![7u8; 64])));
        }
        fake_host::install(host);

        let response = run_buy("buy-wrong-key", false);
        let message = dispatch_message(&response);
        assert!(message.contains("not the trading account"), "{message}");
        assert!(message.contains(USER), "{message}");
        fake_host::with(|host| {
            assert!(
                host.calls_for("sendTransaction").is_empty(),
                "a transaction signed by the wrong key must not be broadcast"
            );
        });
        // A signature exists, so the operation is never rebuilt.
        assert_eq!(
            public_operation("buy-wrong-key")["status"],
            json!("signing_uncertain")
        );
        assert_eq!(dispatch_message(&run_buy("buy-wrong-key", false)), message);
        fake_host::with(|host| {
            assert_eq!(builder_calls(host), 1, "never rebuilt");
            assert_eq!(
                host.sign_requests[0].preimage, host.sign_requests[1].preimage,
                "the retry signs the same transaction"
            );
        });
    }

    /// An operation id belongs to one account. The same id and the same body
    /// on a different account is a different payment, and must not adopt the
    /// first account's stored transaction.
    #[test]
    fn an_operation_id_is_bound_to_the_account_that_created_it() {
        let mut host = host_serving_a_buy();
        host.seed_vfs(
            &format!("wallets/{WALLET}/1/address.sol"),
            &format!("{AMM_CREATOR}\n"),
        );
        fake_host::install(host);
        assert_eq!(run_buy("shared-id", false), DispatchResponse::Write);

        let second = TradeOwner::from_params(WALLET, Some(WALLET), Some("1")).unwrap();
        let response = execute(
            &ctx(&[("bloom.route_id", "ROUTE_BUY")]),
            Action::Buy,
            second,
            &buy_body("shared-id", false),
        );
        // Account 1's address is not the fixture's payer, so its own build is
        // refused — but the point is that it never saw account 0's record.
        assert!(
            matches!(response, DispatchResponse::Error { .. }),
            "{response:?}"
        );
        fake_host::with(|host| {
            assert!(
                host.secret_json(&secret_key(&owner(), "shared-id"))
                    .is_some(),
                "account 0 keeps its own record"
            );
            assert!(
                host.secret_json(&secret_key(
                    &TradeOwner::from_params(WALLET, Some(WALLET), Some("1")).unwrap(),
                    "shared-id"
                ))
                .is_none(),
                "account 1 never adopted it"
            );
            assert_eq!(
                host.calls_for("sendTransaction").len(),
                1,
                "one broadcast, from the account that owns the operation"
            );
        });
    }

    /// The Petal hands the builder the account's own address and nothing
    /// else. A caller cannot name a trader, and the builder is never told a
    /// wallet id.
    #[test]
    fn the_builder_is_told_the_accounts_address_as_user_and_fee_payer() {
        fake_host::install(host_serving_a_buy());
        assert_eq!(run_buy("buy-user", false), DispatchResponse::Write);
        fake_host::with(|host| {
            let built = host
                .calls
                .iter()
                .find(|call| call.url == SWAP_URL)
                .expect("the builder was called");
            assert_eq!(built.body["user"], json!(USER));
            assert_eq!(built.body["feePayer"], json!(USER));
            assert!(
                !built.body.to_string().contains(WALLET),
                "the wallet id never leaves the Petal: {}",
                built.body
            );
        });
    }

    /// The review is frozen with the bytes: a pending operation returns the
    /// same review it was built with, and the public record carries it so a
    /// reader can see what was approved.
    #[test]
    fn the_review_is_frozen_with_the_transaction_and_published() {
        let mut host = host_serving_a_buy();
        host.sign_outcome(Ok(SignOutcome::ApprovalPending {
            action_id: "review-frozen".into(),
            expires_ms: NOW_MS + 60_000,
        }));
        fake_host::install(host);
        assert!(dispatch_message(&run_buy("buy-review", false)).contains("approval required"));
        let first = public_operation("buy-review")["review"].clone();
        assert!(
            first.as_array().is_some_and(|items| !items.is_empty()),
            "the published record carries the review: {first}"
        );
        run_buy("buy-review", false);
        assert_eq!(
            public_operation("buy-review")["review"],
            first,
            "waiting for the owner cannot change what they were shown"
        );
        fake_host::with(|host| {
            assert_eq!(
                host.sign_requests[0].advisory, host.sign_requests[1].advisory,
                "the retry forwards the same review"
            );
        });
    }

    /// Today's real Pump.fun builder output, through this Petal's validation
    /// and review. Ignored by default because it needs captured responses;
    /// `scripts/check-live-builder.sh` fetches them and runs this.
    ///
    /// The local-validator run settles a close, whose transaction the Petal
    /// builds itself. This is the other half: the instruction shapes, pool and
    /// token-account derivations, quotes and economics that only the hosted
    /// builder produces. Nothing here signs or submits.
    #[test]
    #[ignore = "needs PUMPFUN_LIVE_BUILDER_DIR from scripts/check-live-builder.sh"]
    fn live_builder_output_passes_validation_and_produces_a_review() {
        let dir = match std::env::var("PUMPFUN_LIVE_BUILDER_DIR") {
            Ok(dir) => dir,
            Err(_) => panic!("set PUMPFUN_LIVE_BUILDER_DIR, or run scripts/check-live-builder.sh"),
        };
        let mut checked = 0;
        for label in ["buy_bond", "buy_amm", "sell_bond", "sell_amm"] {
            let request_path = format!("{dir}/{label}-request.json");
            let response_path = format!("{dir}/{label}-response.json");
            let (Ok(request_raw), Ok(response_raw)) = (
                std::fs::read_to_string(&request_path),
                std::fs::read_to_string(&response_path),
            ) else {
                continue;
            };
            let Ok(builder_request) = serde_json::from_str::<Value>(&request_raw) else {
                continue;
            };
            let Ok(response) = serde_json::from_str::<Value>(&response_raw) else {
                continue;
            };
            if response
                .get("transaction")
                .and_then(Value::as_str)
                .is_none()
            {
                println!("{label}: builder returned no transaction; skipped");
                continue;
            }
            checked += 1;

            let action = if label.starts_with("buy") {
                Action::Buy
            } else {
                Action::Sell
            };
            let user = builder_request["user"].as_str().expect("request user");
            let mint = if matches!(action, Action::Buy) {
                builder_request["outputMint"].as_str()
            } else {
                builder_request["inputMint"].as_str()
            }
            .expect("request mint");

            // The scale the script agreed across two independent RPCs, written
            // only when they matched. Absent means the review must fall back to
            // raw units, which is itself worth seeing on live output.
            let live_decimals = std::fs::read_to_string(format!("{dir}/{mint}-decimals.txt"))
                .ok()
                .and_then(|text| text.trim().parse::<u8>().ok());

            // The body an agent would write, normalized exactly as a route
            // write normalizes it. `minOutputAmount` is the floor the caller
            // chooses; take the builder's own quote so the check is against
            // what it actually offered.
            let quoted = response
                .pointer("/pumpMintInfo/expectedOutAmount")
                .and_then(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| value.as_u64().map(|value| value.to_string()))
                })
                .unwrap_or_else(|| "1".to_owned());
            let body = json!({
                "mint": mint,
                "amount": builder_request["amount"],
                "minOutputAmount": quoted,
                "slippagePct": builder_request["slippagePct"],
            });
            let mut normalized = body.as_object().expect("body").clone();
            if let Err(error) = normalize(action, user, &mut normalized) {
                panic!("{label}: normalize refused the request: {error:?}");
            }

            let transaction = response["transaction"].as_str().expect("transaction");
            let parsed = match validate_tx(transaction, user, action, &normalized, &response) {
                Ok(parsed) => parsed,
                Err(error) => panic!(
                    "{label}: today's builder output failed validation: {}",
                    dispatch_message(&error)
                ),
            };

            // The review the owner would read, from the validated transaction.
            let review = swap_review(
                &Trader {
                    wallet: "live",
                    account: 0,
                    address: user,
                },
                action,
                &normalized,
                &parsed,
                5_000,
                live_decimals,
            )
            .unwrap_or_else(|error| panic!("{label}: review: {error}"));
            let debits = effects(action, &normalized, &parsed)
                .unwrap_or_else(|error| panic!("{label}: effects: {error}"));
            let destinations = destinations(action, &parsed);

            println!("\n=== {label} ===");
            println!("  program route: {}", protocol_program_of(&parsed));
            for line in &review {
                println!("  review | {line}");
            }
            println!("  declared debits: {}", json!(debits));
            println!("  declared destinations: {}", json!(destinations));

            // The floor the instruction carries must be at least what the
            // request asked for; that is the whole point of the check.
            let (input, minimum) = swap_instruction_amounts(&parsed, action)
                .unwrap_or_else(|error| panic!("{label}: instruction amounts: {error}"));
            let requested_floor: u64 = normalized["minOutputAmount"]
                .as_str()
                .expect("normalized floor")
                .parse()
                .expect("floor parses");
            assert!(
                minimum >= requested_floor,
                "{label}: instruction floor {minimum} is below the requested {requested_floor}"
            );
            assert!(input > 0, "{label}: the instruction spends nothing");
            assert!(
                review.iter().any(|line| line.contains(user)),
                "{label}: the review does not name the account"
            );
            assert!(!destinations.is_empty(), "{label}: no declared destination");
        }
        assert!(
            checked > 0,
            "no builder responses were readable under {dir}"
        );
        println!("\nvalidated {checked} live builder transactions");
    }

    /// Which protocol program a validated swap actually routed through.
    fn protocol_program_of(message: &Msg) -> String {
        let pump = pk(PROGRAMS[5]).expect("pump program");
        let amm = pk(PROGRAMS[6]).expect("amm program");
        for ix in &message.instructions {
            match message.keys.get(ix.program) {
                Some(program) if program == &pump => {
                    return format!("bonding curve {}", PROGRAMS[5]);
                }
                Some(program) if program == &amm => return format!("PumpSwap AMM {}", PROGRAMS[6]),
                _ => {}
            }
        }
        "none found".to_owned()
    }

    /// What a route serves about itself is part of the product contract. A
    /// reader must not be able to find a session, a budget or a second wallet
    /// anywhere in the help, because none of them exist any more.
    #[test]
    fn served_help_describes_owner_approved_trades_and_nothing_else() {
        let sources = [
            ("README.md", include_str!("../files/README.md.rs")),
            ("root", include_str!("../files/$index.rs")),
            (
                "buy.json",
                include_str!("../files/trade/[wallet]/buy.json.rs"),
            ),
            (
                "sell.json",
                include_str!("../files/trade/[wallet]/sell.json.rs"),
            ),
            (
                "close_token_account.json",
                include_str!("../files/trade/[wallet]/close_token_account.json.rs"),
            ),
        ];
        for (name, source) in sources {
            for word in [
                "sweep",
                "collect_fees",
                "sharing_config",
                "new.json",
                "create.json",
                "key.derive",
                "max_lamports",
                "duration_ms",
            ] {
                assert!(!source.contains(word), "{name} still offers {word}");
            }
        }
        assert!(
            sources[0].1.contains("no session key"),
            "the README must say the session model is gone: {}",
            sources[0].1
        );
        assert!(
            sources[2].1.contains("one Bloom ceremony per trade"),
            "buy.json must say what approval it costs"
        );
        assert!(
            sources[4]
                .1
                .contains("rent always returns to the trading account"),
            "close must say where the rent goes"
        );
    }
}
