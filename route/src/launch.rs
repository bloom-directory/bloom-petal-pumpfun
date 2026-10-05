//! Launching a coin: Pump's `create_v2` and the creator's first buy, in one
//! transaction the owner approves like any trade.
//!
//! Pump's builder draws the new coin's mint key and signs the transaction
//! with it before returning it, so the Petal cannot change a byte of the
//! message without voiding that signature: a launch pays the builder's
//! priority fee and is sent without Jito, whose protection means nothing for
//! a buy that happens in the same transaction as the curve is created. The
//! mint key has no power once the coin exists: Pump creates the mint with no
//! mint or freeze authority left to use. Every rebuild draws a new mint, so
//! the coin's address is the one in the signed transaction, read from the
//! operation record.

use super::*;

pub(crate) const IX_CREATE_V2: [u8; 8] = [214, 144, 76, 236, 95, 139, 49, 180];
const IPFS: &str = "https://pump.fun/api/ipfs";
/// A launch request may carry an image, so it may be larger than a trade.
pub(crate) const BODY_MAX: usize = 768 * 1024;
const IMAGE_MAX: usize = 512 * 1024;
/// Pump's builder bounds the first buy's cost at 1% over the SOL given. The
/// buy runs in the same transaction the curve is created in, at the opening
/// price, so nothing can trade ahead of it.
const FIRST_BUY_SLIPPAGE_PCT: f64 = 1.0;
/// Pump's limits on the text `create_v2` stores.
const NAME_MAX: usize = 32;
const SYMBOL_MAX: usize = 13;
const URI_MAX: usize = 200;
const DESCRIPTION_MAX: usize = 1000;
const LINK_MAX: usize = 200;
/// `create_v2`'s arguments after the creator: Mayhem mode, cashback, a
/// creator fee and holder rewards, each off when zero.
const CREATE_FLAGS_MAX: usize = 16;

/// Validate a launch request and fill in what the builder and the checks
/// need. The owner's text goes on chain as written, so it is refused rather
/// than cleaned when it carries characters that could disguise it.
pub(crate) fn normalize(r: &mut Map<String, Value>) -> Result<(), DispatchResponse> {
    plain(r, "name", NAME_MAX, true)?;
    plain(r, "symbol", SYMBOL_MAX, true)?;
    plain(r, "description", DESCRIPTION_MAX, false)?;
    for link in ["twitter", "telegram", "website"] {
        if plain(r, link, LINK_MAX, false)?.is_some_and(|l| !l.starts_with("https://")) {
            return Err(bad(format!("{link} must be an https:// link")));
        }
    }
    let uri = plain(r, "uri", URI_MAX, false)?;
    match (&uri, r.get("image")) {
        (Some(uri), None) if uri.starts_with("https://") => {}
        (Some(_), None) => return Err(bad("uri must be an https:// link")),
        (None, Some(_)) => {
            image(r)?;
        }
        _ => {
            return Err(bad(
                "give exactly one of uri (metadata you host) or image (base64, uploaded to IPFS through Pump)",
            ));
        }
    }
    if uri.is_some()
        && ["description", "twitter", "telegram", "website"]
            .iter()
            .any(|field| r.contains_key(*field))
    {
        return Err(bad(
            "description and links belong in the metadata at uri; send them with image instead",
        ));
    }
    number(r, "amount", 1)?;
    r.insert("minOutputAmount".into(), json!("1"));
    r.insert(
        "slippagePct".into(),
        Value::Number(serde_json::Number::from_f64(FIRST_BUY_SLIPPAGE_PCT).expect("finite")),
    );
    Ok(())
}

/// A text field without control, zero-width or direction-changing
/// characters, at most `max` bytes.
fn plain(
    r: &Map<String, Value>,
    field: &str,
    max: usize,
    required: bool,
) -> Result<Option<String>, DispatchResponse> {
    let Some(value) = r.get(field) else {
        return if required {
            Err(bad(format!("{field} string required")))
        } else {
            Ok(None)
        };
    };
    let text = value
        .as_str()
        .ok_or_else(|| bad(format!("{field} must be a string")))?;
    if text.trim().is_empty() || text.len() > max {
        return Err(bad(format!("{field} must be 1 to {max} bytes")));
    }
    if text.chars().any(hidden) {
        return Err(bad(format!(
            "{field} contains control, zero-width or direction-changing characters"
        )));
    }
    Ok(Some(text.to_owned()))
}

/// The image's bytes and media type, recognised by its first bytes.
fn image(
    r: &Map<String, Value>,
) -> Result<(Vec<u8>, &'static str, &'static str), DispatchResponse> {
    let encoded = r
        .get("image")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("image must be a base64 string"))?;
    if encoded.len() > IMAGE_MAX.div_ceil(3) * 4 + 4 {
        return Err(bad(format!("image exceeds {} KiB", IMAGE_MAX / 1024)));
    }
    let bytes = B64
        .decode(encoded)
        .map_err(|_| bad("image must be standard base64"))?;
    if bytes.len() > IMAGE_MAX {
        return Err(bad(format!("image exceeds {} KiB", IMAGE_MAX / 1024)));
    }
    let (mime, extension) = match bytes.as_slice() {
        [0x89, b'P', b'N', b'G', ..] => ("image/png", "png"),
        [0xFF, 0xD8, 0xFF, ..] => ("image/jpeg", "jpg"),
        [b'G', b'I', b'F', b'8', ..] => ("image/gif", "gif"),
        [
            b'R',
            b'I',
            b'F',
            b'F',
            _,
            _,
            _,
            _,
            b'W',
            b'E',
            b'B',
            b'P',
            ..,
        ] => ("image/webp", "webp"),
        _ => return Err(bad("image must be PNG, JPEG, GIF or WebP")),
    };
    Ok((bytes, mime, extension))
}

/// Pin the image and the coin's metadata to IPFS through Pump, the way its
/// own site does, and return the metadata URI.
fn upload_metadata(r: &Map<String, Value>) -> Result<String, DispatchResponse> {
    let (bytes, mime, extension) = image(r)?;
    let boundary = format!("bloom-{}", hex::encode(&Sha256::digest(&bytes)[..12]));
    let mut body = Vec::with_capacity(bytes.len() + 2048);
    for field in [
        "name",
        "symbol",
        "description",
        "twitter",
        "telegram",
        "website",
    ] {
        if let Some(value) = r.get(field).and_then(Value::as_str) {
            body.extend(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
    }
    body.extend(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"showName\"\r\n\r\ntrue\r\n\
--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"image.{extension}\"\r\nContent-Type: {mime}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend(&bytes);
    body.extend(format!("\r\n--{boundary}--\r\n").as_bytes());
    let response = host::http(
        &HttpRequest {
            method: "POST".into(),
            url: IPFS.into(),
            headers: vec![(
                "content-type".into(),
                format!("multipart/form-data; boundary={boundary}"),
            )],
            body,
        },
        MAX,
    )
    .map_err(|e| fail(format!("metadata upload failed: {}", sdk_message(&e))))?;
    let v: Value = serde_json::from_slice(&response.body)
        .map_err(|_| fail("metadata upload returned invalid JSON"))?;
    if !(200..300).contains(&response.status) {
        return Err(fail(format!("metadata upload refused: {}", safe(&v))));
    }
    v.get("metadataUri")
        .and_then(Value::as_str)
        .filter(|uri| {
            uri.starts_with("https://")
                && uri.len() <= URI_MAX
                && uri.bytes().all(|b| b.is_ascii_graphic())
        })
        .map(str::to_owned)
        .ok_or_else(|| fail("metadata upload returned no usable metadataUri"))
}

pub(crate) fn build(
    trader: &Trader<'_>,
    request: &Map<String, Value>,
    digest: String,
    metadata_uri: Option<String>,
) -> Result<Pending, DispatchResponse> {
    let user = trader.address;
    let uri = match (request.get("uri").and_then(Value::as_str), metadata_uri) {
        (Some(uri), _) => uri.to_owned(),
        (None, Some(uploaded)) => uploaded,
        (None, None) => upload_metadata(request)?,
    };
    let builder_request = json!({
        "user": user,
        "creator": user,
        "feePayer": user,
        "name": request.get("name"),
        "symbol": request.get("symbol"),
        "uri": uri,
        "solLamports": request.get("amount"),
        "mayhemMode": false,
        "cashback": false,
        "tokenizedAgent": false,
        "frontRunningProtection": false,
        "encoding": "base64",
    });
    let response = post(
        &format!("{BUILD}{}", Action::Launch.path()),
        &builder_request,
    )?;
    let tx = response
        .get("transaction")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("builder omitted transaction"))?
        .to_owned();
    let mint = response
        .get("mintPublicKey")
        .and_then(Value::as_str)
        .filter(|mint| pk(mint).is_ok())
        .ok_or_else(|| fail("builder omitted the new coin's address"))?
        .to_owned();
    let mut checked = request.clone();
    checked.insert("uri".into(), json!(uri));
    let parsed = validate(&tx, user, &mint, &checked, &response)?;
    let network_fee_lamports = transaction_fee(&tx, request)?;
    let network_fee_cap_lamports = local_fee_floor(&parsed, request)
        .map_err(fail)?
        .max(network_fee_lamports);
    let created = created_accounts(&tx, &parsed)?;
    let raw = B64
        .decode(&tx)
        .map_err(|_| fail("builder transaction is not base64"))?;
    let message_sha256 = hex::encode(Sha256::digest(envelope(&raw).map_err(fail)?.message));
    let review = review(
        trader,
        request,
        &uri,
        &mint,
        &parsed,
        Costs {
            network_fee_lamports,
            network_fee_cap_lamports,
            created,
        },
    )
    .map_err(|error| fail(format!("cannot describe the built transaction: {error}")))?;
    let mut api = response;
    let fields = api
        .as_object_mut()
        .ok_or_else(|| fail("builder response must be an object"))?;
    fields.remove("transaction");
    fields.insert("metadataUri".into(), json!(uri));
    Ok(Pending {
        digest,
        tx,
        message_sha256,
        api,
        front: false,
        network_fee_lamports,
        network_fee_cap_lamports,
        created: Some(created),
        sell_all: None,
        metadata_uri: Some(uri),
        status: "built".into(),
        signature: None,
        approval: None,
        may_be_signed: false,
        review,
    })
}

/// The builder's launch transaction, checked as built: two signers, the
/// trading account paying and the new mint's signature already valid, and
/// only the instructions a launch needs, naming exactly what was asked.
fn validate(
    transaction: &str,
    user: &str,
    mint: &str,
    request: &Map<String, Value>,
    response: &Value,
) -> Result<Msg, DispatchResponse> {
    let unsafe_tx = |error: String| fail(format!("unsafe builder transaction: {error}"));
    let raw = B64
        .decode(transaction)
        .map_err(|_| unsafe_tx("invalid base64".into()))?;
    let env = envelope(&raw).map_err(unsafe_tx)?;
    let mut message = message(env.message).map_err(unsafe_tx)?;
    hydrate_lookups(&mut message, response)?;
    let payer = pk(user).map_err(fail)?;
    let mint_key = pk(mint).map_err(fail)?;
    if message.required != 2 || message.readonly_signed != 0 {
        return Err(unsafe_tx(
            "a launch has exactly two writable signers".into(),
        ));
    }
    if message.keys.first() != Some(&payer) {
        return Err(unsafe_tx("payer is not the trading account".into()));
    }
    if message.keys.get(1) != Some(&mint_key) {
        return Err(unsafe_tx("the second signer is not the new coin".into()));
    }
    let mint_signature = raw
        .get(env.sig_offset + 64..env.sig_offset + 128)
        .ok_or_else(|| unsafe_tx("mint signature missing".into()))?;
    verify_ed25519(mint, env.message, mint_signature)
        .map_err(|error| unsafe_tx(format!("mint signature: {error}")))?;
    validate_message(&message, &payer, &mint_key, Action::Launch, request).map_err(unsafe_tx)?;
    Ok(message)
}

/// `create_v2` for exactly the requested coin: the new mint and its own
/// bonding curve, the trading account as payer and creator, the requested
/// name, symbol and URI, and every option (Mayhem mode, cashback, creator
/// fee, holder rewards) off.
pub(crate) fn validate_create(
    message: &Msg,
    ix: &Ix,
    payer: &[u8; 32],
    mint: &[u8; 32],
    request: &Map<String, Value>,
) -> Result<(), String> {
    require_account(message, ix, 0, mint, "create mint")?;
    let curve = program_address(&[b"bonding-curve", mint], &pk(PROGRAMS[5])?)?;
    require_account(message, ix, 2, &curve, "create bonding curve")?;
    require_account(message, ix, 5, payer, "create user")?;
    require_account(message, ix, 7, &pk(PROGRAMS[4])?, "create token program")?;
    let mut offset = 8;
    for field in ["name", "symbol", "uri"] {
        let named = borsh_string(&ix.data, &mut offset)?;
        if Some(named) != request.get(field).and_then(Value::as_str) {
            return Err(format!("create {field} differs from the request"));
        }
    }
    let creator = ix
        .data
        .get(offset..offset + 32)
        .ok_or("create creator missing")?;
    if creator != payer {
        return Err("create creator is not the trading account".into());
    }
    let flags = &ix.data[offset + 32..];
    if flags.len() > CREATE_FLAGS_MAX || flags.iter().any(|b| *b != 0) {
        return Err("create enables an option this Petal does not offer".into());
    }
    Ok(())
}

fn borsh_string<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a str, String> {
    let length = data
        .get(*offset..*offset + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or("create argument truncated")? as usize;
    let text = data
        .get(*offset + 4..*offset + 4 + length)
        .ok_or("create argument truncated")?;
    *offset += 4 + length;
    std::str::from_utf8(text).map_err(|_| "create argument is not UTF-8".into())
}

fn review(
    trader: &Trader<'_>,
    request: &Map<String, Value>,
    uri: &str,
    mint: &str,
    message: &Msg,
    costs: Costs,
) -> Result<Vec<String>, String> {
    let (spend, tokens) = swap_instruction_amounts(message, Action::Launch)?;
    let text = |field: &str| {
        request
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_default()
    };
    let total = spend
        .checked_add(costs.created.lamports)
        .and_then(|value| {
            value.checked_add(
                costs
                    .network_fee_cap_lamports
                    .max(costs.network_fee_lamports),
            )
        })
        .ok_or("total native cost exceeds u64")?;
    Ok(vec![
        "Launch a new coin on Pump.fun".to_owned(),
        trader.line(),
        format!("Name: {}", text("name")),
        format!("Symbol: {}", text("symbol")),
        format!("Metadata: {uri}"),
        "Creator: the trading account, which receives Pump's creator fees".to_owned(),
        format!(
            "Coin address: {mint} (Pump draws a new one if the launch is rebuilt after approval; the operation record names the one signed)"
        ),
        format!(
            "First buy, at the opening price: at most {} for {}",
            lamports_display(spend),
            token_display(tokens, mint, Some(6))
        ),
        format!(
            "Network fee: at most {}",
            lamports_display(
                costs
                    .network_fee_cap_lamports
                    .max(costs.network_fee_lamports)
            )
        ),
        format!(
            "Rent for {} new account(s): {}",
            costs.created.count,
            lamports_display(costs.created.lamports)
        ),
        format!("Most this can cost in total: {}", lamports_display(total)),
    ])
}
