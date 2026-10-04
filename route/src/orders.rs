//! Limit orders: a trade the owner approves once, that fills later, when the
//! price reaches a limit.
//!
//! An order is an ordinary Pump buy or sell, checked as any trade is, with
//! two changes. Its amounts are set to the limit, so Pump's program refuses
//! it until the price is there: a buy names the tokens its SOL buys at the
//! limit, and a sell names the least SOL its tokens fetch at the limit. And
//! its recent blockhash is the value of a durable nonce the trading account
//! owns, with the nonce's advance as its first instruction, so the signed
//! transaction stays valid until it lands or the nonce moves. The Petal
//! stores the signed bytes and sends them when a check finds that they would
//! succeed. Cancelling advances the nonce, which voids them.
//!
//! Each nonce is an order slot, created once with its own approval. One slot
//! carries one open order, because landing or cancelling any transaction on
//! a nonce advances it for all of them.
//!
//! What cannot be expressed this way is a stop-loss: a sell's floor keeps it
//! from filling below a price, never above one.

use super::*;

pub(crate) const RECENT_BLOCKHASHES: &str = "SysvarRecentB1ockHashes11111111111111111111";
const RENT_SYSVAR: &str = "SysvarRent111111111111111111111111111111111";
const NONCE_SPACE: u64 = 80;
/// Compute units a slot creation or a cancel is given; each uses a few
/// thousand.
const OWN_COMPUTE_UNITS: u32 = 20_000;
/// The least a slot creation or cancel pays per compute unit, in
/// micro-lamports: 0.00004 SOL for the whole transaction, near what the
/// builder pays per unit for trades. New accounts have
/// no fee history to price from, and at the trades' floor a slot creation
/// sat unlanded on mainnet until its blockhash expired.
const OWN_COMPUTE_UNIT_PRICE: u64 = 2_000_000;
/// Order slots a trading account may have.
pub(crate) const SLOTS: u64 = 4;
/// Pump's own errors for a price that has not reached the limit: too much
/// SOL required, too little SOL received (curve), and exceeded slippage
/// (PumpSwap).
const NOT_YET: [u64; 3] = [6002, 6003, 6004];
/// The curve has graduated; an order built for it can never fill.
const CURVE_COMPLETE: u64 = 6005;

/// A limit order's own facts, kept in its operation record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Order {
    pub side: String,
    pub market_cap_sol: f64,
    pub slot: u64,
    pub nonce_account: String,
    pub nonce_value: String,
    pub mint: String,
    /// The signed transaction, once the owner has approved it.
    #[serde(default)]
    pub signed: Option<String>,
    /// Nonterminal states reserve the slot until the nonce is settled.
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub checked_ms: Option<u64>,
    /// Cancellation bytes stay secret and use the same nonce as the order.
    #[serde(default)]
    pub cancellation: Option<Cancellation>,
    /// True only after a finalized outcome or finalized nonce invalidation.
    /// Older records did not establish finality and must be reconciled.
    #[serde(default)]
    pub settled: bool,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Cancellation {
    pub operation: String,
    pub signed: Option<String>,
    pub front: bool,
}

fn terminal(state: &str) -> bool {
    matches!(
        state,
        "filled" | "cancelled" | "invalidated" | "chain_failed"
    )
}

fn reserves_slot(order: &Order) -> bool {
    !order.settled
}

/// The seed an order slot's address is derived from.
fn seed(slot: u64) -> String {
    format!("bloom-pumpfun-order-{slot}")
}

/// Solana's `create_with_seed`: the address of an account the trading
/// account creates and owns without a key of its own.
pub(crate) fn slot_address(user: &[u8; 32], slot: u64) -> Result<[u8; 32], String> {
    let system = pk(PROGRAMS[1])?;
    let mut hasher = Sha256::new();
    hasher.update(user);
    hasher.update(seed(slot).as_bytes());
    hasher.update(system);
    Ok(hasher.finalize().into())
}

/// A slot's nonce value, when it is an initialized nonce account the
/// trading account controls.
fn nonce_value(account: &Value, user: &[u8; 32]) -> Option<[u8; 32]> {
    let data = owned_data(account, &pk(PROGRAMS[1]).ok()?)?;
    if data.len() != NONCE_SPACE as usize
        || data.get(..4) != Some(&1u32.to_le_bytes()[..])
        || data.get(4..8) != Some(&1u32.to_le_bytes()[..])
        || key_at(&data, 8).as_ref() != Some(user)
    {
        return None;
    }
    key_at(&data, 40)
}

/// An order slot's address and, when it exists, its nonce value.
type Slot = ([u8; 32], Option<[u8; 32]>);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct SlotReservation {
    operation: String,
    digest: String,
}

fn reservation_key(owner: &TradeOwner, slot: u64, nonce: &[u8; 32]) -> String {
    format!(
        "state/{}order-slots/{slot}/{}.json",
        trades_prefix(owner),
        bs58::encode(nonce).into_string()
    )
}

/// Atomic creation prevents concurrent route writes from approving two orders
/// on one nonce. The same operation may resume; a new nonce has a new key.
fn reserve(
    owner: &TradeOwner,
    slot: u64,
    nonce: &[u8; 32],
    operation: &str,
    digest: &str,
) -> Result<(), DispatchResponse> {
    let key = reservation_key(owner, slot, nonce);
    let expected = SlotReservation {
        operation: operation.into(),
        digest: digest.into(),
    };
    if put_new(&key, &expected, false).is_err() {
        match get::<SlotReservation>(&key)? {
            Some(existing) if existing == expected => return Ok(()),
            Some(existing) => {
                return Err(deny(format!(
                    "slot {slot} is reserved by operation {}; retry that operationId",
                    existing.operation
                )));
            }
            None => {
                return Err(fail(
                    "could not persist the order slot reservation; nothing signed",
                ));
            }
        }
    }
    Ok(())
}

/// Every slot's address and, when it exists, its nonce value.
fn slots(user: &[u8; 32]) -> Result<Vec<Slot>, DispatchResponse> {
    let addresses = (0..SLOTS)
        .map(|slot| slot_address(user, slot))
        .collect::<Result<Vec<_>, _>>()
        .map_err(fail)?;
    let accounts = accounts_data(&addresses, "base64")?;
    Ok(addresses
        .into_iter()
        .zip(accounts.iter().map(|account| nonce_value(account, user)))
        .collect())
}

pub(crate) fn normalize(user: &str, r: &mut Map<String, Value>) -> Result<(), DispatchResponse> {
    let side = match r.remove("side").as_ref().and_then(Value::as_str) {
        Some("buy") => Action::Buy,
        Some("sell") => Action::Sell,
        _ => return Err(bad("side must be \"buy\" or \"sell\"")),
    };
    let cap = r
        .remove("marketCapSol")
        .and_then(|v| v.as_f64())
        .filter(|cap| cap.is_finite() && *cap > 0.0 && *cap < 1e12)
        .ok_or_else(|| bad("marketCapSol must be a positive number: the market cap in SOL at which the order fills"))?;
    let slot = match r.remove("slot") {
        None => None,
        Some(v) => Some(
            v.as_u64()
                .filter(|slot| *slot < SLOTS)
                .ok_or_else(|| bad(format!("slot must be 0 to {}", SLOTS - 1)))?,
        ),
    };
    for field in ["slippagePct", "minOutputAmount", "priorityFee"] {
        if r.contains_key(field) {
            return Err(bad(format!(
                "{field} is set by the order itself: the limit is the price"
            )));
        }
    }
    super::normalize(side, user, r)?;
    // The order is built at today's price and tightened to the limit, so
    // its build may move freely; it pays the builder's priority fee because
    // it must land whenever it fills.
    r.insert("slippagePct".into(), json!(MAX_SLIPPAGE_PCT));
    r.insert("priorityFee".into(), json!("builder"));
    r.insert(
        "side".into(),
        json!(if matches!(side, Action::Buy) {
            "buy"
        } else {
            "sell"
        }),
    );
    r.insert("marketCapSol".into(), json!(cap));
    if let Some(slot) = slot {
        r.insert("slot".into(), json!(slot));
    }
    Ok(())
}

pub(crate) fn side(r: &Map<String, Value>) -> Action {
    if r.get("side").and_then(Value::as_str) == Some("buy") {
        Action::Buy
    } else {
        Action::Sell
    }
}

/// Orders on this trading account, with their operation ids.
fn orders(owner: &TradeOwner) -> Result<Vec<(String, Pending)>, DispatchResponse> {
    let ids = stored_children(
        &format!("state/{}operations/", trades_prefix(owner)),
        Some(".json"),
    )?;
    let mut found = Vec::new();
    for id in ids {
        if let Some(pending) = get_secret::<Pending>(&secret_key(owner, &id))?
            && pending.order.is_some()
        {
            found.push((id, pending));
        }
    }
    Ok(found)
}

fn owner_of(trader: &Trader<'_>) -> TradeOwner {
    TradeOwner {
        wallet: trader.wallet.to_owned(),
        account: trader.account,
    }
}

/// Build a limit order: the trade at today's price, checked as any trade
/// is; its durable-nonce form, which signing simulates to bound what it can
/// spend; and that form with its amounts set to the limit, which is what is
/// signed and stored.
pub(crate) fn build(
    trader: &Trader<'_>,
    request: &Map<String, Value>,
    digest: String,
    operation: &str,
) -> Result<Pending, DispatchResponse> {
    let user = pk(trader.address).map_err(fail)?;
    let side = side(request);
    let cap = request
        .get("marketCapSol")
        .and_then(Value::as_f64)
        .ok_or_else(|| fail("normalized marketCapSol missing"))?;
    let slots = slots(&user)?;
    let owner = owner_of(trader);
    let mut busy = orders(&owner)?
        .into_iter()
        .filter(|(id, p)| id != operation && p.order.as_ref().is_some_and(reserves_slot))
        .filter_map(|(_, p)| p.order.map(|o| o.slot))
        .collect::<Vec<_>>();
    for (slot, (_, nonce)) in slots.iter().enumerate() {
        if let Some(nonce) = nonce
            && let Some(reservation) =
                get::<SlotReservation>(&reservation_key(&owner, slot as u64, nonce))?
            && reservation.operation != operation
        {
            busy.push(slot as u64);
        }
    }
    let slot = match request.get("slot").and_then(Value::as_u64) {
        Some(slot) => slot,
        None => (0..SLOTS)
            .find(|slot| slots[*slot as usize].1.is_some() && !busy.contains(slot))
            .ok_or_else(|| {
                deny(format!(
                    "no free order slot: create one by writing {{\"operationId\":\"slot-N\",\"slot\":N}} to order_slot.json (slots 0 to {}; each holds one open order)",
                    SLOTS - 1
                ))
            })?,
    };
    let (nonce_account, value) = slots[slot as usize];
    let value = value.ok_or_else(|| {
        deny(format!(
            "order slot {slot} does not exist yet: create it with order_slot.json"
        ))
    })?;
    if busy.contains(&slot) {
        return Err(deny(format!(
            "order slot {slot} already holds an open order"
        )));
    }

    let mut swap_request = request.clone();
    for field in ["side", "marketCapSol", "slot"] {
        swap_request.remove(field);
    }
    let mut swap = build_swap(side, trader, &swap_request, digest)?;
    let raw = B64
        .decode(&swap.tx)
        .map_err(|_| fail("builder transaction is not base64"))?;
    let message = envelope(&raw).map_err(fail)?.message.to_vec();
    let parsed = super::message(&message).map_err(fail)?;
    let system = pk(PROGRAMS[1]).map_err(fail)?;
    let recent = pk(RECENT_BLOCKHASHES).map_err(fail)?;
    let durable = |instructions: &[Ix]| {
        txedit::with_durable_nonce(
            &message,
            instructions,
            &nonce_account,
            &value,
            &system,
            &recent,
        )
        .and_then(|m| txedit::unsigned_transaction(&m))
        .map(|tx| B64.encode(tx))
        .map_err(fail)
    };
    let relaxed = durable(&parsed.instructions)?;
    let (tightened, limit_line) = tighten(&parsed, side, request, cap)?;
    let order_tx = durable(&tightened)?;
    let order_raw = B64
        .decode(&order_tx)
        .map_err(|_| fail("order transaction is not base64"))?;
    swap.message_sha256 = hex::encode(Sha256::digest(envelope(&order_raw).map_err(fail)?.message));
    swap.tx = order_tx;
    swap.simulate_tx = Some(relaxed);
    let mint = request_text(
        request,
        if matches!(side, Action::Buy) {
            "outputMint"
        } else {
            "inputMint"
        },
    )
    .map_err(fail)?
    .to_owned();
    let verb = if matches!(side, Action::Buy) {
        "buy"
    } else {
        "sell"
    };
    let mut final_message =
        super::message(envelope(&order_raw).map_err(fail)?.message).map_err(fail)?;
    hydrate_lookups(&mut final_message, &json!({}))?;
    swap.review = swap_review(
        trader,
        side,
        request,
        &final_message,
        Costs {
            network_fee_lamports: swap.network_fee_lamports,
            network_fee_cap_lamports: swap.network_fee_cap_lamports,
            created: swap.created.unwrap_or_default(),
        },
        verified_mint_decimals(&mint),
    )
    .map_err(fail)?;
    let mut review = vec![
        format!("Limit {verb} on Pump.fun"),
        limit_line,
        format!(
            "Stays open until it fills or you cancel it, in order slot {slot}; the Petal sends it when a check finds the price there, through {}",
            if swap.front { "Jito" } else { "the public RPC" }
        ),
    ];
    review.extend(swap.review.into_iter().skip(1));
    swap.review = review;
    swap.order = Some(Order {
        side: verb.into(),
        market_cap_sol: cap,
        slot,
        nonce_account: bs58::encode(nonce_account).into_string(),
        nonce_value: bs58::encode(value).into_string(),
        mint,
        signed: None,
        state: String::new(),
        checked_ms: None,
        cancellation: None,
        settled: false,
        note: None,
    });
    reserve(&owner, slot, &value, operation, &swap.digest)?;
    Ok(swap)
}

/// The swap instructions with their amounts set to the limit. The market
/// cap is turned into lamports per raw token unit with the mint's supply
/// read from the chain.
fn tighten(
    parsed: &Msg,
    side: Action,
    request: &Map<String, Value>,
    cap: f64,
) -> Result<(Vec<Ix>, String), DispatchResponse> {
    let mint = pk(request_text(
        request,
        if matches!(side, Action::Buy) {
            "outputMint"
        } else {
            "inputMint"
        },
    )
    .map_err(fail)?)
    .map_err(fail)?;
    let supply = accounts_data(&[mint], "jsonParsed")?
        .first()
        .and_then(|m| {
            m.pointer("/data/parsed/info/supply")?
                .as_str()?
                .parse::<f64>()
                .ok()
        })
        .filter(|s| *s > 0.0)
        .ok_or_else(|| fail("Solana RPC did not give the mint's supply"))?;
    let lamports_per_unit = cap * 1e9 / supply;
    let pump = pk(PROGRAMS[5]).map_err(fail)?;
    let amm = pk(PROGRAMS[6]).map_err(fail)?;
    let discriminator = if matches!(side, Action::Buy) {
        IX_BUY
    } else {
        IX_SELL
    };
    let mut instructions = parsed.instructions.clone();
    let swap = instructions
        .iter_mut()
        .find(|ix| {
            parsed
                .keys
                .get(ix.program)
                .is_some_and(|p| *p == pump || *p == amm)
                && has_discriminator(ix, discriminator)
        })
        .ok_or_else(|| fail("validated swap instruction missing"))?;
    let line = if matches!(side, Action::Buy) {
        let budget = request_u64(request, "amount").map_err(fail)?;
        let tokens = (budget as f64 / lamports_per_unit).ceil();
        if !(1.0..u64::MAX as f64).contains(&tokens) {
            return Err(bad("that limit buys no tokens with this amount"));
        }
        swap.data[8..16].copy_from_slice(&(tokens as u64).to_le_bytes());
        swap.data[16..24].copy_from_slice(&budget.to_le_bytes());
        format!(
            "Buy limit from target market cap {} SOL and the supply at placement: spends at most {} for {} raw token units, including protocol fees",
            cap_display(cap),
            lamports_display(budget),
            tokens as u64
        )
    } else {
        let sold = instruction_u64(swap, 8).map_err(fail)?;
        let floor = (sold as f64 * lamports_per_unit).ceil();
        if !(1.0..u64::MAX as f64).contains(&floor) {
            return Err(bad("that limit prices this sale at nothing"));
        }
        swap.data[16..24].copy_from_slice(&(floor as u64).to_le_bytes());
        format!(
            "Sell limit from target market cap {} SOL and the supply at placement: sells {} raw token units for at least {} after protocol fees",
            cap_display(cap),
            sold,
            lamports_display(floor as u64)
        )
    };
    Ok((instructions, line))
}

fn cap_display(cap: f64) -> String {
    if cap >= 100.0 {
        format!("{cap:.0}")
    } else {
        format!("{cap:.2}")
    }
}

pub(crate) fn normalize_slot(r: &mut Map<String, Value>) -> Result<(), DispatchResponse> {
    r.get("slot")
        .and_then(Value::as_u64)
        .filter(|slot| *slot < SLOTS)
        .ok_or_else(|| bad(format!("slot must be 0 to {}", SLOTS - 1)))?;
    Ok(())
}

/// Create order slot `slot`: a nonce account at an address derived from the
/// trading account, which is also its authority.
pub(crate) fn build_slot(
    trader: &Trader<'_>,
    request: &Map<String, Value>,
    digest: String,
) -> Result<Pending, DispatchResponse> {
    let user = pk(trader.address).map_err(fail)?;
    let slot = request
        .get("slot")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("normalized slot missing"))?;
    let account = slot_address(&user, slot).map_err(fail)?;
    if slots(&user)?[slot as usize].1.is_some() {
        return Err(deny(format!("order slot {slot} already exists")));
    }
    let rent = post(
        RPC,
        &rpc("getMinimumBalanceForRentExemption", json!([NONCE_SPACE])),
    )?
    .get("result")
    .and_then(Value::as_u64)
    .filter(|rent| *rent > 0 && *rent < 10_000_000)
    .ok_or_else(|| fail("Solana RPC did not quote the nonce account's rent"))?;
    let seed = seed(slot);
    let mut create = vec![3, 0, 0, 0];
    create.extend_from_slice(&user);
    create.extend_from_slice(&(seed.len() as u64).to_le_bytes());
    create.extend_from_slice(seed.as_bytes());
    create.extend_from_slice(&rent.to_le_bytes());
    create.extend_from_slice(&NONCE_SPACE.to_le_bytes());
    create.extend_from_slice(&pk(PROGRAMS[1]).map_err(fail)?);
    let mut initialize = vec![6, 0, 0, 0];
    initialize.extend_from_slice(&user);
    let keys = [
        user,
        account,
        pk(PROGRAMS[1]).map_err(fail)?,
        pk(RECENT_BLOCKHASHES).map_err(fail)?,
        pk(RENT_SYSVAR).map_err(fail)?,
    ];
    let instructions = [
        Ix {
            program: 2,
            accounts: vec![0, 1],
            data: create,
        },
        Ix {
            program: 2,
            accounts: vec![1, 3, 4],
            data: initialize,
        },
    ];
    let review_head = vec![
        "Create a Pump.fun order slot".to_owned(),
        trader.line(),
        format!(
            "Order slot {slot}: a nonce account at {} that the trading account owns, used to keep one limit order valid until it fills or is cancelled",
            bs58::encode(account).into_string()
        ),
        format!(
            "Rent held in it: {} (the account stays yours)",
            lamports_display(rent)
        ),
    ];
    own_transaction(
        trader,
        [1, 0, 3],
        &keys,
        &instructions,
        tip_lamports(request)?,
        digest,
        Created {
            count: 1,
            lamports: rent,
        },
        review_head,
        json!({"slot": slot, "slotAccount": bs58::encode(account).into_string(), "rentLamports": rent}),
    )
}

pub(crate) fn normalize_cancel(r: &mut Map<String, Value>) -> Result<(), DispatchResponse> {
    let order = r
        .get("order")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("order must name the order's operationId"))?;
    ident(order, "order")?;
    Ok(())
}

/// Cancel an open order by advancing its slot's nonce, which voids the
/// stored transaction: it can never land after this does.
pub(crate) fn build_cancel(
    trader: &Trader<'_>,
    request: &Map<String, Value>,
    digest: String,
    operation: &str,
) -> Result<Pending, DispatchResponse> {
    let user = pk(trader.address).map_err(fail)?;
    let id = request_text(request, "order").map_err(fail)?;
    let order = get_secret::<Pending>(&secret_key(&owner_of(trader), id))?
        .and_then(|p| p.order)
        .ok_or_else(|| bad(format!("no order {id}")))?;
    if order.settled {
        return Err(bad(format!(
            "order {id} is already settled; check orders.json"
        )));
    }
    if order.signed.is_none() {
        return Err(bad(format!("order {id} is awaiting approval, not signed")));
    }
    if order
        .cancellation
        .as_ref()
        .is_some_and(|c| c.operation != operation)
    {
        return Err(deny(
            "cancellation already requested: retry its original operationId",
        ));
    }
    if current_nonce(&order, "confirmed")? != Some(pk(&order.nonce_value).map_err(fail)?) {
        return Err(bad(format!(
            "order {id} has a changed nonce ({}) : check_orders.json must reconcile it before cancellation",
            if order.state.is_empty() {
                "awaiting approval"
            } else {
                &order.state
            }
        )));
    }
    // Do not use a recent blockhash: a delayed cancel could advance a slot
    // reused after the order filled. Order and cancel must race on one nonce.
    let keys = [user, pk(PROGRAMS[1]).map_err(fail)?];
    let review_head = vec![
        "Cancel a Pump.fun limit order".to_owned(),
        trader.line(),
        format!(
            "Order {id}: {} {} at a market cap of {} SOL, in order slot {}",
            order.side,
            order.mint,
            cap_display(order.market_cap_sol),
            order.slot
        ),
        "Cancels only after its nonce advance finalizes; the order may fill first. The fee and Jito tip are charged"
            .to_owned(),
    ];
    let mut pending = own_transaction(
        trader,
        [1, 0, 1],
        &keys,
        &[],
        tip_lamports(request)?,
        digest,
        Created::default(),
        review_head,
        json!({"order": id, "slot": order.slot, "nonceValue": order.nonce_value}),
    )?;
    let raw = B64
        .decode(&pending.tx)
        .map_err(|_| fail("invalid cancel transaction"))?;
    let env = envelope(&raw).map_err(fail)?;
    let parsed = message(env.message).map_err(fail)?;
    let durable = txedit::with_durable_nonce(
        env.message,
        &parsed.instructions,
        &pk(&order.nonce_account).map_err(fail)?,
        &pk(&order.nonce_value).map_err(fail)?,
        &pk(PROGRAMS[1]).map_err(fail)?,
        &pk(RECENT_BLOCKHASHES).map_err(fail)?,
    )
    .map_err(fail)?;
    pending.message_sha256 = hex::encode(Sha256::digest(&durable));
    pending.tx = B64.encode(txedit::unsigned_transaction(&durable).map_err(fail)?);
    Ok(pending)
}

/// A transaction this Petal builds itself, with a fresh blockhash.
#[allow(clippy::too_many_arguments)]
fn own_transaction(
    trader: &Trader<'_>,
    header: [u8; 3],
    keys: &[[u8; 32]],
    instructions: &[Ix],
    tip: u64,
    digest: String,
    created: Created,
    mut review: Vec<String>,
    api: Value,
) -> Result<Pending, DispatchResponse> {
    // With a tip, the transaction goes through Jito's block engine, as
    // protected trades do. On mainnet the public RPCs accepted these
    // transactions and none of them reached a block. The tip account joins
    // the writable keys, and the indices of the read-only keys move up.
    let mut keys = keys.to_vec();
    let mut instructions = instructions.to_vec();
    let mut header = header;
    if tip > 0 {
        let tip_account = pk(JITO_TIPS[0]).map_err(fail)?;
        let at = keys.len() - usize::from(header[2]);
        keys.insert(at, tip_account);
        for ix in &mut instructions {
            if ix.program >= at {
                ix.program += 1;
            }
            for account in &mut ix.accounts {
                if usize::from(*account) >= at {
                    *account += 1;
                }
            }
        }
        let system = keys
            .iter()
            .position(|k| *k == pk(PROGRAMS[1]).unwrap_or_default())
            .ok_or_else(|| fail("the System program is missing"))?;
        instructions.push(Ix {
            program: system,
            accounts: vec![0, u8::try_from(at).map_err(|_| fail("too many keys"))?],
            data: [&2u32.to_le_bytes()[..], &tip.to_le_bytes()].concat(),
        });
        review.push(format!(
            "Jito tip: {}; sent through Jito's block engine",
            lamports_display(tip)
        ));
        header = [header[0], header[1], header[2]];
    }
    let keys = &keys[..];
    let instructions = &instructions[..];
    let latest = post(
        RPC,
        &rpc("getLatestBlockhash", json!([{"commitment":COMMITMENT}])),
    )?;
    let blockhash = latest
        .pointer("/result/value/blockhash")
        .and_then(Value::as_str)
        .and_then(|b| pk(b).ok())
        .ok_or_else(|| fail("Solana RPC omitted the latest blockhash"))?;
    // A priority fee at the market price for these accounts, so the
    // transaction lands on a busy network before its blockhash expires.
    let writable = (1..keys.len() - usize::from(header[2]))
        .map(|i| bs58::encode(keys[i]).into_string())
        .collect::<Vec<_>>();
    let price = recent_compute_unit_price(&writable)
        .unwrap_or(0)
        .max(OWN_COMPUTE_UNIT_PRICE)
        .min(MAX_PRIORITY_FEE_LAMPORTS * 1_000_000 / u64::from(OWN_COMPUTE_UNITS));
    let mut keys = keys.to_vec();
    keys.push(pk(PROGRAMS[0]).map_err(fail)?);
    let budget = keys.len() - 1;
    let mut all = vec![
        Ix {
            program: budget,
            accounts: Vec::new(),
            data: [&[2u8][..], &OWN_COMPUTE_UNITS.to_le_bytes()].concat(),
        },
        Ix {
            program: budget,
            accounts: Vec::new(),
            data: [&[3u8][..], &price.to_le_bytes()].concat(),
        },
    ];
    all.extend_from_slice(instructions);
    let header = [header[0], header[1], header[2] + 1];
    let message = txedit::plain_message(header, &keys, &blockhash, &all).map_err(fail)?;
    let parsed = super::message(&message).map_err(fail)?;
    let network_fee_lamports =
        quote_message_fee(&message)?.max(local_fee_floor(&parsed, &Map::new()).map_err(fail)?);
    review.push(format!(
        "Estimated network fee: {} (a cap, charged as used)",
        lamports_display(network_fee_lamports)
    ));
    review.push(format!(
        "Most this can cost in total: {}",
        lamports_display(
            network_fee_lamports
                .saturating_add(created.lamports)
                .saturating_add(tip)
        )
    ));
    let _ = trader;
    Ok(Pending {
        digest,
        tx: B64.encode(txedit::unsigned_transaction(&message).map_err(fail)?),
        message_sha256: hex::encode(Sha256::digest(&message)),
        api,
        front: tip > 0,
        network_fee_lamports,
        network_fee_cap_lamports: network_fee_lamports,
        created: Some(created),
        sell_all: None,
        metadata_uri: None,
        order: None,
        simulate_tx: None,
        status: "built".into(),
        signature: None,
        approval: None,
        may_be_signed: false,
        review,
    })
}

/// Record cancellation intent before signing and executable bytes before
/// sending. A restart can reconcile or resend the same cancel without signing.
pub(crate) fn request_cancel(
    owner: &TradeOwner,
    id: &str,
    operation: &str,
    p: &Pending,
    signed: Option<String>,
) -> Result<(), DispatchResponse> {
    let key = secret_key(owner, id);
    let mut original = get_secret::<Pending>(&key)?.ok_or_else(|| bad("order not found"))?;
    let order = original
        .order
        .as_mut()
        .ok_or_else(|| bad("operation is not an order"))?;
    if order.settled {
        return Err(deny("order already settled; refresh orders.json"));
    }
    if p.api.get("nonceValue").and_then(Value::as_str) != Some(&order.nonce_value) {
        return Err(deny("cancellation does not bind the order's nonce"));
    }
    if order
        .cancellation
        .as_ref()
        .is_some_and(|c| c.operation != operation)
    {
        return Err(deny("retry the existing cancellation operationId"));
    }
    // Preserve any signed bytes if the caller is reconciling signing.
    let signed = signed.or_else(|| order.cancellation.as_ref().and_then(|c| c.signed.clone()));
    order.cancellation = Some(Cancellation {
        operation: operation.into(),
        signed,
        front: p.front,
    });
    order.state = "cancel_pending".into();
    order.note = Some(
        "cancellation requested; the order can still fill until the nonce advance finalizes".into(),
    );
    original.status = order.state.clone();
    put(&key, &original, true)?;
    publish(owner, id, Action::LimitOrder, &original)
}

/// Check and reconcile all unsettled orders. Every simulation is unsigned;
/// executable bytes leave only through the selected broadcast route.
pub fn check(c: &Ctx, w: String) -> DispatchResponse {
    let owner = match TradeOwner::scope(c, &w) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let list = match orders(&owner) {
        Ok(v) => v,
        Err(e) => return e,
    };
    for (id, mut p) in list {
        let Some(order) = p.order.clone() else {
            continue;
        };
        // Older packages marked cancelled at RPC acceptance, so recheck those
        // records too. Filled/failed/invalidated records require no new send.
        if order.settled && order.state != "invalidated" {
            continue;
        }
        let (state, note) = match reconcile(&p, &order) {
            Ok(outcome) => outcome,
            Err(e) => (
                order.state.clone(),
                format!("check failed: {}", dispatch_message(&e)),
            ),
        };
        let order = p.order.as_mut().expect("checked above");
        order.settled = terminal(&state);
        order.state = state.clone();
        order.note = Some(note);
        order.checked_ms = Some(host::now_ms());
        p.status = state;
        let key = secret_key(&owner, &id);
        if let Err(e) =
            put(&key, &p, true).and_then(|_| publish(&owner, &id, Action::LimitOrder, &p))
        {
            return e;
        }
    }
    DispatchResponse::Write
}

fn signed_signature(signed: &str) -> Option<String> {
    let raw = B64.decode(signed).ok()?;
    signed_message(&raw).ok()?;
    Some(bs58::encode(raw.get(1..65)?).into_string())
}

fn signed_message(raw: &[u8]) -> Result<&[u8], DispatchResponse> {
    if raw.len() > MAX_TX || raw.first() != Some(&1) {
        return Err(fail("invalid stored signer count or packet size"));
    }
    let bytes = raw
        .get(65..)
        .ok_or_else(|| fail("truncated stored signature"))?;
    let parsed = message(bytes).map_err(fail)?;
    if parsed.required != 1 {
        return Err(fail("stored signer/header mismatch"));
    }
    Ok(bytes)
}

#[derive(Debug, PartialEq)]
enum ChainStatus {
    Absent,
    Pending,
    Confirmed,
    Finalized,
    Failed(String, bool),
}

fn status_at(url: &str, signed: &str) -> Result<ChainStatus, DispatchResponse> {
    let signature = signed_signature(signed).ok_or_else(|| fail("invalid stored transaction"))?;
    let reply = post_exact(
        url,
        &rpc(
            "getSignatureStatuses",
            json!([[signature], {"searchTransactionHistory":true}]),
        ),
    )?;
    let value = reply
        .pointer("/result/value/0")
        .ok_or_else(|| fail("RPC omitted signature status"))?;
    if value.is_null() {
        return Ok(ChainStatus::Absent);
    }
    let err = value
        .get("err")
        .ok_or_else(|| fail("RPC omitted transaction error status"))?;
    let commitment = value
        .get("confirmationStatus")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("RPC omitted transaction commitment"))?;
    if !matches!(commitment, "processed" | "confirmed" | "finalized") {
        return Err(fail("RPC returned an unknown transaction commitment"));
    }
    if !err.is_null() {
        return Ok(ChainStatus::Failed(
            err.to_string().chars().take(200).collect(),
            commitment == "finalized",
        ));
    }
    Ok(match commitment {
        "finalized" => ChainStatus::Finalized,
        "confirmed" => ChainStatus::Confirmed,
        _ => ChainStatus::Pending,
    })
}

/// A final outcome needs both independently queried RPCs to agree. A lagging
/// or unavailable second RPC keeps the slot reserved; it never licenses reuse.
fn chain_status(signed: &str) -> Result<ChainStatus, DispatchResponse> {
    let primary = status_at(RPC, signed)?;
    if matches!(
        primary,
        ChainStatus::Finalized | ChainStatus::Failed(_, true)
    ) {
        let verify = status_at(RPC_VERIFY, signed)?;
        if primary != verify {
            return Ok(ChainStatus::Pending);
        }
    }
    Ok(primary)
}

fn payer(order: &Order) -> Result<[u8; 32], DispatchResponse> {
    let raw = B64
        .decode(
            order
                .signed
                .as_deref()
                .ok_or_else(|| fail("order not signed"))?,
        )
        .map_err(|_| fail("invalid stored order"))?;
    let parsed = message(signed_message(&raw)?).map_err(fail)?;
    parsed
        .keys
        .first()
        .copied()
        .ok_or_else(|| fail("order payer missing"))
}

fn current_nonce(order: &Order, commitment: &str) -> Result<Option<[u8; 32]>, DispatchResponse> {
    let user = payer(order)?;
    let read = |url| -> Result<Option<[u8; 32]>, DispatchResponse> {
        let value = post_exact(
            url,
            &rpc(
                "getMultipleAccounts",
                json!([[order.nonce_account],
            {"encoding":"base64", "commitment":commitment}]),
            ),
        )?;
        let account = value
            .pointer("/result/value/0")
            .ok_or_else(|| fail("RPC omitted order nonce"))?;
        if account.is_null() {
            return Ok(None);
        }
        nonce_value(account, &user)
            .map(Some)
            .ok_or_else(|| fail("invalid order nonce account or authority"))
    };
    let primary = read(RPC)?;
    let verify = read(RPC_VERIFY)?;
    if primary != verify {
        return Err(fail(
            "RPCs disagree on the order nonce; slot remains reserved",
        ));
    }
    Ok(primary)
}

fn simulate_order(signed: &str) -> Result<Value, DispatchResponse> {
    let raw = B64
        .decode(signed)
        .map_err(|_| fail("invalid stored transaction"))?;
    let unsigned = B64.encode(txedit::unsigned_transaction(signed_message(&raw)?).map_err(fail)?);
    let value = post(
        RPC,
        &rpc(
            "simulateTransaction",
            json!([unsigned,
        {"encoding":"base64","sigVerify":false,"replaceRecentBlockhash":false,"commitment":COMMITMENT}]),
        ),
    )?;
    value
        .pointer("/result/value/err")
        .cloned()
        .ok_or_else(|| fail("RPC omitted simulation result"))
}

fn send_order(signed: &str, front: bool) -> Result<(), DispatchResponse> {
    let expected = signed_signature(signed).ok_or_else(|| fail("invalid stored signature"))?;
    let sent = if front {
        post(
            JITO,
            &rpc("sendTransaction", json!([signed, {"encoding":"base64"}])),
        )?
    } else {
        send_public(signed)?
    };
    if sent.get("result").and_then(Value::as_str) != Some(&expected) {
        return Err(fail("RPC signature mismatch; submission outcome unknown"));
    }
    Ok(())
}

fn reconcile(p: &Pending, order: &Order) -> Result<(String, String), DispatchResponse> {
    let Some(signed) = order.signed.as_deref() else {
        return Ok((
            p.status.clone(),
            "awaiting approval; no signed order".into(),
        ));
    };
    let status = chain_status(signed)?;
    match status {
        ChainStatus::Finalized => return Ok(("filled".into(), "fill finalized on chain".into())),
        ChainStatus::Failed(ref err, true) => {
            return Ok((
                "chain_failed".into(),
                format!("order failed on chain and spent its nonce: {err}"),
            ));
        }
        _ => {}
    }
    let expected = pk(&order.nonce_value).map_err(fail)?;
    if let Some(cancel) = &order.cancellation
        && let Some(cancel_tx) = cancel.signed.as_deref()
        && chain_status(cancel_tx)? == ChainStatus::Finalized
    {
        // The original transaction may be confirmed on the winning fork even
        // if another RPC reports the cancellation finalized. Do not guess.
        if matches!(status, ChainStatus::Confirmed) {
            return Ok((
                "cancel_pending".into(),
                "conflicting fill/cancel observations; waiting for finality".into(),
            ));
        }
        return Ok((
            "cancelled".into(),
            "cancellation finalized; the signed order is invalid".into(),
        ));
    }
    if current_nonce(order, "confirmed")? != Some(expected) {
        if current_nonce(order, "finalized")? != Some(expected) {
            return Ok(("invalidated".into(), "nonce change finalized; this order cannot execute. Its fill/cancellation outcome is not established; inspect the recorded signatures".into()));
        }
        return Ok((
            if order.cancellation.is_some() {
                "cancel_pending"
            } else {
                "submitted"
            }
            .into(),
            "nonce changed but is not finalized; slot remains reserved".into(),
        ));
    }
    if let Some(cancel) = &order.cancellation {
        if let Some(tx) = cancel.signed.as_deref() {
            let err = simulate_order(tx)?;
            if err.is_null() {
                let result = send_order(tx, cancel.front);
                return Ok(("cancel_pending".into(), match result {
                    Ok(()) => "cancellation sent; order remains executable until the nonce advance finalizes".into(),
                    Err(e) => format!("cancellation submission uncertain: {}; retry the same cancellation operationId", dispatch_message(&e)),
                }));
            }
            return Ok((
                "cancel_pending".into(),
                format!(
                    "cancellation would fail: {}; retry its original operationId",
                    err
                ),
            ));
        }
        return Ok((
            "cancel_pending".into(),
            "cancellation awaiting approval/signing; retry its original operationId".into(),
        ));
    }
    if matches!(order.state.as_str(), "cancelled" | "cancel_pending") {
        return Ok((
            "cancel_pending".into(),
            "legacy cancellation is unverified and nonce remains live; request cancellation again"
                .into(),
        ));
    }
    match status {
        ChainStatus::Confirmed => {
            return Ok((
                "confirmed".into(),
                "fill confirmed; waiting for finality".into(),
            ));
        }
        ChainStatus::Pending | ChainStatus::Failed(_, false) => {
            return Ok((
                "submitted".into(),
                "transaction observed; waiting for finality".into(),
            ));
        }
        _ => {}
    }
    let err = simulate_order(signed)?;
    if err.is_null() {
        // On lost acknowledgements or dropped sends, resend only identical
        // bytes. A durable nonce permits at most one execution.
        let result = send_order(signed, p.front);
        return Ok((
            "submitted".into(),
            match result {
                Ok(()) => "sent the signed order; waiting for confirmation".into(),
                Err(e) => format!(
                    "submission outcome unknown: {}; the same bytes will be reconciled on the next check",
                    dispatch_message(&e)
                ),
            },
        ));
    }
    let code = err
        .pointer("/InstructionError/1/Custom")
        .and_then(Value::as_u64);
    Ok(match code {
        Some(code) if NOT_YET.contains(&code) => (
            "open".into(),
            "waiting: the price has not reached the limit".into(),
        ),
        Some(CURVE_COMPLETE) => (
            "dead".into(),
            "coin graduated; cancel this curve order to invalidate its nonce and free the slot"
                .into(),
        ),
        _ => (
            "open".into(),
            format!(
                "would not fill now: {}",
                err.to_string().chars().take(200).collect::<String>()
            ),
        ),
    })
}

/// `trade/<wallet>/<index>/orders.json`: every order and every slot.
pub fn list(c: &Ctx, w: String) -> DispatchResponse {
    match list_value(c, &w) {
        Ok(v) => petal::read_json_value(&v),
        Err(e) => e,
    }
}

pub(crate) fn list_value(c: &Ctx, w: &str) -> Result<Value, DispatchResponse> {
    let owner = TradeOwner::scope(c, w)?;
    let user = pk(&owner.address()?).map_err(fail)?;
    let list = orders(&owner)?;
    let slots = slots(&user)?;
    let orders = list
        .iter()
        .filter_map(|(id, p)| {
            let o = p.order.as_ref()?;
            Some(json!({
                "order": id,
                "side": o.side,
                "mint": o.mint,
                "marketCapSol": o.market_cap_sol,
                "slot": o.slot,
                "state": if o.state.is_empty() { "awaiting approval" } else { o.state.as_str() },
                "note": o.note,
                "checkedMs": o.checked_ms,
                "signature": p.signature,
                "cancelOperation": o.cancellation.as_ref().map(|c| c.operation.as_str()),
                "cancelSignature": o.cancellation.as_ref().and_then(|c| c.signed.as_deref()).and_then(signed_signature),
            }))
        })
        .collect::<Vec<_>>();
    let slots = slots.iter().enumerate().map(|(slot, (address, value))| {
        let holder = list.iter().find(|(_, p)| p.order.as_ref().is_some_and(|o| o.slot == slot as u64 && reserves_slot(o)));
        let reservation = match value {
            Some(nonce) => get::<SlotReservation>(&reservation_key(&owner, slot as u64, nonce))?,
            None => None,
        };
        Ok(json!({
            "slot": slot,
            "address": bs58::encode(address).into_string(),
            "exists": value.is_some(),
            "order": holder.map(|(id, _)| id.clone()).or_else(|| reservation.map(|r| r.operation)),
        }))
    }).collect::<Result<Vec<_>, DispatchResponse>>()?;
    Ok(json!({
        "orders": orders,
        "slots": slots,
        "note": "An order fills only when a check finds the price at its limit: write {} to check_orders.json, from an agent or a timer. Cancel with cancel_order.json.",
    }))
}
