//! What a trader should know about a coin beyond its price: who holds it,
//! what its creator has done before and since launch, who bought in its
//! first block, what its mint still allows, and how it has traded.
//!
//! Every check is best effort. One that cannot be made is named in
//! `unchecked` instead of failing the whole summary, because a summary that
//! says what it could not see is more useful than none.

use super::*;
use std::collections::BTreeMap;

const TOP_HOLDERS: &str = "https://frontend-api-v3.pump.fun/coins/top-holders";
/// Share of supply the ten largest holders may own, outside the curve or
/// pool, before a summary warns.
const TOP_TEN_WARN_PCT: f64 = 30.0;
/// Share of supply other wallets may buy in the creation block before a
/// summary warns. Coordinated wallets buying alongside the launch are how a
/// bundled launch looks.
const LAUNCH_BLOCK_WARN_PCT: f64 = 10.0;
/// How far below its all-time high a coin may trade before a summary warns.
const BELOW_HIGH_WARN_PCT: f64 = 50.0;
/// How many of the creator's coins are read.
const CREATOR_HISTORY: usize = 50;
/// A creator with this many other coins, none graduated, draws a warning.
const SERIAL_CREATOR_COINS: usize = 5;
/// Newest signatures read for a curve. A curve with this many or more has
/// traded too much for its first block to be found in one page.
const SIGNATURE_PAGE: usize = 1000;
/// First-block transactions read, each a few tens of KiB.
const LAUNCH_TRANSACTIONS: usize = 6;
const LAUNCH_RESPONSE_MAX: usize = 1 << 20;
/// Token-2022 extensions every Pump coin carries. Any other can take a fee
/// on transfers, block them, or let someone else move holders' tokens.
const PUMP_EXTENSIONS: [&str; 2] = ["metadataPointer", "tokenMetadata"];

/// A coin's risk facts, and the warnings they raise.
pub(crate) struct Risk {
    /// Supply in raw units, from the chain when the mint could be read.
    pub supply: Option<u128>,
    pub decimals: Option<u8>,
    pub creator_pct: Option<f64>,
    pub report: Value,
    pub warnings: Vec<String>,
}

/// What the mint account says, and what the creator holds of it.
struct MintFacts {
    supply: u128,
    decimals: u8,
    mint_authority: Option<String>,
    freeze_authority: Option<String>,
    extensions: Vec<String>,
    creator_holds: Option<u128>,
}

/// What happened in the block the coin was created in.
struct Launch {
    creator_bought: u128,
    other_buyers: usize,
    others_bought: u128,
    /// The block held more transactions than were read.
    partial: bool,
}

pub(crate) fn risk(
    mint: &[u8; 32],
    m: &str,
    coin: &Value,
    market: Option<Market>,
    creator: Option<&str>,
) -> Risk {
    let mut unchecked = Vec::new();
    let mut warnings = Vec::new();
    let creator_key = creator.and_then(|c| pk(c).ok());

    let facts = mint_facts(mint, creator_key.as_ref());
    if facts.is_none() {
        unchecked.push("mint");
    }
    let supply = facts.as_ref().map(|f| f.supply).or_else(|| {
        coin.get("total_supply").and_then(|s| {
            s.as_u64()
                .map(u128::from)
                .or_else(|| s.as_str()?.parse().ok())
        })
    });
    let decimals = facts.as_ref().map(|f| f.decimals).or_else(|| {
        coin.get("base_decimals")
            .and_then(Value::as_u64)
            .and_then(|d| u8::try_from(d).ok())
    });
    let pct = |amount: u128| {
        supply
            .filter(|s| *s > 0)
            .map(|s| amount as f64 / s as f64 * 100.0)
    };
    let creator_pct = facts.as_ref().and_then(|f| f.creator_holds).and_then(pct);
    if creator_pct.is_none() {
        unchecked.push("creatorHolds");
    }
    if let Some(facts) = &facts {
        if facts.mint_authority.is_some() {
            warnings.push("Someone can still mint more of this coin".to_owned());
        }
        if facts.freeze_authority.is_some() {
            warnings.push("Someone can freeze this coin in holders' wallets".to_owned());
        }
        let odd = facts
            .extensions
            .iter()
            .filter(|e| !PUMP_EXTENSIONS.contains(&e.as_str()))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if !odd.is_empty() {
            warnings.push(format!(
                "The token has extensions Pump coins do not ({}); they can charge fees on or block transfers",
                odd.join(", ")
            ));
        }
    }

    let pump = pk(PROGRAMS[5]).ok();
    let curve = pump.and_then(|p| program_address(&[b"bonding-curve", mint], &p).ok());
    let pool = canonical_pool(mint).ok();
    let excluded = [curve, pool]
        .into_iter()
        .flatten()
        .map(|a| bs58::encode(a).into_string())
        .collect::<Vec<_>>();
    let scale = 10f64.powi(i32::from(decimals.unwrap_or(6)));
    // Pump's index can lag or leave holders out; the creator's holding read
    // from the chain is a floor under the ten largest.
    let holders = supply
        .and_then(|s| top_holders(m, &excluded, s as f64 / scale))
        .map(|(top_ten, count)| (top_ten.max(creator_pct.unwrap_or(0.0)), count));
    if holders.is_none() {
        unchecked.push("holders");
    }
    if let Some((top_ten, _)) = holders
        && top_ten >= TOP_TEN_WARN_PCT
    {
        warnings.push(format!(
            "The 10 largest holders own {top_ten:.1}% of the supply"
        ));
    }

    let history = creator.and_then(|c| creator_history(c, m));
    if history.is_none() {
        unchecked.push("creatorHistory");
    }
    if let Some((others, graduated, capped)) = history
        && others >= SERIAL_CREATOR_COINS
        && graduated == 0
    {
        let count = if capped {
            format!("at least {others}")
        } else {
            others.to_string()
        };
        warnings.push(format!(
            "The creator has launched {count} other coins and none graduated"
        ));
    }

    let launch = match (market, curve, creator) {
        (Some(Market::Curve { .. }), Some(curve), Some(creator)) => {
            let found = first_block(&curve, m, creator);
            if found.is_none() {
                unchecked.push("launch");
            }
            found
        }
        _ => {
            unchecked.push("launch");
            None
        }
    };
    if let Some(launch) = &launch {
        let others = pct(launch.others_bought);
        if let Some(others_pct) = others.filter(|p| *p >= LAUNCH_BLOCK_WARN_PCT) {
            warnings.push(format!(
                "{} other wallet(s) bought {others_pct:.1}% of the supply in the block the coin was created, which is how a bundled launch looks",
                launch.other_buyers
            ));
        }
        if let (Some(bought), Some(holds)) = (pct(launch.creator_bought), creator_pct)
            && launch.creator_bought > 0
            && holds < bought / 2.0
        {
            warnings.push(format!(
                "The creator bought {bought:.1}% at launch and now holds {holds:.1}%"
            ));
        }
    }

    let below_high = below_high(coin);
    if let Some(below) = below_high.filter(|b| *b >= BELOW_HIGH_WARN_PCT) {
        warnings.push(format!("Trading {below:.0}% below its all-time high"));
    }

    let report = json!({
        "top10HoldPct": holders.map(|h| h.0),
        "holders": holders.and_then(|h| h.1),
        "creatorHoldsPct": creator_pct,
        "creatorHoldingScope": "associated_token_accounts_only",
        "creatorBoughtAtLaunchPct": launch.as_ref().and_then(|l| pct(l.creator_bought)),
        "launchBlockBuyers": launch.as_ref().map(|l| l.other_buyers),
        "launchBlockBoughtPct": launch.as_ref().and_then(|l| pct(l.others_bought)),
        "launchBlockPartial": launch.as_ref().map(|l| l.partial),
        "creatorOtherCoins": history.map(|h| h.0),
        "creatorGraduatedCoins": history.map(|h| h.1),
        "mintAuthority": facts.as_ref().map(|f| f.mint_authority.clone()),
        "freezeAuthority": facts.as_ref().map(|f| f.freeze_authority.clone()),
        "tokenExtensions": facts.as_ref().map(|f| f.extensions.clone()),
        "belowAllTimeHighPct": below_high,
        "unchecked": unchecked,
    });
    Risk {
        supply,
        decimals,
        creator_pct,
        report,
        warnings,
    }
}

/// The mint account, parsed, and the creator's associated token accounts
/// under both token programs, in one call.
fn mint_facts(mint: &[u8; 32], creator: Option<&[u8; 32]>) -> Option<MintFacts> {
    let mut keys = vec![*mint];
    if let Some(creator) = creator {
        let associated = pk(PROGRAMS[2]).ok()?;
        for program in [PROGRAMS[3], PROGRAMS[4]] {
            keys.push(program_address(&[creator, &pk(program).ok()?, mint], &associated).ok()?);
        }
    }
    let accounts = accounts_data(&keys, "jsonParsed").ok()?;
    let owner = accounts[0].get("owner").and_then(Value::as_str)?;
    if owner != PROGRAMS[3] && owner != PROGRAMS[4] {
        return None;
    }
    let info = accounts[0].pointer("/data/parsed/info")?;
    let authority = |field: &str| -> Option<Option<String>> {
        match info.get(field)? {
            Value::Null => Some(None),
            Value::String(address) if pk(address).is_ok() => Some(Some(address.clone())),
            _ => None,
        }
    };
    let mint_authority = authority("mintAuthority")?;
    let freeze_authority = authority("freezeAuthority")?;
    // Missing Token-2022 extension information must not become a clean bill.
    if owner == PROGRAMS[4] && !info.get("extensions").is_some_and(Value::is_array) {
        return None;
    }
    let creator_holds = if creator.is_some() {
        accounts[1..]
            .iter()
            .map(|account| {
                if account.is_null() {
                    Some(0)
                } else {
                    account
                        .pointer("/data/parsed/info/tokenAmount/amount")?
                        .as_str()?
                        .parse::<u128>()
                        .ok()
                }
            })
            .sum::<Option<u128>>()
    } else {
        None
    };
    Some(MintFacts {
        supply: info.get("supply")?.as_str()?.parse().ok()?,
        decimals: u8::try_from(info.get("decimals")?.as_u64()?).ok()?,
        mint_authority,
        freeze_authority,
        extensions: match info.get("extensions") {
            Some(Value::Array(list)) => list
                .iter()
                .map(|e| {
                    e.get("extension")?
                        .as_str()
                        .filter(|name| {
                            !name.is_empty()
                                && name.len() <= 40
                                && name.chars().all(|c| c.is_ascii_alphanumeric())
                        })
                        .map(str::to_owned)
                })
                .collect::<Option<Vec<_>>>()?,
            None if owner == PROGRAMS[3] => Vec::new(),
            _ => return None,
        },
        creator_holds,
    })
}

/// The ten largest holders' share of `supply` (in whole tokens), leaving out
/// the curve and pool, and the number of holders. Pump's own index; the
/// public RPC does not serve the largest-accounts query.
fn top_holders(m: &str, excluded: &[String], supply: f64) -> Option<(f64, Option<u64>)> {
    let v = fetch("GET", format!("{TOP_HOLDERS}/{m}"), vec![]).ok()?;
    let held = v
        .get("topHolders")?
        .as_array()?
        .iter()
        .filter(|h| {
            h.get("address")
                .and_then(Value::as_str)
                .is_some_and(|a| !excluded.iter().any(|e| e == a))
        })
        .take(10)
        .map(|h| h.get("amount").and_then(Value::as_f64))
        .sum::<Option<f64>>()?;
    (supply > 0.0).then(|| {
        (
            (held / supply * 100.0).min(100.0),
            v.get("totalHolders").and_then(Value::as_u64),
        )
    })
}

/// How many other coins the creator launched, how many graduated, and
/// whether the page was full so there may be more.
fn creator_history(creator: &str, m: &str) -> Option<(usize, usize, bool)> {
    let v = fetch(
        "GET",
        format!(
            "{COIN_LISTINGS}?offset=0&limit={CREATOR_HISTORY}&sort=created_timestamp&order=DESC&includeNsfw=true&creator={creator}"
        ),
        vec![],
    )
    .ok()?;
    let coins = v.as_array()?;
    // A listing that ignored the filter would describe someone else.
    if coins
        .iter()
        .any(|c| c.get("creator").and_then(Value::as_str) != Some(creator))
    {
        return None;
    }
    let others = coins
        .iter()
        .filter(|c| c.get("mint").and_then(Value::as_str) != Some(m))
        .collect::<Vec<_>>();
    let graduated = others
        .iter()
        .filter(|c| c.get("complete").and_then(Value::as_bool) == Some(true))
        .count();
    Some((others.len(), graduated, coins.len() >= CREATOR_HISTORY))
}

/// Who bought in the block the curve was created in. The oldest page of the
/// curve's signatures ends at its creation; the successful transactions in
/// that slot are read, and each fee payer's change in its balance of the
/// mint is what it bought. `None` for a curve with too much history.
fn first_block(curve: &[u8; 32], m: &str, creator: &str) -> Option<Launch> {
    let page = post(
        RPC,
        &rpc(
            "getSignaturesForAddress",
            json!([bs58::encode(curve).into_string(), {"limit": SIGNATURE_PAGE, "commitment": COMMITMENT}]),
        ),
    )
    .ok()?;
    let signatures = page.get("result")?.as_array()?;
    if signatures.is_empty() || signatures.len() >= SIGNATURE_PAGE {
        return None;
    }
    let slot = signatures.last()?.get("slot")?.as_u64()?;
    let first = signatures
        .iter()
        .rev()
        .filter(|s| {
            s.get("slot").and_then(Value::as_u64) == Some(slot)
                && s.get("err").is_some_and(Value::is_null)
        })
        .filter_map(|s| s.get("signature")?.as_str())
        .collect::<Vec<_>>();
    let batch = first
        .iter()
        .take(LAUNCH_TRANSACTIONS)
        .enumerate()
        .map(|(id, signature)| {
            json!({"jsonrpc":"2.0","id":id,"method":"getTransaction","params":[signature,
                {"encoding":"json","maxSupportedTransactionVersion":1,"commitment":COMMITMENT}]})
        })
        .collect::<Vec<_>>();
    let replies = fetch_within(
        "POST",
        RPC.into(),
        serde_json::to_vec(&batch).ok()?,
        LAUNCH_RESPONSE_MAX,
    )
    .ok()?;
    let mut bought = BTreeMap::<String, i128>::new();
    for reply in replies.as_array()? {
        let tx = reply.get("result")?;
        let payer = tx.pointer("/transaction/message/accountKeys/0")?.as_str()?;
        let held = |list: &str| -> i128 {
            tx.pointer(&format!("/meta/{list}"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|b| {
                    b.get("mint").and_then(Value::as_str) == Some(m)
                        && b.get("owner").and_then(Value::as_str) == Some(payer)
                })
                .filter_map(|b| {
                    b.pointer("/uiTokenAmount/amount")?
                        .as_str()?
                        .parse::<i128>()
                        .ok()
                })
                .sum()
        };
        *bought.entry(payer.to_owned()).or_default() +=
            held("postTokenBalances") - held("preTokenBalances");
    }
    let others = bought
        .iter()
        .filter(|(payer, amount)| payer.as_str() != creator && **amount > 0)
        .map(|(_, amount)| *amount as u128)
        .collect::<Vec<_>>();
    Some(Launch {
        creator_bought: bought.get(creator).copied().unwrap_or(0).max(0) as u128,
        other_buyers: others.len(),
        others_bought: others.iter().sum(),
        partial: first.len() > LAUNCH_TRANSACTIONS,
    })
}

/// How far below its all-time high the coin trades, in percent, from Pump's
/// dollar figures.
fn below_high(coin: &Value) -> Option<f64> {
    let high = coin.get("ath_market_cap").and_then(Value::as_f64)?;
    let now = coin.get("usd_market_cap").and_then(Value::as_f64)?;
    (high > 0.0 && now >= 0.0).then(|| ((1.0 - now / high) * 100.0).clamp(0.0, 100.0))
}

const SWAP_API: &str = "https://swap-api.pump.fun/v2/coins";
/// Candles per chart: two minutes of seconds, two hours of minutes, ten
/// hours of five minutes, or five days of hours.
const CANDLES: usize = 120;
/// Trades listed, newest first.
const TRADES: usize = 50;

/// Price candles: SOL per whole token, with SOL volume.
pub(crate) struct Candle {
    pub time_ms: u64,
    pub open: f64,
    pub high: f64,
    pub low: f64,
    pub close: f64,
    pub volume: f64,
}

pub(crate) struct Chart {
    pub interval: &'static str,
    pub interval_ms: u64,
    /// Whole tokens in supply, to turn a price into a market cap.
    pub supply: f64,
    pub candles: Vec<Candle>,
}

/// The candle interval that fits a coin's age into one chart.
fn interval_for(age_ms: u64) -> (&'static str, u64) {
    match age_ms / 60_000 {
        0..2 => ("1s", 1_000),
        2..120 => ("1m", 60_000),
        120..600 => ("5m", 300_000),
        _ => ("1h", 3_600_000),
    }
}

fn chart(m: &str) -> Result<Chart, DispatchResponse> {
    pk(m).map_err(|_| bad("invalid mint"))?;
    chart_from(m, &fetch("GET", format!("{COINS}/{m}"), vec![])?)
}
/// Candles for a coin whose Pump record is already in hand.
pub(crate) fn chart_from(m: &str, coin: &Value) -> Result<Chart, DispatchResponse> {
    let created = coin
        .get("created_timestamp")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let (interval, interval_ms) = interval_for(host::now_ms().saturating_sub(created));
    let decimals = coin
        .get("base_decimals")
        .and_then(Value::as_u64)
        .filter(|d| *d <= 12)
        .unwrap_or(6) as i32;
    let supply = coin
        .get("total_supply")
        .and_then(|s| s.as_f64().or_else(|| s.as_str()?.parse().ok()))
        .ok_or_else(|| fail("Pump did not report the coin's supply"))?
        / 10f64.powi(decimals);
    let rows = fetch(
        "GET",
        format!(
            "{SWAP_API}/{m}/candles?interval={interval}&limit={CANDLES}&currency=SOL&createdTs={created}"
        ),
        vec![],
    )?;
    let number = |row: &Value, field: &str| {
        row.get(field)
            .and_then(|v| v.as_str()?.parse::<f64>().ok().or(v.as_f64()))
            .filter(|n| n.is_finite() && *n >= 0.0)
    };
    let mut candles = rows
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|row| {
            let candle = Candle {
                time_ms: row.get("timestamp")?.as_u64()?,
                open: number(row, "open")?,
                high: number(row, "high")?,
                low: number(row, "low")?,
                close: number(row, "close")?,
                volume: number(row, "volume")?,
            };
            (candle.low > 0.0 && candle.low <= candle.high).then_some(candle)
        })
        .take(CANDLES)
        .collect::<Vec<_>>();
    candles.sort_by_key(|c| c.time_ms);
    candles.dedup_by_key(|c| c.time_ms);
    Ok(Chart {
        interval,
        interval_ms,
        supply,
        candles,
    })
}

/// `market/<mint>/candles.json`: recent price candles, at an interval chosen
/// from the coin's age.
pub fn candles(m: &str) -> DispatchResponse {
    let chart = match chart(m) {
        Ok(chart) => chart,
        Err(e) => return e,
    };
    let change = match (chart.candles.first(), chart.candles.last()) {
        (Some(first), Some(last)) if first.open > 0.0 => {
            Some((last.close / first.open - 1.0) * 100.0)
        }
        _ => None,
    };
    petal::read_json_value(&json!({
        "mint": m,
        "interval": chart.interval,
        "columns": ["timeMs", "open", "high", "low", "close", "volumeSol"],
        "candles": chart.candles.iter().map(|c| json!([c.time_ms, c.open, c.high, c.low, c.close, c.volume])).collect::<Vec<_>>(),
        "changePct": change,
        "supplyTokens": chart.supply,
        "note": "Prices are SOL per whole token from Pump's trade index; multiply by supplyTokens for the market cap. Minutes without trades have no candle.",
    }))
}

/// `market/<mint>/trades.json`: the latest trades, newest first, with who
/// traded and a tally of buying against selling.
pub fn trades(m: &str) -> DispatchResponse {
    match trades_value(m) {
        Ok(v) => petal::read_json_value(&v),
        Err(e) => e,
    }
}
pub(crate) fn trades_value(m: &str) -> Result<Value, DispatchResponse> {
    pk(m).map_err(|_| bad("invalid mint"))?;
    let v = fetch(
        "GET",
        format!("{SWAP_API}/{m}/trades?limit={TRADES}"),
        vec![],
    )?;
    let number = |t: &Value, field: &str| {
        t.get(field)
            .and_then(Value::as_str)
            .and_then(|n| n.parse::<f64>().ok())
            .filter(|n| n.is_finite() && *n >= 0.0)
    };
    let trades = v
        .get("trades")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|t| {
            let side = match t.get("type")?.as_str()? {
                "buy" => "buy",
                "sell" => "sell",
                _ => return None,
            };
            let wallet = t.get("userAddress")?.as_str().filter(|a| pk(a).is_ok())?;
            let tx = t.get("tx")?.as_str().filter(|s| {
                (64..=90).contains(&s.len()) && bs58::decode(s).into_vec().is_ok()
            })?;
            Some(json!({
                "time": t.get("timestamp")?.as_str().filter(|s| s.len() <= 32 && s.bytes().all(|b| b.is_ascii_graphic()))?,
                "side": side,
                "sol": number(t, "amountSol")?,
                "tokens": number(t, "baseAmount")?,
                "priceSol": number(t, "priceSol"),
                "venue": match t.get("program").and_then(Value::as_str) {
                    Some("pump") => "curve",
                    Some("pump_amm") => "pool",
                    _ => "other",
                },
                "wallet": wallet,
                "tx": tx,
            }))
        })
        .take(TRADES)
        .collect::<Vec<_>>();
    let total = |side: &str| {
        trades
            .iter()
            .filter(|t| t["side"] == side)
            .filter_map(|t| t["sol"].as_f64())
            .sum::<f64>()
    };
    let count = |side: &str| trades.iter().filter(|t| t["side"] == side).count();
    Ok(json!({
        "mint": m,
        "buys": count("buy"),
        "sells": count("sell"),
        "boughtSol": total("buy"),
        "soldSol": total("sell"),
        "trades": trades,
        "note": "Pump's trade index, newest first. Sums cover only the trades listed.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_host::{self, FakeHost};

    const MINT: &str = "C8CMvu8FXZruHrNjFaixaDJjiveG6gKmUvT5BrK5pump";
    const WALLET: &str = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF";
    const TX: &str =
        "2H3Dikr12qk9PWTGUvsMvaEG7aFjtAoVXEZNyWcXxpnMChW6MBCTx9V5jM1mcLVxoxQN5SadMsqLUZjHiUA1wShi";
    const NOW_MS: u64 = 1_790_000_000_000;

    fn bytes_of(response: DispatchResponse) -> Vec<u8> {
        match response {
            DispatchResponse::Read(bytes) => bytes,
            other => panic!("{other:?}"),
        }
    }

    fn coin_aged(host: &mut FakeHost, minutes: u64) -> u64 {
        let created = NOW_MS - minutes * 60_000;
        host.reply(
            &format!("{COINS}/{MINT}"),
            json!({"symbol": "<MOG>", "created_timestamp": created,
                "total_supply": 1_000_000_000_000_000u64, "base_decimals": 6}),
        );
        created
    }

    fn candle(time_ms: u64, open: &str, close: &str) -> Value {
        json!({"timestamp": time_ms, "open": open, "high": "0.00000004", "low": "0.00000001",
            "close": close, "volume": "1.5"})
    }

    /// A young coin is charted in minutes and an old one in hours, so either
    /// fits one chart; malformed candles are dropped.
    #[test]
    fn candles_fit_the_coin_age_and_drop_malformed_rows() {
        for (minutes, interval) in [(1, "1s"), (30, "1m"), (5 * 60, "5m"), (3 * 24 * 60, "1h")] {
            let mut host = FakeHost::new(NOW_MS);
            let created = coin_aged(&mut host, minutes);
            host.reply(
                &format!("{SWAP_API}/{MINT}/candles?interval={interval}&limit=120&currency=SOL&createdTs={created}"),
                json!([
                    candle(NOW_MS - 120_000, "0.00000002", "0.00000003"),
                    candle(NOW_MS - 60_000, "NaN", "0.00000003"),
                    {"timestamp": NOW_MS, "open": "0.00000003"},
                    candle(NOW_MS, "0.00000003", "0.00000003"),
                ]),
            );
            fake_host::install(host);
            let v: Value = serde_json::from_slice(&bytes_of(candles(MINT))).unwrap();
            assert_eq!(v["interval"], json!(interval));
            assert_eq!(v["candles"].as_array().unwrap().len(), 2);
            assert!((v["changePct"].as_f64().unwrap() - 50.0).abs() < 1e-9);
            assert_eq!(v["supplyTokens"], json!(1e9));
        }
    }

    /// Trades keep only well-formed buys and sells, and tally them.
    #[test]
    fn trades_are_projected_and_tallied() {
        let mut host = FakeHost::new(NOW_MS);
        let trade = |side: &str, sol: &str, wallet: &str, tx: &str| {
            json!({"type": side, "amountSol": sol, "baseAmount": "1000", "priceSol": "0.0000001",
                "timestamp": "2026-09-29T01:04:34.000Z", "program": "pump",
                "userAddress": wallet, "tx": tx})
        };
        host.reply(
            &format!("{SWAP_API}/{MINT}/trades?limit=50"),
            json!({"trades": [
                trade("buy", "0.5", WALLET, TX),
                trade("sell", "0.2", WALLET, TX),
                trade("sell", "9", "not a wallet", TX),
                trade("mint", "9", WALLET, TX),
                trade("buy", "9", WALLET, "<script>"),
            ]}),
        );
        fake_host::install(host);
        let v: Value = serde_json::from_slice(&bytes_of(trades(MINT))).unwrap();
        assert_eq!(v["trades"].as_array().unwrap().len(), 2);
        assert_eq!(
            (v["buys"].clone(), v["sells"].clone()),
            (json!(1), json!(1))
        );
        assert_eq!(v["boughtSol"], json!(0.5));
        assert_eq!(v["trades"][0]["venue"], json!("curve"));
    }

    #[test]
    fn an_invalid_mint_is_refused_before_any_request() {
        fake_host::install(FakeHost::new(NOW_MS));
        for response in [candles("x/../y"), trades("x?y")] {
            assert!(
                matches!(response, DispatchResponse::Error { .. }),
                "{response:?}"
            );
        }
        fake_host::with(|host| assert!(host.calls.is_empty()));
    }

    #[test]
    fn missing_or_malformed_mint_facts_remain_unchecked() {
        let valid = json!({"supply":"1000000000000000","decimals":6,"mintAuthority":null,"freezeAuthority":null,"extensions":[]});
        let mut cases = Vec::new();
        for field in ["mintAuthority", "freezeAuthority", "extensions"] {
            let mut info = valid.clone();
            info.as_object_mut().unwrap().remove(field);
            cases.push(info);
        }
        let mut bad_authority = valid.clone();
        bad_authority["mintAuthority"] = json!("invalid");
        cases.push(bad_authority);
        let mut bad_extension = valid.clone();
        bad_extension["extensions"] = json!([{}]);
        cases.push(bad_extension);
        for info in cases {
            let mut host = FakeHost::new(NOW_MS);
            host.chain.accounts.insert(
                MINT.into(),
                json!({"owner":PROGRAMS[4],"data":{"parsed":{"info":info}}}),
            );
            fake_host::install(host);
            let result = risk(&pk(MINT).unwrap(), MINT, &json!({}), None, None);
            assert!(
                result.report["unchecked"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("mint"))
            );
            assert!(result.report["tokenExtensions"].is_null());
        }
    }

    #[test]
    fn explicit_absent_authorities_and_known_extensions_can_be_read() {
        let mut host = FakeHost::new(NOW_MS);
        host.chain.accounts.insert(MINT.into(), json!({"owner":PROGRAMS[4],"data":{"parsed":{"info":
            {"supply":"1000000","decimals":6,"mintAuthority":null,"freezeAuthority":null,"extensions":[{"extension":"metadataPointer"},{"extension":"tokenMetadata"}]}}}}));
        fake_host::install(host);
        let facts = mint_facts(&pk(MINT).unwrap(), None).unwrap();
        assert!(facts.mint_authority.is_none() && facts.freeze_authority.is_none());
        assert_eq!(facts.extensions, vec!["metadataPointer", "tokenMetadata"]);
    }
}
