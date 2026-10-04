//! Views for people. Every data file has a JSON form for agents; these lay
//! the same facts out to read: Markdown that reads well from `cat` in a
//! terminal, and self-contained HTML pages that open in a browser from the
//! mounted folder and link to one another.
//!
//! Everything a coin's creator chose (name, symbol) is escaped for the format
//! it lands in. Every page carries a Content-Security-Policy that allows no
//! network access at all except coin images from the public IPFS gateway, so
//! a page can neither load nor send anything else.

use super::*;
use crate::insight::{Candle, Chart};
use std::collections::BTreeMap;

/// Columns and rows of a terminal chart.
const TEXT_CHART_WIDTH: usize = 64;
const TEXT_CHART_HEIGHT: usize = 12;
/// Trades shown on a coin's page.
const PAGE_TRADES: usize = 25;
/// Holdings whose names are looked up, one request each.
const NAMED_HOLDINGS: usize = 20;
const PAGE_WIDTH: f64 = 1000.0;
const PAGE_HEIGHT: f64 = 340.0;

#[derive(Clone, Copy, PartialEq)]
pub enum Format {
    Markdown,
    Html,
}

// ---------------------------------------------------------------- listings

pub fn listing(listing: Listing, format: Format) -> DispatchResponse {
    listing_at(listing, format, "")
}

/// The petal's front page: the newest coins, linking into `coins/`.
pub fn front_page() -> DispatchResponse {
    listing_at(Listing::Latest, Format::Html, "coins/")
}

/// A listing whose links are relative to `prefix`, the path from the page
/// to the `coins/` directory.
fn listing_at(listing: Listing, format: Format, prefix: &str) -> DispatchResponse {
    let data = match listing_value(listing) {
        Ok(data) => data,
        Err(e) => return unavailable(&e, format, prefix),
    };
    let coins = data["coins"].as_array().cloned().unwrap_or_default();
    let now = host::now_ms();
    let (title, other, other_label, this) = match listing {
        Listing::Latest => ("Newest coins", "live", "Live now", "latest"),
        Listing::Live => ("Live now", "latest", "Newest coins", "live"),
    };
    match format {
        Format::Markdown => {
            let mut out = format!(
                "# Pump.fun · {title}\n\n{} · {} coins · open a coin with `cat coins/<mint>.md` · also: coins/{other}.md\n\n",
                stamp(now),
                coins.len()
            );
            let rows = coins
                .iter()
                .enumerate()
                .map(|(index, coin)| {
                    vec![
                        (index + 1).to_string(),
                        format!(
                            "{} {}",
                            cell(coin["symbol"].as_str().unwrap_or("?")),
                            cell(coin["name"].as_str().unwrap_or(""))
                        ),
                        market_cap_cell(coin),
                        progress_cell(coin),
                        age_since(coin["createdMs"].as_u64(), now),
                        age_since(coin["lastTradeMs"].as_u64(), now),
                        coin["mint"].as_str().unwrap_or("").to_owned(),
                    ]
                })
                .collect::<Vec<_>>();
            out.push_str(&table(
                &[
                    "#",
                    "Coin",
                    "Market cap",
                    "Curve",
                    "Age",
                    "Last trade",
                    "Mint",
                ],
                &[true, false, true, false, true, true, false],
                &rows,
            ));
            out.push_str(
                "\nNames and symbols are the creators' own and are not unique; trade by mint.\n",
            );
            markdown(out)
        }
        Format::Html => {
            let cards = coins
                .iter()
                .map(|coin| {
                    let mint = coin["mint"].as_str().unwrap_or("");
                    let symbol = coin["symbol"].as_str().unwrap_or("?");
                    let progress = coin["curveProgressPct"].as_f64();
                    let status = if let Some(label) = quote_label(coin) {
                        format!("<span class=pill>{label}</span>")
                    } else if coin["graduated"] == json!(true) {
                        "<span class=pill>graduated</span>".to_owned()
                    } else {
                        format!("<span class=muted>{:.0}% to graduation</span>", progress.unwrap_or(0.0))
                    };
                    format!(
                        "<a class=card href=\"{prefix}{mint}.html\"><div class=coin>{avatar}<div class=grow><div class=sym>{sym}</div><div class=name>{name}</div></div><div class=right><div class=v>{cap}</div><div class=muted>{usd}</div></div></div>{bar}<div class=row><span>{status}</span><span>{age} old · {last}</span></div></a>",
                        avatar = avatar(coin["image"].as_str(), symbol, 44),
                        sym = html(symbol),
                        name = html(coin["name"].as_str().unwrap_or("")),
                        cap = coin["marketCapSol"].as_f64().map(sol).unwrap_or_else(|| "—".into()),
                        usd = coin["marketCapUsd"].as_f64().map(usd).unwrap_or_default(),
                        bar = progress
                            .map(|p| format!("<div class=bar><i style=\"width:{p:.1}%\"></i></div>"))
                            .unwrap_or_default(),
                        age = age_since(coin["createdMs"].as_u64(), now),
                        last = match coin["lastTradeMs"].as_u64() {
                            Some(ms) => format!("traded {} ago", age_since(Some(ms), now)),
                            None => "no trades yet".to_owned(),
                        },
                    )
                })
                .collect::<String>();
            page(
                &format!("Pump.fun · {title}"),
                &nav_from(prefix, this),
                &format!(
                    "<header class=head><h1>{title}</h1><p class=muted>{} · {} coins · <a href=\"{prefix}{other}.html\">{other_label} →</a></p></header><div class=grid>{cards}</div><p class=muted>Names, symbols and images are the creators' own and are not unique. Trade by mint, after reading the coin's page.</p>",
                    stamp(now),
                    coins.len()
                ),
                "",
            )
        }
    }
}

/// The token a coin is priced in, when it is not SOL.
fn quote_label(coin: &Value) -> Option<&'static str> {
    (coin["quotedInSol"] == json!(false)).then(|| match coin["quoteMint"].as_str() {
        Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v") => "USDC pair",
        _ => "non-SOL pair",
    })
}

fn market_cap_cell(coin: &Value) -> String {
    if let Some(label) = quote_label(coin) {
        return label.into();
    }
    coin["marketCapSol"]
        .as_f64()
        .map(sol)
        .unwrap_or_else(|| "—".into())
}

fn progress_cell(coin: &Value) -> String {
    if coin["graduated"] == json!(true) {
        return "graduated".into();
    }
    match coin["curveProgressPct"].as_f64() {
        Some(pct) => format!("{} {pct:>3.0}%", meter(pct, 8)),
        None => "—".into(),
    }
}

// ------------------------------------------------------------------- coin

pub fn coin_page(m: &str, format: Format) -> DispatchResponse {
    // An invalid mint is the reader's mistake, not an outage.
    if pk(m).is_err() {
        return bad("invalid mint");
    }
    let (summary, record) = match coin_value(m) {
        Ok(found) => found,
        Err(e) => return unavailable(&e, format, ""),
    };
    // A page is still worth showing without its chart or trades.
    let chart = insight::chart_from(m, &record).ok();
    let trades = insight::trades_value(m).ok();
    let now = host::now_ms();
    match format {
        Format::Markdown => markdown(coin_markdown(
            m,
            &summary,
            chart.as_ref(),
            trades.as_ref(),
            now,
        )),
        Format::Html => {
            let symbol = summary["symbol"].as_str().unwrap_or("?");
            page(
                &format!("{symbol} · Pump.fun"),
                &nav(""),
                &coin_html(m, &summary, chart.as_ref(), trades.as_ref(), now),
                CHART_SCRIPT,
            )
        }
    }
}

/// One line of a coin's checklist.
#[derive(Clone, Copy, PartialEq)]
enum Level {
    Pass,
    Warn,
    Unknown,
}

/// The coin's risks as a checklist: every warning, then what was checked and
/// found fine, then what could not be checked.
fn checklist(summary: &Value) -> Vec<(Level, String)> {
    let risk = &summary["risk"];
    let mut items = summary["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|w| (Level::Warn, w.to_owned()))
        .collect::<Vec<_>>();
    let warned = |needle: &str| items.iter().any(|(_, w)| w.contains(needle));
    let mut passes = Vec::new();
    let mut unknown = Vec::new();
    if !risk["tokenExtensions"].is_null()
        && risk["mintAuthority"].is_null()
        && risk["freezeAuthority"].is_null()
        && !warned("extensions")
    {
        passes
            .push("No one can mint more, freeze holders' tokens or charge on transfers".to_owned());
    }
    if let Some(pct) = risk["creatorHoldsPct"].as_f64()
        && !warned("creator still holds")
        && !warned("now holds")
    {
        passes.push(format!("The creator's associated token accounts hold {}; other accounts and related wallets are not checked", share(pct)));
    }
    if let Some(pct) = risk["top10HoldPct"].as_f64()
        && !warned("10 largest")
    {
        passes.push(format!(
            "Pump's index reports the 10 largest holders own {}; the index may lag",
            share(pct)
        ));
    }
    if risk["launchBlockPartial"].as_bool() == Some(true) {
        unknown.push((Level::Unknown, format!(
            "Partial launch sample: {} other fee payer(s) bought {} in the transactions inspected; the rest were not checked",
            risk["launchBlockBuyers"].as_u64().unwrap_or(0),
            share(risk["launchBlockBoughtPct"].as_f64().unwrap_or(0.0))
        )));
    } else if risk["launchBlockBuyers"].as_u64().is_some() && !warned("bundled") {
        passes.push(match risk["launchBlockBuyers"].as_u64() {
            Some(0) => {
                "No other fee payer bought in the inspected creation-block transactions".to_owned()
            }
            Some(n) => format!(
                "{n} other wallet(s) bought {} in the creation block",
                share(risk["launchBlockBoughtPct"].as_f64().unwrap_or(0.0))
            ),
            None => unreachable!(),
        });
    }
    if let (Some(others), Some(graduated)) = (
        risk["creatorOtherCoins"].as_u64(),
        risk["creatorGraduatedCoins"].as_u64(),
    ) && !warned("none graduated")
    {
        passes.push(match others {
            0 => "Pump's index lists no other coin for this creator".to_owned(),
            _ if others >= 49 => {
                format!("The creator has launched 49+ other coins; {graduated} graduated")
            }
            _ => format!("The creator has launched {others} other coin(s); {graduated} graduated"),
        });
    }
    items.extend(passes.into_iter().map(|p| (Level::Pass, p)));
    items.extend(unknown);
    for check in risk["unchecked"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let what = match check {
            "mint" => "the mint's authorities",
            "creatorHolds" => "the creator's holding",
            "holders" => "the largest holders",
            "creatorHistory" => "the creator's other coins",
            "launch" => "who bought in the launch block (unavailable or outside the history limit)",
            other => other,
        };
        items.push((Level::Unknown, format!("Could not check {what}")));
    }
    items
}

fn coin_markdown(
    m: &str,
    summary: &Value,
    chart: Option<&Chart>,
    trades: Option<&Value>,
    now: u64,
) -> String {
    let symbol = cell(summary["symbol"].as_str().unwrap_or("?"));
    let name = cell(summary["name"].as_str().unwrap_or(""));
    let title = if name.is_empty() || name.eq_ignore_ascii_case(&symbol) {
        symbol.clone()
    } else {
        format!("{symbol} · {name}")
    };
    let mut out = format!("# {title}\n\n`{m}`\n\n");
    out.push_str(&format!(
        "{} · launched {} ago · holders: {} · {}\n\n",
        status_text(summary),
        age_since(summary["createdMs"].as_u64(), now),
        holders_text(summary),
        stamp(now)
    ));
    out.push_str(&table(
        &["Market cap", "Price", "Curve", "Below high"],
        &[true, true, false, true],
        &[vec![
            cap_text(summary),
            summary["priceSol"]
                .as_f64()
                .map(price)
                .unwrap_or_else(|| "—".into()),
            curve_text(summary),
            summary["risk"]["belowAllTimeHighPct"]
                .as_f64()
                .map(|p| format!("{p:.0}%"))
                .unwrap_or_else(|| "—".into()),
        ]],
    ));
    match chart.filter(|c| c.candles.len() >= 2) {
        Some(chart) => out.push_str(&format!(
            "\n## Market cap in SOL · {} candles · {}\n\n```text\n{}```\n",
            chart.interval,
            change_text(chart),
            text_chart(chart, now)
        )),
        None => out.push_str("\n## Market cap\n\nNot enough trading to chart yet.\n"),
    }
    out.push_str("\n## Checks\n\n");
    for (level, text) in checklist(summary) {
        let mark = match level {
            Level::Pass => "✓",
            Level::Warn => "⚠",
            Level::Unknown => "?",
        };
        out.push_str(&format!("{mark} {}\n", cell(&text)));
    }
    if let Some(trades) = trades {
        let list = trades["trades"].as_array().cloned().unwrap_or_default();
        out.push_str(&format!(
            "\n## Latest trades · {} buys {} · {} sells {}\n\n",
            trades["buys"],
            sol(trades["boughtSol"].as_f64().unwrap_or(0.0)),
            trades["sells"],
            sol(trades["soldSol"].as_f64().unwrap_or(0.0)),
        ));
        if list.is_empty() {
            out.push_str("No trades yet.\n");
        }
        let rows = list
            .iter()
            .take(PAGE_TRADES)
            .map(|t| {
                let side = t["side"].as_str().unwrap_or("");
                vec![
                    iso_ms(t["time"].as_str().unwrap_or(""))
                        .map(|ms| format!("{} ago", age_since(Some(ms), now)))
                        .unwrap_or_default(),
                    if side == "buy" {
                        "▲ buy".into()
                    } else {
                        "▼ sell".into()
                    },
                    sol(t["sol"].as_f64().unwrap_or(0.0)),
                    compact(t["tokens"].as_f64().unwrap_or(0.0)),
                    short(t["wallet"].as_str().unwrap_or("")),
                ]
            })
            .collect::<Vec<_>>();
        if !rows.is_empty() {
            out.push_str(&table(
                &["When", "Side", "SOL", "Tokens", "Wallet"],
                &[true, false, true, true, false],
                &rows,
            ));
        }
    }
    out.push_str(&format!(
        "\n## Trade\n\nBuy 0.01 SOL of it (the amount is in lamports) from the mounted folder:\n\n    echo '{{\"operationId\":\"buy-1\",\"mint\":\"{m}\",\"amount\":\"10000000\"}}' > trade/<wallet>/buy.json\n\nSell with `sell.json` and `\"amount\":\"all\"` or `\"50%\"`. Every trade waits for your approval in Bloom.\n\nNames and links are the creator's own; prices, authorities and the creator's holding are read from the chain; holders and the creator's other coins are Pump's figures.\n"
    ));
    out
}

fn coin_html(
    m: &str,
    summary: &Value,
    chart: Option<&Chart>,
    trades: Option<&Value>,
    now: u64,
) -> String {
    let symbol = summary["symbol"].as_str().unwrap_or("?");
    let mut out = format!(
        "<header class=\"head coinhead\">{avatar}<div><h1>{sym} <span class=muted>{name}</span></h1><div class=muted><code id=mint>{m}</code> <button id=copy type=button>Copy</button></div><div class=tags><span class=pill>{status}</span><span class=pill>launched {age} ago</span><span class=pill>{stamp}</span></div></div></header>",
        avatar = avatar(summary["image"].as_str(), symbol, 72),
        sym = html(symbol),
        name = html(
            summary["name"]
                .as_str()
                .filter(|n| !n.eq_ignore_ascii_case(symbol))
                .unwrap_or("")
        ),
        status = html(&status_text(summary)),
        age = age_since(summary["createdMs"].as_u64(), now),
        stamp = stamp(now),
    );
    let stat = |k: &str, v: String| {
        format!("<div class=\"card stat\"><div class=k>{k}</div><div class=v>{v}</div></div>")
    };
    out.push_str("<section class=stats>");
    out.push_str(&stat(
        "Market cap",
        format!(
            "{}<div class=sub>{}</div>",
            html(&cap_text(summary)),
            summary["marketCapUsd"]
                .as_f64()
                .map(usd)
                .unwrap_or_default()
        ),
    ));
    out.push_str(&stat(
        "Price",
        summary["priceSol"]
            .as_f64()
            .map(price)
            .unwrap_or_else(|| "—".into()),
    ));
    out.push_str(&stat(
        "Curve",
        match summary["curveProgressPct"].as_f64() {
            Some(p) => format!("{p:.0}%<div class=bar><i style=\"width:{p:.1}%\"></i></div>"),
            None => html(&curve_text(summary)),
        },
    ));
    out.push_str(&stat("Holders", html(&holders_text(summary))));
    out.push_str(&stat(
        "Below high",
        summary["risk"]["belowAllTimeHighPct"]
            .as_f64()
            .map(|p| format!("{p:.0}%"))
            .unwrap_or_else(|| "—".into()),
    ));
    out.push_str("</section>");
    match chart.filter(|c| c.candles.len() >= 2) {
        Some(chart) => {
            let change = change_pct(chart);
            out.push_str(&format!(
                "<section class=card><div class=charthead><span>Market cap in SOL · {} candles</span><span class={}>{}</span></div>{}</section>",
                chart.interval,
                if change >= 0.0 { "buy" } else { "sell" },
                html(&change_text(chart)),
                svg_chart(chart, now)
            ));
        }
        None => out.push_str(
            "<section class=\"card empty\">Not enough trading to chart yet. Reload once the coin has traded more.</section>",
        ),
    }
    out.push_str("<div class=cols><section><h2>Checks</h2><ul class=checks>");
    for (level, text) in checklist(summary) {
        let (class, mark) = match level {
            Level::Pass => ("ok", "✓"),
            Level::Warn => ("warn", "⚠"),
            Level::Unknown => ("unknown", "?"),
        };
        out.push_str(&format!(
            "<li class={class}><b>{mark}</b><span>{}</span></li>",
            html(&text)
        ));
    }
    out.push_str(&format!(
        "</ul><h2>Trade</h2><p class=muted>Buy 0.01 SOL of it (the amount is in lamports) from the petal's mounted folder. Every trade waits for your approval in Bloom.</p><pre class=snippet>echo '{{\"operationId\":\"buy-1\",\"mint\":\"{m}\",\"amount\":\"10000000\"}}' &gt; trade/&lt;wallet&gt;/buy.json</pre><p class=muted>Sell with <code>sell.json</code> and <code>\"amount\":\"all\"</code> or <code>\"50%\"</code>.</p><p><a href=\"https://pump.fun/coin/{m}\" rel=noreferrer>pump.fun</a> · <a href=\"https://solscan.io/token/{m}\" rel=noreferrer>Solscan</a></p></section>"
    ));
    if let Some(trades) = trades {
        let list = trades["trades"].as_array().cloned().unwrap_or_default();
        out.push_str(&format!(
            "<section><h2>Latest trades</h2><p class=muted><span class=buy>{} buys · {}</span> &nbsp; <span class=sell>{} sells · {}</span></p><table><thead><tr><th>When</th><th>Side</th><th class=num>SOL</th><th class=num>Tokens</th><th>Wallet</th></tr></thead><tbody>",
            trades["buys"],
            sol(trades["boughtSol"].as_f64().unwrap_or(0.0)),
            trades["sells"],
            sol(trades["soldSol"].as_f64().unwrap_or(0.0)),
        ));
        for t in list.iter().take(PAGE_TRADES) {
            let side = if t["side"] == json!("buy") {
                "buy"
            } else {
                "sell"
            };
            let wallet = t["wallet"].as_str().unwrap_or("");
            let tx = t["tx"].as_str().unwrap_or("");
            out.push_str(&format!(
                "<tr><td><a href=\"https://solscan.io/tx/{tx}\" rel=noreferrer>{when}</a></td><td class={side}>{arrow} {side}</td><td class=num>{sol}</td><td class=num>{tokens}</td><td><a href=\"https://solscan.io/account/{wallet}\" rel=noreferrer><code>{short}</code></a></td></tr>",
                when = iso_ms(t["time"].as_str().unwrap_or(""))
                    .map(|ms| format!("{} ago", age_since(Some(ms), now)))
                    .unwrap_or_default(),
                arrow = if side == "buy" { "▲" } else { "▼" },
                sol = sol(t["sol"].as_f64().unwrap_or(0.0)),
                tokens = compact(t["tokens"].as_f64().unwrap_or(0.0)),
                short = short(wallet),
            ));
        }
        out.push_str("</tbody></table>");
        if list.is_empty() {
            out.push_str("<p class=\"card empty\">No trades yet.</p>");
        }
        out.push_str("</section>");
    }
    out.push_str("</div><p class=muted>Names and images are the creator's own. Prices, authorities and the creator's holding are read from the chain; holders and the creator's other coins are Pump's figures.</p>");
    out
}

/// The market cap: in SOL when it can be priced in SOL, otherwise in the
/// token the coin is priced in.
fn cap_text(summary: &Value) -> String {
    if let Some(cap) = summary["marketCapSol"].as_f64() {
        return sol(cap);
    }
    let quote = &summary["quote"];
    match (quote["marketCap"].as_f64(), quote["symbol"].as_str()) {
        (Some(cap), Some(symbol)) => format!("{} {}", sol_short(cap), symbol),
        _ => "—".into(),
    }
}

/// Pump's holder count, which is zero until its index catches up.
fn holders_text(summary: &Value) -> String {
    match summary["risk"]["holders"].as_u64() {
        Some(0) | None => "not counted yet".into(),
        Some(count) => count.to_string(),
    }
}

fn status_text(summary: &Value) -> String {
    if let Some(symbol) = summary["quote"]["symbol"].as_str() {
        format!("priced in {symbol} · not tradable here")
    } else if summary["priceSol"].is_null() {
        "not tradable here".into()
    } else if summary["graduated"] == json!(true) {
        "graduated to PumpSwap".into()
    } else {
        "on its bonding curve".into()
    }
}

fn curve_text(summary: &Value) -> String {
    match summary["curveProgressPct"].as_f64() {
        Some(p) => format!("{} {p:.0}%", meter(p, 10)),
        None if summary["graduated"] == json!(true) => "graduated".into(),
        None => "—".into(),
    }
}

fn change_pct(chart: &Chart) -> f64 {
    match (chart.candles.first(), chart.candles.last()) {
        (Some(first), Some(last)) if first.open > 0.0 => (last.close / first.open - 1.0) * 100.0,
        _ => 0.0,
    }
}

fn change_text(chart: &Chart) -> String {
    let span = chart
        .candles
        .last()
        .zip(chart.candles.first())
        .map(|(last, first)| last.time_ms - first.time_ms + chart.interval_ms)
        .unwrap_or(0);
    format!("{:+.1}% over {}", change_pct(chart), duration(span))
}

/// Closing market caps, one per column, carried forward over minutes
/// without trades, from the first candle to the last.
fn columns(chart: &Chart, width: usize) -> Vec<f64> {
    let (Some(first), Some(last)) = (chart.candles.first(), chart.candles.last()) else {
        return Vec::new();
    };
    let span = (last.time_ms - first.time_ms + chart.interval_ms).max(1) as f64;
    let mut values = vec![None; width];
    for c in &chart.candles {
        let column = (((c.time_ms - first.time_ms) as f64 / span) * width as f64) as usize;
        values[column.min(width - 1)] = Some(c.close * chart.supply);
    }
    let mut last_seen = first.open * chart.supply;
    values
        .into_iter()
        .map(|v| {
            if let Some(v) = v {
                last_seen = v;
            }
            last_seen
        })
        .collect()
}

/// A scale over `values`: logarithmic once the range passes twentyfold,
/// which keeps a coin that moved a hundredfold readable.
struct Scale {
    low: f64,
    high: f64,
    log: bool,
}
impl Scale {
    fn over(values: impl Iterator<Item = f64>) -> Self {
        let (mut low, mut high) = (f64::INFINITY, f64::NEG_INFINITY);
        for v in values.filter(|v| *v > 0.0 && v.is_finite()) {
            low = low.min(v);
            high = high.max(v);
        }
        if !low.is_finite() {
            return Self {
                low: 0.0,
                high: 1.0,
                log: false,
            };
        }
        let log = high / low > 20.0;
        // A range under a tenth of the price is drawn as a tenth, so a coin
        // that barely moved looks flat instead of stretched to full height.
        let mid = (high + low) / 2.0;
        if high - low < mid * 0.1 {
            low = low.min(mid * 0.95);
            high = high.max(mid * 1.05);
        }
        Self { low, high, log }
    }
    /// Where `v` falls, from 0 at the bottom to 1 at the top.
    fn at(&self, v: f64) -> f64 {
        let f = |x: f64| if self.log { x.max(1e-300).ln() } else { x };
        ((f(v) - f(self.low)) / (f(self.high) - f(self.low))).clamp(0.0, 1.0)
    }
    fn value(&self, fraction: f64) -> f64 {
        if self.log {
            (self.low.ln() + (self.high.ln() - self.low.ln()) * fraction).exp()
        } else {
            self.low + (self.high - self.low) * fraction
        }
    }
}

/// A block chart for a terminal: each column is filled to its closing
/// market cap in eighths of a row.
fn text_chart(chart: &Chart, now: u64) -> String {
    const BLOCKS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let values = columns(chart, TEXT_CHART_WIDTH);
    let scale = Scale::over(values.iter().copied());
    let eighths = values
        .iter()
        .map(|v| (scale.at(*v) * (TEXT_CHART_HEIGHT * 8 - 1) as f64).round() as usize + 1)
        .collect::<Vec<_>>();
    let mut out = String::new();
    for row in (0..TEXT_CHART_HEIGHT).rev() {
        let label = match row {
            r if r == TEXT_CHART_HEIGHT - 1 => sol_short(scale.high),
            r if r == TEXT_CHART_HEIGHT / 2 => sol_short(scale.value(0.5)),
            0 => sol_short(scale.low),
            _ => String::new(),
        };
        let tick = if label.is_empty() { '│' } else { '┤' };
        out.push_str(&format!("{label:>8} {tick}"));
        for filled in &eighths {
            let level = filled.saturating_sub(row * 8).min(8);
            out.push(BLOCKS[level]);
        }
        out.push('\n');
    }
    out.push_str(&format!("{:>8} └{}\n", "", "─".repeat(TEXT_CHART_WIDTH)));
    let left = format!(
        "{} ago",
        age_since(chart.candles.first().map(|c| c.time_ms), now)
    );
    let right = format!(
        "{} ago",
        age_since(chart.candles.last().map(|c| c.time_ms), now)
    );
    out.push_str(&format!(
        "{:>8}  {left}{}{right}\n",
        "",
        " ".repeat(TEXT_CHART_WIDTH.saturating_sub(left.chars().count() + right.chars().count()))
    ));
    out
}

/// An area chart of closing market caps with volume under it, and the
/// numbers behind it for the page's hover readout.
fn svg_chart(chart: &Chart, now: u64) -> String {
    let (w, h) = (PAGE_WIDTH, PAGE_HEIGHT);
    let (left, right, top, bottom) = (8.0, 78.0, 12.0, 28.0);
    let volume_h = 46.0;
    let plot_w = w - left - right;
    let plot_h = h - top - bottom - volume_h - 8.0;
    let candles: &[Candle] = &chart.candles;
    let first = candles[0].time_ms;
    let span = (candles[candles.len() - 1].time_ms - first + chart.interval_ms).max(1) as f64;
    let x = |t: u64| {
        left + (t - first) as f64 / span * plot_w + plot_w / span * chart.interval_ms as f64 / 2.0
    };
    let scale = Scale::over(candles.iter().map(|c| c.close * chart.supply));
    let y = |v: f64| top + (1.0 - scale.at(v)) * plot_h;
    let up = change_pct(chart) >= 0.0;
    let color = if up { "var(--up)" } else { "var(--down)" };
    let mut line = String::new();
    for (i, c) in candles.iter().enumerate() {
        line.push_str(&format!(
            "{}{:.1},{:.1}",
            if i == 0 { "M" } else { " L" },
            x(c.time_ms),
            y(c.close * chart.supply)
        ));
    }
    let base = top + plot_h;
    let area = format!(
        "{line} L{:.1},{base:.1} L{:.1},{base:.1} Z",
        x(candles[candles.len() - 1].time_ms),
        x(first)
    );
    let mut svg = format!(
        "<div class=\"chart\" id=\"chart\"><svg viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"market cap chart\"><defs><linearGradient id=\"fill\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\"><stop offset=\"0\" stop-color=\"{color}\" stop-opacity=\".35\"/><stop offset=\"1\" stop-color=\"{color}\" stop-opacity=\"0\"/></linearGradient></defs>"
    );
    for step in 0..=4 {
        let fraction = f64::from(step) / 4.0;
        let at = top + (1.0 - fraction) * plot_h;
        svg.push_str(&format!(
            "<line x1=\"{left}\" x2=\"{:.1}\" y1=\"{at:.1}\" y2=\"{at:.1}\" class=\"gl\"/><text x=\"{:.1}\" y=\"{:.1}\" class=\"axis\">{}</text>",
            left + plot_w,
            left + plot_w + 8.0,
            at + 4.0,
            sol_short(scale.value(fraction))
        ));
    }
    let top_volume = candles
        .iter()
        .map(|c| c.volume)
        .fold(0.0, f64::max)
        .max(1e-12);
    let bar = (plot_w / span * chart.interval_ms as f64 * 0.7).clamp(1.0, 14.0);
    for c in candles {
        let height = c.volume / top_volume * volume_h;
        svg.push_str(&format!(
            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{bar:.1}\" height=\"{:.1}\" class=\"{}\"/>",
            x(c.time_ms) - bar / 2.0,
            h - bottom - height,
            height.max(0.5),
            if c.close >= c.open { "vup" } else { "vdown" }
        ));
    }
    svg.push_str(&format!(
        "<path d=\"{area}\" fill=\"url(#fill)\"/><path d=\"{line}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"2\" vector-effect=\"non-scaling-stroke\"/>"
    ));
    let mut last_label = String::new();
    for step in 0..4 {
        let t = first + (span * f64::from(step) / 3.0) as u64;
        let t = t.min(candles[candles.len() - 1].time_ms);
        let label = age_since(Some(t), now);
        if label == last_label {
            continue;
        }
        last_label.clone_from(&label);
        svg.push_str(&format!(
            "<text x=\"{:.1}\" y=\"{:.1}\" class=\"axis\" text-anchor=\"{}\">{} ago</text>",
            x(t),
            h - 8.0,
            match step {
                0 => "start",
                3 => "end",
                _ => "middle",
            },
            label
        ));
    }
    svg.push_str("<line id=\"cross\" class=\"cross\" y1=\"0\" y2=\"0\" x1=\"0\" x2=\"0\"/></svg><div class=\"tip\" id=\"tip\"></div></div>");
    let points = candles
        .iter()
        .map(|c| {
            json!([
                x(c.time_ms) / w,
                y(c.close * chart.supply) / h,
                c.close * chart.supply,
                c.volume,
                c.time_ms
            ])
        })
        .collect::<Vec<_>>();
    svg.push_str(&format!(
        "<script type=\"application/json\" id=\"points\">{}</script>",
        serde_json::to_string(&points).unwrap_or_else(|_| "[]".into())
    ));
    svg
}

/// Hover readout for the chart and the copy button. Reads the numbers the
/// page embeds; fetches nothing.
const CHART_SCRIPT: &str = r#"
const c=document.getElementById('chart'),tip=document.getElementById('tip'),cross=document.getElementById('cross');
const pts=JSON.parse((document.getElementById('points')||{}).textContent||'[]');
const fmt=v=>v>=1e6?(v/1e6).toFixed(2)+'M':v>=1e3?(v/1e3).toFixed(1)+'K':v>=10?v.toFixed(0):v.toFixed(2);
if(c&&pts.length){c.addEventListener('mousemove',e=>{const r=c.getBoundingClientRect(),fx=(e.clientX-r.left)/r.width;
let b=pts[0];for(const p of pts){if(Math.abs(p[0]-fx)<Math.abs(b[0]-fx))b=p}
const d=new Date(b[4]);tip.style.display='block';tip.innerHTML='<b>'+fmt(b[2])+' SOL</b> market cap<br>'+b[3].toFixed(2)+' SOL volume<br>'+d.toISOString().slice(5,16).replace('T',' ')+' UTC';
tip.style.left=Math.min(r.width-170,Math.max(0,b[0]*r.width+12))+'px';tip.style.top=Math.max(0,b[1]*r.height-40)+'px';
cross.setAttribute('x1',b[0]*1000);cross.setAttribute('x2',b[0]*1000);cross.setAttribute('y2',340);});
c.addEventListener('mouseleave',()=>{tip.style.display='none';cross.setAttribute('y2',0)})}
const b=document.getElementById('copy');if(b)b.onclick=()=>{navigator.clipboard.writeText(document.getElementById('mint').textContent);b.textContent='Copied'};
"#;

// --------------------------------------------------------------- holdings

pub fn holdings(c: &Ctx, w: String, format: Format) -> DispatchResponse {
    let data = match holdings_value(c, w.clone()) {
        Ok(data) => data,
        Err(e) => return unavailable(&e, format, "../../coins/"),
    };
    let now = host::now_ms();
    // Orders are shown when they can be read; holdings do not depend on them.
    let open_orders = orders::list_value(c, &w)
        .ok()
        .and_then(|v| v.get("orders").cloned())
        .unwrap_or_default();
    let tokens = data["tokens"].as_array().cloned().unwrap_or_default();
    let held = tokens
        .iter()
        .filter(|t| t["empty"] == json!(false))
        .collect::<Vec<_>>();
    let empty = tokens.iter().filter(|t| t["empty"] == json!(true)).count();
    let rent = tokens
        .iter()
        .filter(|t| t["empty"] == json!(true))
        .filter_map(|t| t["rentLamports"].as_u64())
        .sum::<u64>();
    // Names come from Pump's record for each coin, one request each.
    let names = held
        .iter()
        .take(NAMED_HOLDINGS)
        .filter_map(|t| {
            let mint = t["mint"].as_str()?;
            let record = fetch("GET", format!("{COINS}/{mint}"), vec![]).ok()?;
            Some((
                mint.to_owned(),
                (
                    clean_text(&record, "symbol", 16),
                    clean_text(&record, "name", 48),
                ),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let value = |t: &Value| {
        t["sellValueLamports"]
            .as_str()
            .and_then(|v| v.parse::<u64>().ok())
    };
    let total = held.iter().filter_map(|t| value(t)).sum::<u64>();
    let address = data["account"]["address"].as_str().unwrap_or("");
    let account = data["account"]["account"].as_u64().unwrap_or(0);
    match format {
        Format::Markdown => {
            let mut out = format!(
                "# Holdings · {} account {account}\n\n`{address}` · {} · worth about {} if sold now\n\n",
                cell(&w),
                stamp(now),
                sol(total as f64 / 1e9)
            );
            let rows = held
                .iter()
                .map(|t| {
                    let mint = t["mint"].as_str().unwrap_or("");
                    let (symbol, name) = names
                        .get(mint)
                        .cloned()
                        .unwrap_or_else(|| ("?".into(), "unknown token".into()));
                    vec![
                        format!("{} {}", cell(&symbol), cell(&name)),
                        t["uiAmount"]
                            .as_str()
                            .map(|a| compact(a.parse().unwrap_or(0.0)))
                            .unwrap_or_default(),
                        value(t)
                            .map(|v| sol(v as f64 / 1e9))
                            .unwrap_or_else(|| "—".into()),
                        mint.to_owned(),
                    ]
                })
                .collect::<Vec<_>>();
            if rows.is_empty() {
                out.push_str("No coins held.\n");
            } else {
                out.push_str(&table(
                    &["Coin", "Amount", "Sale estimate", "Mint"],
                    &[false, true, true, false],
                    &rows,
                ));
            }
            if empty > 0 {
                out.push_str(&format!(
                    "\n{empty} empty token account(s) hold {} of rent; close each with `close_token_account.json` to get it back.\n",
                    sol(rent as f64 / 1e9)
                ));
            }
            out.push_str("\n\"Sale estimate\" is what selling everything returns at the current price, including price impact, before protocol fees, network fee, tip and any later price move. Sell with `sell.json` and `\"amount\":\"all\"` or `\"50%\"`.\n");
            let orders = order_rows(&open_orders);
            if !orders.is_empty() {
                out.push_str("\n## Limit orders\n\n");
                out.push_str(&table(
                    &["Order", "Side", "At market cap", "State", "Mint"],
                    &[false, false, true, false, false],
                    &orders,
                ));
                out.push_str(
                    "\nOrders fill only when something writes `{}` to `check_orders.json`.\n",
                );
            }
            markdown(out)
        }
        Format::Html => {
            let rows = held
                .iter()
                .map(|t| {
                    let mint = t["mint"].as_str().unwrap_or("");
                    let (symbol, name) = names
                        .get(mint)
                        .cloned()
                        .unwrap_or_else(|| ("?".into(), "unknown token".into()));
                    let image = Some(image_link(mint, 86));
                    format!(
                        "<tr><td><a class=coin href=\"../../coins/{mint}.html\">{avatar}<span><b>{sym}</b><br><span class=muted>{name}</span></span></a></td><td class=num>{amount}</td><td class=num>{worth}</td><td><code>{short}</code></td></tr>",
                        avatar = avatar(image.as_deref(), &symbol, 36),
                        sym = html(&symbol),
                        name = html(&name),
                        amount = t["uiAmount"].as_str().map(|a| compact(a.parse().unwrap_or(0.0))).unwrap_or_default(),
                        worth = value(t).map(|v| sol(v as f64 / 1e9)).unwrap_or_else(|| "—".into()),
                        short = short(mint),
                    )
                })
                .collect::<String>();
            let body = format!(
                "<header class=head><h1>Holdings</h1><p class=muted>{wallet} · account {account} · <code>{address}</code> · {stamp}</p></header><section class=stats><div class=\"card stat\"><div class=k>Sale estimate before fees</div><div class=v>{total}</div></div><div class=\"card stat\"><div class=k>Coins</div><div class=v>{count}</div></div><div class=\"card stat\"><div class=k>Rent in empty accounts</div><div class=v>{rent}</div></div></section>{table}<p class=muted>“Sale estimate” is what selling everything returns at the current price, including price impact, before protocol fees, network fee, tip and any later price move. Sell with <code>sell.json</code> and <code>\"amount\":\"all\"</code> or <code>\"50%\"</code>; close empty accounts with <code>close_token_account.json</code> to get their rent back.</p>",
                wallet = html(&w),
                stamp = stamp(now),
                total = sol(total as f64 / 1e9),
                count = held.len(),
                rent = sol(rent as f64 / 1e9),
                table = if rows.is_empty() {
                    "<p class=card>No coins held.</p>".to_owned()
                } else {
                    format!(
                        "<table><thead><tr><th>Coin</th><th class=num>Amount</th><th class=num>Sale estimate</th><th>Mint</th></tr></thead><tbody>{rows}</tbody></table>"
                    )
                },
            );
            let orders = order_rows(&open_orders);
            let body = if orders.is_empty() {
                body
            } else {
                let rows = orders
                    .iter()
                    .map(|r| {
                        format!(
                            "<tr><td>{}</td><td class={}>{}</td><td class=num>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                            html(&r[0]),
                            if r[1] == "buy" { "buy" } else { "sell" },
                            html(&r[1]),
                            html(&r[2]),
                            html(&r[3]),
                            html(&short(&r[4]))
                        )
                    })
                    .collect::<String>();
                format!(
                    "{body}<h2>Limit orders</h2><table><thead><tr><th>Order</th><th>Side</th><th class=num>At market cap</th><th>State</th><th>Mint</th></tr></thead><tbody>{rows}</tbody></table><p class=muted>Orders fill only when something writes <code>{{}}</code> to <code>check_orders.json</code>.</p>"
                )
            };
            page(
                "Holdings · Pump.fun",
                &nav_from("../../coins/", "holdings"),
                &body,
                "",
            )
        }
    }
}

/// Limit orders that are not finished, as table rows.
fn order_rows(orders: &Value) -> Vec<Vec<String>> {
    orders
        .as_array()
        .into_iter()
        .flatten()
        .filter(|o| {
            !matches!(
                o["state"].as_str(),
                Some("filled" | "cancelled" | "invalidated" | "chain_failed")
            )
        })
        .map(|o| {
            vec![
                cell(o["order"].as_str().unwrap_or("")),
                o["side"].as_str().unwrap_or("").to_owned(),
                o["marketCapSol"].as_f64().map(sol).unwrap_or_default(),
                cell(o["state"].as_str().unwrap_or("")),
                o["mint"].as_str().unwrap_or("").to_owned(),
            ]
        })
        .collect()
}

// ------------------------------------------------------------ page chrome

/// A page that says what could not be read, instead of a read error a
/// browser would show as a broken file. The public RPC and Pump's API both
/// refuse bursts, so the usual cure is a reload.
fn unavailable(error: &DispatchResponse, format: Format, prefix: &str) -> DispatchResponse {
    let reason = dispatch_message(error);
    match format {
        Format::Markdown => markdown(format!(
            "# Could not load this just now\n\n{}\n\nPump's API and the public Solana RPC refuse bursts of requests; read the file again in a few seconds.\n",
            cell(&reason)
        )),
        Format::Html => page(
            "Could not load · Pump.fun",
            &nav_from(prefix, ""),
            &format!(
                "<section class=card><h1>Could not load this just now</h1><p class=muted>{}</p><p>Pump's API and the public Solana RPC refuse bursts of requests. Reload in a few seconds.</p></section>",
                html(&reason)
            ),
            "",
        ),
    }
}

fn nav(active: &str) -> String {
    nav_from("", active)
}

fn nav_from(prefix: &str, active: &str) -> String {
    let link = |href: &str, key: &str, label: &str| {
        format!(
            "<a href=\"{prefix}{href}\"{}>{label}</a>",
            if key == active { " class=on" } else { "" }
        )
    };
    format!(
        "<nav><span class=brand>◆ Pump.fun <span class=muted>in Bloom</span></span>{}{}</nav>",
        link("latest.html", "latest", "Newest"),
        link("live.html", "live", "Live"),
    )
}

fn page(title: &str, nav: &str, body: &str, script: &str) -> DispatchResponse {
    let script = if script.is_empty() {
        String::new()
    } else {
        format!("<script>{script}</script>")
    };
    DispatchResponse::Read(
        format!(
            "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><meta http-equiv=Content-Security-Policy content=\"default-src 'none'; img-src https://images.pump.fun https://imagedelivery.net; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><meta name=referrer content=no-referrer><title>{}</title><style>{STYLE}</style></head><body><div class=wrap>{nav}{body}<footer class=muted>Snapshot through Bloom at {} · reload to refresh</footer></div>{script}</body></html>",
            html(title),
            html(&stamp(host::now_ms()))
        )
        .into_bytes(),
    )
}

const STYLE: &str = r#"
:root{--bg:#0a0d13;--panel:#111620;--line:#1e2531;--text:#e7eaf0;--muted:#8a93a6;--up:#22c55e;--down:#f0525c;--warn:#f5a524;--accent:#8ea2ff;color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#f5f6fa;--panel:#fff;--line:#e4e7ee;--text:#10131a;--muted:#667085;--up:#16a34a;--down:#dc2626;--warn:#b45309;--accent:#4f5bd5;color-scheme:light}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:20px 16px 40px}
nav{display:flex;gap:18px;align-items:center;margin-bottom:22px}nav a{color:var(--muted);text-decoration:none;font-weight:500}nav a.on,nav a:hover{color:var(--text)}.brand{font-weight:700;margin-right:auto}
h1{margin:0;font-size:28px;letter-spacing:-.01em}h2{font-size:13px;margin:26px 0 10px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.06em}
.head{margin-bottom:18px}.head p{margin:4px 0 0}.coinhead{display:flex;gap:18px;align-items:center}
.muted{color:var(--muted)}a{color:var(--accent)}code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--line);padding:2px 6px;border-radius:6px;word-break:break-all}
button{font:inherit;font-size:12px;color:var(--text);background:var(--line);border:0;border-radius:6px;padding:3px 10px;cursor:pointer}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 16px;color:inherit;text-decoration:none;display:block}
a.card:hover{border-color:var(--accent);transform:translateY(-1px)}a.card{transition:border-color .15s,transform .15s}
.coin{display:flex;gap:12px;align-items:center;color:inherit;text-decoration:none}.grow{flex:1;min-width:0}.right{text-align:right}
.avatar{position:relative;border-radius:12px;object-fit:cover;background:linear-gradient(135deg,var(--line),var(--panel));display:grid;place-items:center;font-weight:700;color:var(--muted);flex:none;overflow:hidden}
.avatar img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}.sym{font-weight:700}.name{color:var(--muted);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.v{font-weight:650}
.row{display:flex;justify-content:space-between;gap:8px;font-size:12.5px;color:var(--muted);margin-top:10px}
.bar{height:6px;background:var(--line);border-radius:3px;overflow:hidden;margin-top:10px}.bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--up))}
.pill{display:inline-block;font-size:12px;padding:2px 10px;border-radius:999px;border:1px solid var(--line);color:var(--muted);margin:6px 6px 0 0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0}
.stat .sub{font-size:13px;color:var(--muted);font-weight:400}.empty{color:var(--muted);text-align:center;padding:28px}.stat .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}.stat .v{font-size:21px;margin-top:2px}
.charthead{display:flex;justify-content:space-between;color:var(--muted);font-size:13px;margin-bottom:6px}
.chart{position:relative;overflow-x:auto}.chart svg{width:100%;min-width:640px;height:auto;display:block}
.gl{stroke:var(--line)}.axis{fill:var(--muted);font-size:12px}.vup{fill:var(--up);opacity:.35}.vdown{fill:var(--down);opacity:.35}.cross{stroke:var(--muted);stroke-dasharray:3 3}
.tip{position:absolute;pointer-events:none;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:6px 10px;font-size:12px;display:none;white-space:nowrap;box-shadow:0 6px 24px rgba(0,0,0,.25)}
.cols{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.3fr);gap:28px}@media (max-width:860px){.cols{grid-template-columns:1fr}}
.checks{padding:0;margin:0}.checks li{list-style:none;padding:9px 0;border-bottom:1px solid var(--line);display:flex;gap:12px}.checks b{width:16px;flex:none;text-align:center}
.ok b{color:var(--up)}.warn b{color:var(--warn)}.unknown b{color:var(--muted)}.warn span{color:var(--text)}
table{width:100%;border-collapse:collapse;font-size:14px}th{color:var(--muted);font-weight:500;text-align:left;font-size:12.5px}td,th{padding:8px 6px;border-bottom:1px solid var(--line)}.num{text-align:right;font-variant-numeric:tabular-nums}
td a{color:inherit;text-decoration:none}.buy{color:var(--up)}.sell{color:var(--down)}
.snippet{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font:13px ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-all}
footer{margin-top:30px;font-size:12.5px}
"#;

fn avatar(image: Option<&str>, symbol: &str, size: u32) -> String {
    match image {
        // The initials sit under the image and show if it fails to load.
        Some(image) => format!(
            "<span class=avatar style=\"width:{size}px;height:{size}px\">{}<img src=\"{}\" alt=\"\" loading=lazy onerror=\"this.remove()\"></span>",
            initials(symbol),
            html(image)
        ),
        None => format!(
            "<span class=avatar style=\"width:{size}px;height:{size}px\">{}</span>",
            initials(symbol)
        ),
    }
}

fn initials(symbol: &str) -> String {
    html(
        &symbol
            .chars()
            .filter(|c| c.is_alphanumeric())
            .take(2)
            .collect::<String>()
            .to_uppercase(),
    )
}

// -------------------------------------------------------------- formatting

fn markdown(text: String) -> DispatchResponse {
    DispatchResponse::Read(text.into_bytes())
}

/// A Markdown table padded so it also lines up when read raw.
fn table(headers: &[&str], right: &[bool], rows: &[Vec<String>]) -> String {
    let widths = (0..headers.len())
        .map(|i| {
            rows.iter()
                .map(|r| width(&r[i]))
                .chain([width(headers[i]), 3])
                .max()
                .unwrap_or(3)
        })
        .collect::<Vec<_>>();
    let pad = |text: &str, i: usize| {
        let gap = " ".repeat(widths[i].saturating_sub(width(text)));
        if right[i] {
            format!("{gap}{text}")
        } else {
            format!("{text}{gap}")
        }
    };
    let line = |cells: Vec<String>| format!("| {} |\n", cells.join(" | "));
    let mut out = line(headers.iter().enumerate().map(|(i, h)| pad(h, i)).collect());
    out.push_str(&line(
        widths
            .iter()
            .enumerate()
            .map(|(i, w)| {
                if right[i] {
                    format!("{}:", "-".repeat(w - 1))
                } else {
                    "-".repeat(*w)
                }
            })
            .collect(),
    ));
    for row in rows {
        out.push_str(&line(
            row.iter().enumerate().map(|(i, c)| pad(c, i)).collect(),
        ));
    }
    out
}

/// Columns `text` takes in a terminal: wide East Asian characters and most
/// emoji take two, combining marks and variation selectors none.
fn width(text: &str) -> usize {
    text.chars()
        .map(|c| match c as u32 {
            0x0300..=0x036F | 0x200D | 0xFE00..=0xFE0F => 0,
            0x1100..=0x115F
            | 0x2E80..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE30..=0xFE4F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1F64F
            | 0x1F900..=0x1FAFF
            | 0x20000..=0x3FFFD => 2,
            _ => 1,
        })
        .sum()
}

/// Creator text made safe for a Markdown table cell.
fn cell(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '|' => '¦',
            '`' | '<' | '>' => '·',
            c => c,
        })
        .collect()
}

pub(crate) fn html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A share of supply, without rounding a small holding to zero.
fn share(pct: f64) -> String {
    match pct {
        0.0 => "none".into(),
        p if p < 0.1 => "under 0.1%".into(),
        p => format!("{p:.1}%"),
    }
}

fn meter(pct: f64, width: usize) -> String {
    let filled = ((pct / 100.0) * width as f64)
        .round()
        .clamp(0.0, width as f64) as usize;
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn sol(amount: f64) -> String {
    format!("{} SOL", sol_short(amount))
}

fn sol_short(amount: f64) -> String {
    match amount {
        a if a >= 1e6 => format!("{:.2}M", a / 1e6),
        a if a >= 1e4 => format!("{:.1}K", a / 1e3),
        a if a >= 1e3 => format!("{:.2}K", a / 1e3),
        a if a >= 100.0 => format!("{a:.0}"),
        a if a >= 1.0 => format!("{a:.2}"),
        a if a >= 0.01 => format!("{a:.3}"),
        0.0 => "0".into(),
        a => format!("{a:.5}"),
    }
}

fn usd(amount: f64) -> String {
    match amount {
        a if a >= 1e6 => format!("${:.2}M", a / 1e6),
        a if a >= 1e3 => format!("${:.1}K", a / 1e3),
        a => format!("${a:.0}"),
    }
}

/// A price in SOL to three significant figures, written out in full so a
/// person can compare two at a glance.
fn price(amount: f64) -> String {
    if amount <= 0.0 || !amount.is_finite() {
        return "—".into();
    }
    let decimals = (2 - amount.log10().floor() as i32).clamp(0, 15) as usize;
    format!("{amount:.decimals$} SOL")
}

fn compact(amount: f64) -> String {
    match amount {
        a if a >= 1e9 => format!("{:.2}B", a / 1e9),
        a if a >= 1e6 => format!("{:.2}M", a / 1e6),
        a if a >= 1e3 => format!("{:.1}K", a / 1e3),
        a => format!("{a:.0}"),
    }
}

fn short(address: &str) -> String {
    if address.len() <= 12 {
        return address.to_owned();
    }
    format!("{}…{}", &address[..5], &address[address.len() - 5..])
}

fn duration(ms: u64) -> String {
    match ms / 1000 {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 48 * 3600 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

fn age_since(ms: Option<u64>, now: u64) -> String {
    ms.map(|ms| duration(now.saturating_sub(ms)))
        .unwrap_or_else(|| "?".into())
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `Sep 29 03:41 UTC`.
fn stamp(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (_, month, day) = civil(days);
    format!(
        "{} {day} {:02}:{:02} UTC",
        MONTHS[(month - 1) as usize],
        rem / 3600,
        rem % 3600 / 60
    )
}

/// Days since 1970-01-01 to (year, month, day), after Howard Hinnant.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-09-29T01:04:34.000Z` to milliseconds since the epoch.
fn iso_ms(text: &str) -> Option<u64> {
    let number = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    let days = days_from_civil(number(0..4)?, number(5..7)?, number(8..10)?);
    let seconds = days * 86_400 + number(11..13)? * 3600 + number(14..16)? * 60 + number(17..19)?;
    u64::try_from(seconds * 1000).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fake_host::{self, FakeHost};

    const MINT: &str = "C8CMvu8FXZruHrNjFaixaDJjiveG6gKmUvT5BrK5pump";
    const NOW: u64 = 1_790_643_874_000;
    const EVIL: &str = "<img src=x onerror=alert(1)>";

    fn text(response: DispatchResponse) -> String {
        match response {
            DispatchResponse::Read(bytes) => String::from_utf8(bytes).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    fn listing_host() -> FakeHost {
        let mut host = FakeHost::new(NOW);
        host.reply(
            &format!("{COIN_LISTINGS}?offset=0&limit={LISTING_LIMIT}&sort=created_timestamp&order=DESC&includeNsfw=false"),
            json!([
                {"mint": MINT, "symbol": EVIL, "name": "a|b", "created_timestamp": NOW - 90_000,
                 "last_trade_timestamp": NOW - 5_000, "market_cap": 42.5, "usd_market_cap": 5000.0,
                 "real_token_reserves": 396_550_000_000_000u64, "quote_mint": "11111111111111111111111111111111"},
                {"mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "symbol": "USD", "name": "usd pair",
                 "quote_mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}
            ]),
        );
        host
    }

    /// The lists escape the creator's text, link each coin to its page, and
    /// allow the page no network access beyond Pump's images.
    #[test]
    fn the_newest_coins_page_is_safe_and_linked() {
        fake_host::install(listing_host());
        let page = text(listing(Listing::Latest, Format::Html));
        assert!(
            !page.contains(EVIL) && page.contains("&lt;img src=x"),
            "escaped"
        );
        assert!(page.contains(&format!("href=\"{MINT}.html\"")));
        assert!(page.contains(
            "default-src 'none'; img-src https://images.pump.fun https://imagedelivery.net;"
        ));
        assert!(
            page.contains("width:50.0%"),
            "curve progress from the listing"
        );
        assert!(page.contains("USDC pair"));
        assert!(!page.contains("<script src"));

        fake_host::install(listing_host());
        let front = text(front_page());
        assert!(front.contains(&format!("href=\"coins/{MINT}.html\"")));
        assert!(front.contains("href=\"coins/live.html\""));
    }

    #[test]
    fn the_newest_coins_read_as_a_table_in_a_terminal() {
        fake_host::install(listing_host());
        let page = text(listing(Listing::Latest, Format::Markdown));
        let rows = page
            .lines()
            .filter(|l| l.starts_with('|'))
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 4, "header, rule and two coins: {page}");
        assert!(
            rows.iter().all(|r| r.matches('|').count() == 8),
            "no cell breaks the table: {page}"
        );
        assert!(
            rows[2].contains("42.50 SOL") && rows[2].contains("████░░░░  50%"),
            "{page}"
        );
        assert!(rows[3].contains("USDC pair"), "{page}");
    }

    /// A coin page renders even when every chain check, the chart and the
    /// trades are unavailable, and says what it could not check.
    #[test]
    fn a_coin_page_degrades_to_what_it_could_read() {
        let mut host = FakeHost::new(NOW);
        host.reply(
            &format!("{COINS}/{MINT}"),
            json!({"mint": MINT, "symbol": EVIL, "name": "x", "created_timestamp": NOW - 60_000,
                "total_supply": 1_000_000_000_000_000u64}),
        );
        fake_host::install(host);
        let page = text(coin_page(MINT, Format::Html));
        assert!(!page.contains(EVIL));
        assert!(page.contains("Could not check the mint"));
        assert!(!page.contains("<svg"), "no chart without candles");
        let md = text(coin_page(MINT, Format::Markdown));
        assert!(
            md.contains("? Could not check the mint's authorities"),
            "{md}"
        );
        assert!(md.contains(&format!(
            "echo '{{\"operationId\":\"buy-1\",\"mint\":\"{MINT}\""
        )));
    }

    /// With candles and trades the page draws the chart and lists trades
    /// that link to the explorer.
    #[test]
    fn a_coin_page_charts_and_lists_trades() {
        let mut host = FakeHost::new(NOW);
        let created = NOW - 30 * 60_000;
        host.reply(
            &format!("{COINS}/{MINT}"),
            json!({"mint": MINT, "symbol": "MOG", "created_timestamp": created,
                "total_supply": 1_000_000_000_000_000u64, "base_decimals": 6}),
        );
        host.reply(
            &format!("https://swap-api.pump.fun/v2/coins/{MINT}/candles?interval=1m&limit=120&currency=SOL&createdTs={created}"),
            json!([
                {"timestamp": NOW - 120_000, "open": "0.00000002", "high": "0.00000004", "low": "0.00000001", "close": "0.00000003", "volume": "1.5"},
                {"timestamp": NOW - 60_000, "open": "0.00000003", "high": "0.00000004", "low": "0.00000001", "close": "0.00000002", "volume": "0.5"}
            ]),
        );
        let tx = "2H3Dikr12qk9PWTGUvsMvaEG7aFjtAoVXEZNyWcXxpnMChW6MBCTx9V5jM1mcLVxoxQN5SadMsqLUZjHiUA1wShi";
        host.reply(
            &format!("https://swap-api.pump.fun/v2/coins/{MINT}/trades?limit=50"),
            json!({"trades": [{"type": "buy", "amountSol": "0.5", "baseAmount": "1000", "priceSol": "0.0000001",
                "timestamp": "2026-09-29T01:04:04.000Z", "program": "pump",
                "userAddress": "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF", "tx": tx}]}),
        );
        fake_host::install(host);
        let page = text(coin_page(MINT, Format::Html));
        assert!(page.contains("<svg viewBox=\"0 0 1000 340\""));
        assert!(page.contains("id=\"points\""));
        assert!(page.contains(&format!("https://solscan.io/tx/{tx}")));
        assert!(page.contains("30s ago"), "trade age from its timestamp");
    }

    struct HoldingsRoute;
    impl petal::RouteIdentity for HoldingsRoute {
        const PATH: &'static str = "trade/[wallet]/holdings.html";
        const CANONICAL_PATH: &'static str = "trade/[wallet]/holdings.html";
        const PARAMS: &'static [(&'static str, usize)] = &[];
    }

    /// Holdings name each coin, value it, link to its page, and count the
    /// rent sitting in empty accounts.
    #[test]
    fn holdings_name_value_and_link_each_coin() {
        let user = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF";
        let install = || {
            let mut host = FakeHost::new(NOW);
            host.seed_vfs("wallets/main/0/address.sol", user);
            let account = |mint: &str, amount: &str| {
                json!({"pubkey": "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf", "account": {"lamports": 2_039_280,
                    "data": {"parsed": {"info": {"mint": mint, "tokenAmount": {"amount": amount, "decimals": 6, "uiAmountString": "35323.46"}}}}}})
            };
            host.reply(
                &format!("{RPC_VERIFY} getTokenAccountsByOwner"),
                json!({"result": {"value": [account(MINT, "35323464136")]}}),
            );
            host.reply(
                &format!("{RPC_VERIFY} getTokenAccountsByOwner"),
                json!({"result": {"value": [account("H3m3TD2mwmU5zkUTHRDoLU7RdxbWp6BEgoQa3s9wpump", "0")]}}),
            );
            host.reply(
                &format!("{COINS}/{MINT}"),
                json!({"symbol": "MOG", "name": "Mog <b>"}),
            );
            fake_host::install(host);
        };
        install();
        let ctx = petal::Ctx::bind::<HoldingsRoute>(petal::RawCtx {
            petal_root: "/petals/pumpfun".into(),
            package_hash: "test".into(),
            path: "trade/main/holdings.html".into(),
            params: vec![("wallet".into(), "main".into())],
            actor: None,
        });
        let page = text(holdings(&ctx, "main".into(), Format::Html));
        assert!(
            page.contains(&format!("href=\"../../coins/{MINT}.html\"")),
            "{page}"
        );
        assert!(page.contains("Mog &lt;b&gt;") && page.contains("35.3K"));
        assert!(
            page.contains("0.00204 SOL"),
            "rent in the empty account: {page}"
        );
        assert!(page.contains("href=\"../../coins/latest.html\""));
        install();
        let md = text(holdings(&ctx, "main".into(), Format::Markdown));
        assert!(md.contains("1 empty token account(s)"), "{md}");
    }

    /// When Pump or the RPC refuses, a person gets a page that says so, not
    /// a broken file; an invalid mint is still an error.
    #[test]
    fn an_outage_reads_as_a_page_not_a_broken_file() {
        fake_host::install(FakeHost::new(NOW));
        let page = text(listing(Listing::Live, Format::Html));
        assert!(page.contains("Could not load this just now"), "{page}");
        let md = text(coin_page(MINT, Format::Markdown));
        assert!(md.starts_with("# Could not load this just now"), "{md}");
        assert!(matches!(
            coin_page("not/a/mint", Format::Html),
            DispatchResponse::Error { .. }
        ));
    }

    #[test]
    fn dates_round_trip() {
        assert_eq!(iso_ms("2026-09-29T01:04:34.000Z"), Some(1_790_643_874_000));
        assert_eq!(stamp(1_790_643_874_000), "Sep 29 01:04 UTC");
        assert_eq!(civil(0), (1970, 1, 1));
    }

    #[test]
    fn numbers_read_at_a_glance() {
        assert_eq!(sol(796.38), "796 SOL");
        assert_eq!(sol(3995.2), "4.00K SOL");
        assert_eq!(sol(28.4), "28.40 SOL");
        assert_eq!(price(0.000_000_796_449), "0.000000796 SOL");
        assert_eq!(compact(35_323_892.7), "35.32M");
        assert_eq!(meter(50.0, 8), "████░░░░");
    }

    #[test]
    fn creator_text_cannot_escape_its_cell_or_tag() {
        assert_eq!(cell("a|b`<c>"), "a¦b··c·");
        assert_eq!(cell("test_do_not_buy"), "test_do_not_buy");
        assert_eq!(width("火🐸a"), 5);
        assert_eq!(
            html("<script>'x'&\"y\"</script>"),
            "&lt;script&gt;&#39;x&#39;&amp;&quot;y&quot;&lt;/script&gt;"
        );
    }

    #[test]
    fn a_terminal_chart_fills_to_each_close() {
        let chart = Chart {
            interval: "1m",
            interval_ms: 60_000,
            supply: 1e9,
            candles: (0..10)
                .map(|i| Candle {
                    time_ms: i * 60_000,
                    open: 1e-8,
                    high: 2e-8,
                    low: 1e-8,
                    close: 1e-8 * (1.0 + i as f64 / 9.0),
                    volume: 1.0,
                })
                .collect(),
        };
        let text = text_chart(&chart, 11 * 60_000);
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), TEXT_CHART_HEIGHT + 2);
        assert!(lines[0].trim_start().starts_with("20.00 ┤"), "{text}");
        assert!(lines[TEXT_CHART_HEIGHT - 1].contains("10.00 ┤"), "{text}");
        let flat = Scale::over([100.0, 100.2].into_iter());
        assert!(flat.high - flat.low >= 9.9, "a 0.2% move is not stretched");
        assert!(
            lines[0].ends_with('█'),
            "the last close is the highest: {text}"
        );
        assert!(lines.last().unwrap().contains("11m ago"), "{text}");
    }

    #[test]
    fn partial_launch_samples_are_unknown_in_both_rendered_views() {
        let summary = json!({"mint":MINT,"symbol":"TEST","name":"Test",
            "warnings":[],"risk":{"launchBlockBuyers":0,"launchBlockBoughtPct":0.0,"launchBlockPartial":true,"unchecked":[]}});
        let checks = checklist(&summary);
        assert!(checks.iter().any(
            |(level, text)| *level == Level::Unknown && text.contains("Partial launch sample")
        ));
        assert!(
            !checks
                .iter()
                .any(|(level, text)| *level == Level::Pass && text.contains("No other"))
        );
        let md = coin_markdown(MINT, &summary, None, None, NOW);
        let html = coin_html(MINT, &summary, None, None, NOW);
        for view in [md, html] {
            assert!(view.contains("Partial launch sample"));
            assert!(!view.contains("No other fee payer"));
        }
    }

    #[test]
    fn creator_and_holder_observations_keep_their_attribution_limits() {
        let summary = json!({"warnings":[],"risk":{"creatorHoldsPct":0.0,"top10HoldPct":5.0,"creatorOtherCoins":0,"creatorGraduatedCoins":0,"unchecked":[]}});
        let checks = checklist(&summary)
            .into_iter()
            .map(|(_, t)| t)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(checks.contains("associated token accounts"));
        assert!(checks.contains("related wallets are not checked"));
        assert!(checks.contains("index may lag"));
        assert!(!checks.contains("first coin"));
    }

    #[test]
    fn unsettled_dead_and_pending_cancel_orders_remain_visible() {
        let rows = order_rows(&json!([
            {"order":"dead","state":"dead"}, {"order":"cancel","state":"cancel_pending"},
            {"order":"confirmed","state":"confirmed"}, {"order":"done","state":"filled"}
        ]));
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().any(|r| r[0] == "dead"));
        assert!(!rows.iter().any(|r| r[0] == "done"));
    }

    #[test]
    fn html_snapshots_show_their_generation_time() {
        fake_host::install(FakeHost::new(NOW));
        let text = text(page("Snapshot", "", "<p>Snapshot</p>", ""));
        assert!(text.contains("Snapshot through Bloom at"));
        assert!(text.contains(&stamp(NOW)));
    }
}
