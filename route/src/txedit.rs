//! Edits the Petal makes to a builder's v0 message after validating it.
//!
//! Only the instruction section changes. The header, static keys, blockhash
//! and address-table lookups are copied byte for byte, except that one
//! read-only static key may be appended when an added instruction names a
//! program the builder only loaded through a table. Programs cannot be
//! table-loaded, and table-loaded accounts are indexed after the static keys,
//! so every instruction index at or past the old static count moves up by one.

use super::{Ix, short};

/// Where the static keys end and the instruction section starts and ends.
struct Layout {
    static_count: usize,
    keys_end: usize,
    instructions: (usize, usize),
}

fn layout(message: &[u8]) -> Result<Layout, String> {
    if message.first() != Some(&128) || message.len() < 4 {
        return Err("only v0 messages can be edited".into());
    }
    let mut offset = 4;
    let static_count = short(message, &mut offset)?;
    let keys_end = offset + static_count * 32;
    let mut offset = keys_end + 32;
    let start = offset;
    for _ in 0..short(message, &mut offset)? {
        offset += 1;
        let accounts = short(message, &mut offset)?;
        offset += accounts;
        let data = short(message, &mut offset)?;
        offset += data;
    }
    if offset > message.len() {
        return Err("truncated instruction section".into());
    }
    Ok(Layout {
        static_count,
        keys_end,
        instructions: (start, offset),
    })
}

fn encode_short(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// `message` with its instructions replaced by `instructions`, and with
/// `program` appended as a read-only static key when it is not already one.
/// Returns the new message and the static index of `program`, if given.
pub(crate) fn rewrite(
    message: &[u8],
    instructions: &[Ix],
    program: Option<&[u8; 32]>,
) -> Result<(Vec<u8>, Option<usize>), String> {
    let layout = layout(message)?;
    let (static_keys, _) =
        message[layout.keys_end - layout.static_count * 32..layout.keys_end].as_chunks::<32>();
    let existing = program.and_then(|p| static_keys.iter().position(|key| key == p));
    let added = program.is_some() && existing.is_none();
    if added && layout.static_count >= 127 {
        return Err("no room for another static key".into());
    }
    let shift = |index: u8| -> Result<u8, String> {
        if added && usize::from(index) >= layout.static_count {
            index
                .checked_add(1)
                .ok_or_else(|| "account index overflow".to_string())
        } else {
            Ok(index)
        }
    };
    let mut out = Vec::with_capacity(message.len() + 64);
    out.extend_from_slice(&message[..4]);
    if added {
        // The appended key is an unsigned read-only static key.
        out[3] = out[3]
            .checked_add(1)
            .ok_or("read-only key count overflow")?;
    }
    encode_short(layout.static_count + usize::from(added), &mut out);
    out.extend_from_slice(&message[layout.keys_end - layout.static_count * 32..layout.keys_end]);
    if added {
        out.extend_from_slice(program.expect("added implies a program"));
    }
    out.extend_from_slice(&message[layout.keys_end..layout.keys_end + 32]);
    encode_short(instructions.len(), &mut out);
    for ix in instructions {
        out.push(u8::try_from(ix.program).map_err(|_| "program index overflow")?);
        encode_short(ix.accounts.len(), &mut out);
        for account in &ix.accounts {
            out.push(shift(*account)?);
        }
        encode_short(ix.data.len(), &mut out);
        out.extend_from_slice(&ix.data);
    }
    out.extend_from_slice(&message[layout.instructions.1..]);
    let index = program.map(|_| existing.unwrap_or(layout.static_count));
    Ok((out, index))
}

/// The durable-nonce form of `message`: its first instruction advances
/// `nonce_account` (whose authority is the fee payer, static key 0), and its
/// recent blockhash is the nonce's value, so the signed transaction stays
/// valid until the nonce is advanced, by this transaction or a cancel.
///
/// The nonce account joins the writable unsigned static keys, and the
/// recent-blockhashes sysvar (and the System program, if the builder only
/// loaded it from a table) join the read-only unsigned ones. Every account
/// index is moved to match. Instructions and lookups are otherwise copied.
pub(crate) fn with_durable_nonce(
    message: &[u8],
    instructions: &[Ix],
    nonce_account: &[u8; 32],
    nonce_value: &[u8; 32],
    system_program: &[u8; 32],
    recent_blockhashes: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let layout = layout(message)?;
    let [_, required, readonly_signed, readonly_unsigned] = message[..4] else {
        return Err("message header missing".into());
    };
    let static_count = layout.static_count;
    let (static_keys, _) =
        message[layout.keys_end - static_count * 32..layout.keys_end].as_chunks::<32>();
    if static_keys.contains(nonce_account) || static_keys.contains(recent_blockhashes) {
        return Err("the builder's message already names the nonce accounts".into());
    }
    let writable_end = static_count
        .checked_sub(usize::from(readonly_unsigned))
        .filter(|end| *end >= usize::from(required))
        .ok_or("inconsistent message header")?;
    let system = static_keys.iter().position(|key| key == system_program);
    let appended = 1 + usize::from(system.is_none());
    if static_count + 1 + appended > 127 {
        return Err("no room for the nonce keys".into());
    }
    let moved = |index: usize| -> Result<u8, String> {
        let moved = if index < writable_end {
            index
        } else if index < static_count {
            index + 1
        } else {
            index + 1 + appended
        };
        u8::try_from(moved).map_err(|_| "account index overflow".to_string())
    };
    let mut keys: Vec<[u8; 32]> = static_keys.to_vec();
    keys.insert(writable_end, *nonce_account);
    keys.push(*recent_blockhashes);
    if system.is_none() {
        keys.push(*system_program);
    }
    let system_index = match system {
        Some(index) => moved(index)?,
        None => u8::try_from(keys.len() - 1).map_err(|_| "account index overflow")?,
    };
    let advance = Ix {
        program: usize::from(system_index),
        accounts: vec![
            u8::try_from(writable_end).map_err(|_| "account index overflow")?,
            u8::try_from(static_count + 1).map_err(|_| "account index overflow")?,
            0,
        ],
        data: vec![4, 0, 0, 0],
    };
    let mut out = Vec::with_capacity(message.len() + 160);
    out.extend_from_slice(&[
        0x80,
        required,
        readonly_signed,
        readonly_unsigned
            .checked_add(u8::try_from(appended).map_err(|_| "key count overflow")?)
            .ok_or("read-only key count overflow")?,
    ]);
    encode_short(keys.len(), &mut out);
    for key in &keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(nonce_value);
    encode_short(instructions.len() + 1, &mut out);
    for ix in std::iter::once(&advance).chain(instructions) {
        let program = if std::ptr::eq(ix, &advance) {
            u8::try_from(ix.program).map_err(|_| "program index overflow")?
        } else {
            moved(ix.program)?
        };
        out.push(program);
        encode_short(ix.accounts.len(), &mut out);
        for account in &ix.accounts {
            if std::ptr::eq(ix, &advance) {
                out.push(*account);
            } else {
                out.push(moved(usize::from(*account))?);
            }
        }
        encode_short(ix.data.len(), &mut out);
        out.extend_from_slice(&ix.data);
    }
    out.extend_from_slice(&message[layout.instructions.1..]);
    Ok(out)
}

/// A v0 message with no address lookups: `header` is (required signers,
/// read-only signed, read-only unsigned), and each instruction names its
/// program and accounts by index into `keys`.
pub(crate) fn plain_message(
    header: [u8; 3],
    keys: &[[u8; 32]],
    blockhash: &[u8; 32],
    instructions: &[Ix],
) -> Result<Vec<u8>, String> {
    let mut out = vec![0x80, header[0], header[1], header[2]];
    encode_short(keys.len(), &mut out);
    for key in keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(blockhash);
    encode_short(instructions.len(), &mut out);
    for ix in instructions {
        out.push(u8::try_from(ix.program).map_err(|_| "program index overflow")?);
        encode_short(ix.accounts.len(), &mut out);
        out.extend_from_slice(&ix.accounts);
        encode_short(ix.data.len(), &mut out);
        out.extend_from_slice(&ix.data);
    }
    out.push(0);
    Ok(out)
}

/// An unsigned transaction carrying `message`, with one zeroed signature slot
/// per required signer.
pub(crate) fn unsigned_transaction(message: &[u8]) -> Result<Vec<u8>, String> {
    let signers = usize::from(*message.get(1).ok_or("message header missing")?);
    let mut out = Vec::with_capacity(1 + signers * 64 + message.len());
    encode_short(signers, &mut out);
    out.resize(out.len() + signers * 64, 0);
    out.extend_from_slice(message);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::{envelope, message as parse};
    use super::*;

    fn fixture_message(name: &str) -> Vec<u8> {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/pump-builder-fixtures.json")).unwrap();
        let raw = B64
            .decode(fixtures[name]["transaction"].as_str().unwrap())
            .unwrap();
        envelope(&raw).unwrap().message.to_vec()
    }

    #[test]
    fn rewriting_the_same_instructions_reproduces_the_message() {
        for name in ["buy_bond", "buy_amm", "sell_bond", "sell_amm"] {
            let original = fixture_message(name);
            let parsed = parse(&original).unwrap();
            let (rewritten, _) = rewrite(&original, &parsed.instructions, None).unwrap();
            assert_eq!(rewritten, original, "{name}");
        }
    }

    #[test]
    fn appending_a_program_key_shifts_only_table_loaded_indices() {
        let original = fixture_message("buy_amm");
        let parsed = parse(&original).unwrap();
        let program = [9u8; 32];
        let (rewritten, index) = rewrite(&original, &parsed.instructions, Some(&program)).unwrap();
        let reparsed = parse(&rewritten).unwrap();
        let static_count = parsed.keys.len();
        assert_eq!(index, Some(static_count));
        assert_eq!(reparsed.keys.len(), static_count + 1);
        assert_eq!(reparsed.keys[static_count], program);
        assert_eq!(reparsed.readonly_unsigned, parsed.readonly_unsigned + 1);
        assert_eq!(reparsed.lookups.len(), parsed.lookups.len());
        for (before, after) in parsed.instructions.iter().zip(&reparsed.instructions) {
            assert_eq!(before.program, after.program);
            assert_eq!(before.data, after.data);
            for (a, b) in before.accounts.iter().zip(&after.accounts) {
                let expected = if usize::from(*a) >= static_count {
                    a + 1
                } else {
                    *a
                };
                assert_eq!(*b, expected);
            }
        }
    }

    /// The durable form of a builder message keeps every account an
    /// instruction names, adds the nonce advance first, and carries the
    /// nonce as its blockhash.
    #[test]
    fn the_durable_nonce_form_keeps_every_account_and_advances_first() {
        let tables = super::super::test_lookup_tables();
        for name in [
            "buy_bond",
            "buy_amm",
            "sell_bond",
            "sell_amm",
            "buy_bond_protected",
        ] {
            let original = fixture_message(name);
            let mut before = parse(&original).unwrap();
            super::super::append_lookup_addresses(&mut before, &tables).unwrap();
            let (nonce, value, system, sysvar) = ([7u8; 32], [8u8; 32], [0u8; 32], [6u8; 32]);
            let durable = with_durable_nonce(
                &original,
                &before.instructions,
                &nonce,
                &value,
                &system,
                &sysvar,
            )
            .unwrap();
            let mut after = parse(&durable).unwrap();
            super::super::append_lookup_addresses(&mut after, &tables).unwrap();
            assert_eq!(after.blockhash, value, "{name}");
            assert_eq!(after.required, before.required);
            let advance = &after.instructions[0];
            assert_eq!(after.keys[advance.program], system, "{name}");
            assert_eq!(advance.data, [4, 0, 0, 0]);
            let named = |m: &super::super::Msg, ix: &Ix| {
                ix.accounts
                    .iter()
                    .map(|a| m.keys[usize::from(*a)])
                    .collect::<Vec<_>>()
            };
            assert_eq!(named(&after, advance), vec![nonce, sysvar, before.keys[0]]);
            assert!(
                after.writable(usize::from(advance.accounts[0])),
                "the nonce account is writable"
            );
            assert!(!after.writable(usize::from(advance.accounts[1])));
            assert_eq!(after.instructions.len(), before.instructions.len() + 1);
            for (b, a) in before.instructions.iter().zip(&after.instructions[1..]) {
                assert_eq!(before.keys[b.program], after.keys[a.program], "{name}");
                assert_eq!(named(&before, b), named(&after, a), "{name}");
                assert_eq!(b.data, a.data);
                for (ib, ia) in b.accounts.iter().zip(&a.accounts) {
                    assert_eq!(
                        before.writable(usize::from(*ib)),
                        after.writable(usize::from(*ia)),
                        "{name}: writability is preserved"
                    );
                }
            }
        }
    }

    #[test]
    fn an_unsigned_transaction_round_trips_through_the_envelope() {
        let original = fixture_message("sell_bond");
        let tx = unsigned_transaction(&original).unwrap();
        assert_eq!(envelope(&tx).unwrap().message, original.as_slice());
    }
}
