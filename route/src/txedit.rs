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
    let static_keys = message[layout.keys_end - layout.static_count * 32..layout.keys_end]
        .chunks_exact(32)
        .collect::<Vec<_>>();
    let existing = program.and_then(|p| static_keys.iter().position(|key| *key == p));
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

    #[test]
    fn an_unsigned_transaction_round_trips_through_the_envelope() {
        let original = fixture_message("sell_bond");
        let tx = unsigned_transaction(&original).unwrap();
        assert_eq!(envelope(&tx).unwrap().message, original.as_slice());
    }
}
