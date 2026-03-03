use std::io::Read;

use crate::{transactions::tx::ParseError, utils::varint::VarInt};

mod opcode;

#[derive(Debug, PartialEq, Eq)]
pub struct Script {
    commands: Vec<Command>,
}

pub fn encode_num(num: i64) -> Vec<u8> {
    if num == 0 {
        return vec![];
    }

    let abs = num.unsigned_abs();
    let negative = num < 0;

    // Build little-endian bytes of the absolute value
    let mut result = Vec::new();
    let mut val = abs;
    while val > 0 {
        result.push((val & 0xff) as u8);
        val >>= 8;
    }

    // If the top bit of the last byte is set, we need an extra byte for the sign
    if result.last().unwrap() & 0x80 != 0 {
        if negative {
            result.push(0x80);
        } else {
            result.push(0x00);
        }
    } else if negative {
        // Set the sign bit on the last byte
        let last = result.last_mut().unwrap();
        *last |= 0x80;
    }

    result
}

pub fn decode_num(element: &[u8]) -> i64 {
    if element.is_empty() {
        return 0;
    }

    // Little-endian sign-magnitude: sign bit is MSB of last byte
    let last = *element.last().unwrap();
    let negative = last & 0x80 != 0;

    // Strip the sign bit to get the absolute value
    let mut bytes = element.to_vec();
    let last_idx = bytes.len() - 1;
    bytes[last_idx] &= 0x7f;

    // Reconstruct as little-endian
    let mut result: i64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        result |= (b as i64) << (8 * i);
    }

    if negative { -result } else { result }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Data(Vec<u8>),
    Op(u8),
}
impl Script {
    pub fn new(cmds: Vec<Command>) -> Self {
        Self { commands: cmds }
    }

    pub fn decode(stream: &mut impl Read) -> Result<Self, ParseError> {
        // Read the script length (varint)
        let length = VarInt::read_varint(stream)?.value();
        let mut cmds = vec![];
        let mut count = 0;

        while count < length {
            // Read one byte
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte)?;
            count += 1;
            let current_byte = byte[0];

            match current_byte {
                1..=75 => {
                    let n = current_byte;
                    let mut data_buf = vec![0; n as usize];
                    stream.read_exact(&mut data_buf)?;
                    cmds.push(Command::Data(data_buf));
                    count += n as u64;
                }
                76 => {
                    let mut len_buf = [0u8; 1];
                    stream.read_exact(&mut len_buf)?;
                    let data_length = u64::from_le_bytes([len_buf[0], 0, 0, 0, 0, 0, 0, 0]);
                    let mut data_buf = vec![0u8; data_length as usize];
                    stream.read_exact(&mut data_buf)?;
                    cmds.push(Command::Data(data_buf));
                    count += data_length + 1;
                }
                77 => {
                    let mut len_buf = [0u8; 2];
                    stream.read_exact(&mut len_buf)?;
                    let data_length = u16::from_le_bytes(len_buf) as u64;
                    let mut data_buf = vec![0u8; data_length as usize];
                    stream.read_exact(&mut data_buf)?;
                    cmds.push(Command::Data(data_buf));
                    count += data_length + 2;
                }
                _ => {
                    let op_code = current_byte;
                    cmds.push(Command::Op(op_code));
                }
            }
        }

        if count != length {
            return Err(ParseError::SyntaxError);
        }

        Ok(Self::new(cmds))
    }

    pub fn commands(&self) -> &[Command] {
        &self.commands
    }

    pub fn encode(&self) -> Vec<u8> {
        let raw_bytes: Vec<u8> = self
            .commands
            .iter()
            .flat_map(|cmd| match cmd {
                Command::Op(opcode) => vec![*opcode],
                Command::Data(data) => {
                    let len = data.len();
                    let mut buf = match len {
                        0..=75 => vec![len as u8],
                        76..=0xff => vec![76u8, len as u8],
                        0x100..=520 => {
                            let mut b = vec![77u8];
                            b.extend_from_slice(&(len as u16).to_le_bytes());
                            b
                        }
                        _ => panic!("cmd too long"),
                    };
                    buf.extend_from_slice(data);
                    buf
                }
            })
            .collect();
        let mut result = VarInt::encode_varint(raw_bytes.len() as u64);
        result.extend_from_slice(&raw_bytes);
        result
    }
}

// Script notes
// Basic execution:
//
// Run unlocking script → leaves data on stack
// Run locking script → consumes stack data
// If final stack top is true (non-zero), coins can be spent

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::*;

    // ====================================================================
    // TEST 1: Parse raw script bytes into structured commands
    // ====================================================================
    //
    // A real scriptSig from the book (chapter 6):
    //   <71-byte DER signature> <33-byte compressed pubkey>
    //
    // After parsing, this should produce 2 commands:
    //   Command::Data(71 bytes) -- the signature
    //   Command::Data(33 bytes) -- the compressed public key
    //
    // To pass this test you need to:
    //   1. Create a `Command` enum with variants `Op(u8)` and `Data(Vec<u8>)`
    //   2. Change `Script.commands` from `Vec<u8>` to `Vec<Command>`
    //   3. Rewrite `Script::decode()` to interpret push-byte instructions:
    //      - Bytes 0x01..=0x4b (1-75): read next N bytes as data
    //      - Byte 0x4c (OP_PUSHDATA1): read 1 byte as length, then data
    //      - Byte 0x4d (OP_PUSHDATA2): read 2 bytes (LE) as length, then data
    //      - Otherwise: it's an opcode -> Command::Op(byte)
    //   4. Add a `commands()` accessor: pub fn commands(&self) -> &[Command]
    //
    #[test]
    fn test_parse_script_into_commands() {
        let raw_script_hex = "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937";
        let raw = hex::decode(raw_script_hex).unwrap();
        let mut cursor = Cursor::new(raw);

        let script = Script::decode(&mut cursor).unwrap();
        let cmds = script.commands();

        // Should have exactly 2 commands: a 71-byte sig and a 33-byte pubkey
        assert_eq!(cmds.len(), 2, "Expected 2 commands (sig + pubkey)");

        // First command: 71-byte DER signature (push byte 0x47 = 71)
        let expected_sig = hex::decode(
            "304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601"
        ).unwrap();
        assert_eq!(cmds[0], Command::Data(expected_sig));

        // Second command: 33-byte compressed public key (push byte 0x21 = 33)
        let expected_pubkey =
            hex::decode("035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937")
                .unwrap();
        assert_eq!(cmds[1], Command::Data(expected_pubkey));
    }

    // // ====================================================================
    // // TEST 2: Script number encoding and decoding
    // // ====================================================================
    // //
    // // Bitcoin Script uses its own integer encoding on the stack:
    // //   - Little-endian byte order
    // //   - Most significant bit of the last byte is the sign bit
    // //   - 0 is encoded as empty bytes
    // //
    // // To pass this test, implement:
    // //   pub fn encode_num(num: i64) -> Vec<u8>
    // //   pub fn decode_num(element: &[u8]) -> i64
    // //
    // // These should be public functions in the script module so they can
    // // also be imported by the integration tests.
    // //
    #[test]
    fn test_script_number_encoding() {
        // Zero
        assert_eq!(encode_num(0), Vec::<u8>::new());
        assert_eq!(decode_num(&[]), 0);

        // Positive values
        assert_eq!(encode_num(1), vec![0x01]);
        assert_eq!(decode_num(&[0x01]), 1);

        assert_eq!(encode_num(127), vec![0x7f]);
        assert_eq!(decode_num(&[0x7f]), 127);

        // 128 needs extra byte because 0x80 alone would be -0
        assert_eq!(encode_num(128), vec![0x80, 0x00]);
        assert_eq!(decode_num(&[0x80, 0x00]), 128);

        assert_eq!(encode_num(256), vec![0x00, 0x01]);
        assert_eq!(decode_num(&[0x00, 0x01]), 256);

        assert_eq!(encode_num(1000), vec![0xe8, 0x03]);
        assert_eq!(decode_num(&[0xe8, 0x03]), 1000);

        // Negative values
        assert_eq!(encode_num(-1), vec![0x81]);
        assert_eq!(decode_num(&[0x81]), -1);

        assert_eq!(encode_num(-127), vec![0xff]);
        assert_eq!(decode_num(&[0xff]), -127);

        assert_eq!(encode_num(-128), vec![0x80, 0x80]);
        assert_eq!(decode_num(&[0x80, 0x80]), -128);

        assert_eq!(encode_num(-256), vec![0x00, 0x81]);
        assert_eq!(decode_num(&[0x00, 0x81]), -256);

        // Round-trip: decode(encode(n)) == n
        for n in [-1000, -255, -1, 0, 1, 255, 1000, 65535] {
            assert_eq!(decode_num(&encode_num(n)), n, "Round-trip failed for {}", n);
        }
    }

    // ====================================================================
    // TEST 3: Individual stack opcode functions
    // ====================================================================
    //
    // Each opcode is a function: (stack: &mut Vec<Vec<u8>>) -> bool
    //
    // To pass this test, implement these functions (in opcode.rs or wherever,
    // just re-export them so they're accessible via `use super::*` here):
    //
    //   op_dup, op_hash160_op, op_equal, op_equalverify, op_verify, op_add
    //
    // Note: the hash160 opcode function is named `op_hash160_op` to avoid
    // collision with utils::hash160::hash160. Name it however you like --
    // just update the reference here accordingly.
    //
    use crate::script::opcode::*;
    #[test]
    fn test_stack_opcodes() {
        use crate::utils::hash160::hash160;

        // --- OP_DUP: duplicate top stack element ---
        let mut stack: Vec<Vec<u8>> = vec![vec![0x01, 0x02, 0x03]];
        assert!(op_dup(&mut stack));
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0], stack[1]);

        // OP_DUP on empty stack should fail
        let mut empty_stack: Vec<Vec<u8>> = vec![];
        assert!(!op_dup(&mut empty_stack));

        // --- OP_HASH160: pop top, push hash160(top) ---
        let mut stack: Vec<Vec<u8>> = vec![b"hello world".to_vec()];
        assert!(op_hash160_op(&mut stack));
        assert_eq!(stack.len(), 1);
        let expected_hash = hash160(b"hello world");
        assert_eq!(stack[0], expected_hash.to_vec());

        // --- OP_EQUAL: pop two, push encode_num(1) if equal, encode_num(0) if not ---
        let mut stack: Vec<Vec<u8>> = vec![vec![0x01], vec![0x01]];
        assert!(op_equal(&mut stack));
        assert_eq!(stack.len(), 1);
        assert_eq!(decode_num(&stack[0]), 1);

        let mut stack: Vec<Vec<u8>> = vec![vec![0x01], vec![0x02]];
        assert!(op_equal(&mut stack));
        assert_eq!(stack.len(), 1);
        assert_eq!(decode_num(&stack[0]), 0);

        // --- OP_VERIFY: pop top, fail if zero ---
        let mut stack: Vec<Vec<u8>> = vec![encode_num(1)];
        assert!(op_verify(&mut stack));
        assert_eq!(stack.len(), 0);

        let mut stack: Vec<Vec<u8>> = vec![encode_num(0)];
        assert!(!op_verify(&mut stack));

        // --- OP_EQUALVERIFY: equal + verify ---
        let mut stack: Vec<Vec<u8>> = vec![vec![0xab], vec![0xab]];
        assert!(op_equalverify(&mut stack));
        assert_eq!(stack.len(), 0);

        let mut stack: Vec<Vec<u8>> = vec![vec![0xab], vec![0xcd]];
        assert!(!op_equalverify(&mut stack));

        // --- OP_ADD: pop two numbers, push sum ---
        let mut stack: Vec<Vec<u8>> = vec![encode_num(2), encode_num(3)];
        assert!(op_add(&mut stack));
        assert_eq!(stack.len(), 1);
        assert_eq!(decode_num(&stack[0]), 5);
    }
    //
    // // ====================================================================
    // // TEST 4: Serialize round-trip with Command-based Script
    // // ====================================================================
    // //
    // // After changing Script to use Vec<Command>, encode() must reproduce
    // // the exact same bytes that decode() consumed.
    // //
    // // Serialization rules for each Command:
    // //   Data(bytes) where len < 75:    emit [len_byte] [bytes...]
    // //   Data(bytes) where 75..256:     emit [0x4c] [len_byte] [bytes...]
    // //   Data(bytes) where 256..=520:   emit [0x4d] [len_le_2bytes] [bytes...]
    // //   Op(byte):                      emit [byte]
    // //
    // // Prepend total raw length as a varint.
    // //
    // #[test]
    // fn test_script_serialize_roundtrip() {
    //     // A real scriptSig
    //     let raw_hex = "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937";
    //     let raw = hex::decode(raw_hex).unwrap();
    //     let mut cursor = Cursor::new(raw.clone());
    //
    //     let script = Script::decode(&mut cursor).unwrap();
    //     let serialized = script.encode();
    //     assert_eq!(
    //         hex::encode(&serialized),
    //         raw_hex,
    //         "Serialized script must match original bytes exactly"
    //     );
    //
    //     // A P2PKH scriptPubKey: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    //     let script_pubkey_hex = "1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac";
    //     let raw_pubkey = hex::decode(script_pubkey_hex).unwrap();
    //     let mut cursor = Cursor::new(raw_pubkey.clone());
    //
    //     let script = Script::decode(&mut cursor).unwrap();
    //     let cmds = script.commands();
    //     assert_eq!(cmds.len(), 5);
    //     assert_eq!(cmds[0], Command::Op(0x76)); // OP_DUP
    //     assert_eq!(cmds[1], Command::Op(0xa9)); // OP_HASH160
    //     if let Command::Data(ref hash) = cmds[2] {
    //         assert_eq!(hash.len(), 20, "P2PKH hash should be 20 bytes");
    //     } else {
    //         panic!("Expected Command::Data for the pubkey hash");
    //     }
    //     assert_eq!(cmds[3], Command::Op(0x88)); // OP_EQUALVERIFY
    //     assert_eq!(cmds[4], Command::Op(0xac)); // OP_CHECKSIG
    //
    //     let serialized = script.encode();
    //     assert_eq!(hex::encode(&serialized), script_pubkey_hex);
    // }
    //
    // // ====================================================================
    // // TEST 5: Evaluate a simple math script on the stack machine
    // // ====================================================================
    // //
    // // Script: <2> <3> OP_ADD <5> OP_EQUAL
    // //
    // // To pass this test, implement:
    // //   pub fn evaluate(&self, z: U256) -> bool
    // //
    // // The method:
    // //   1. Iterates through self.commands
    // //   2. Data -> push onto stack
    // //   3. Op(byte) -> dispatch to opcode function:
    // //      - 0x93 (147) -> op_add
    // //      - 0x87 (135) -> op_equal
    // //      - 0x76 (118) -> op_dup
    // //      - 0xa9 (169) -> op_hash160_op
    // //      - 0x88 (136) -> op_equalverify
    // //      - 0xac (172) -> op_checksig (needs z)
    // //      - etc.
    // //   4. After loop: return false if stack empty or top decodes to 0
    // //
    // #[test]
    // fn test_evaluate_simple_math_script() {
    //     use primitive_types::U256;
    //
    //     // 2 + 3 == 5 -> true
    //     let script = Script::new(vec![
    //         Command::Data(encode_num(2)),
    //         Command::Data(encode_num(3)),
    //         Command::Op(0x93), // OP_ADD
    //         Command::Data(encode_num(5)),
    //         Command::Op(0x87), // OP_EQUAL
    //     ]);
    //     assert!(script.evaluate(U256::zero()), "2 + 3 should equal 5");
    //
    //     // 2 + 3 == 4 -> false
    //     let script_fail = Script::new(vec![
    //         Command::Data(encode_num(2)),
    //         Command::Data(encode_num(3)),
    //         Command::Op(0x93), // OP_ADD
    //         Command::Data(encode_num(4)),
    //         Command::Op(0x87), // OP_EQUAL
    //     ]);
    //     assert!(
    //         !script_fail.evaluate(U256::zero()),
    //         "2 + 3 should not equal 4"
    //     );
    // }
}
