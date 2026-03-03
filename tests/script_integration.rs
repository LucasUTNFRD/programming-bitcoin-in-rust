// //! Integration tests for Bitcoin Script evaluation.
// //!
// //! These tests verify end-to-end script evaluation including
// //! ECDSA signature verification (OP_CHECKSIG) and script pattern detection.
//
// use std::io::Cursor;
//
// use primitive_types::U256;
// use programmign_bitcoin_in_rust::script::{encode_num, Command, Script};
//
// // ========================================================================
// // TEST 6: Full P2PKH script evaluation with real signature data
// // ========================================================================
// //
// // This test uses known-good data from the book (chapter 6).
// //
// // To pass this test you need:
// //   1. OP_CHECKSIG implemented:
// //      - Pop SEC pubkey from stack
// //      - Pop DER signature from stack (strip last byte = hash_type)
// //      - Parse both using your existing PublicKey / Signature types
// //      - Verify against z using PublicKey::verify_signature
// //      - Push encode_num(1) if valid, encode_num(0) otherwise
// //
// //      The pubkey in this test is uncompressed (65 bytes, starts with 0x04),
// //      so use PublicKey::parse(). Your implementation should detect the
// //      format by the first byte:
// //        0x04 -> uncompressed (65 bytes) -> PublicKey::parse()
// //        0x02 | 0x03 -> compressed (33 bytes) -> PublicKey::parse_compressed()
// //
// //   2. Script combination via Add trait:
// //      impl std::ops::Add for Script {
// //          type Output = Script;
// //          fn add(self, other: Script) -> Script {
// //              // concatenate commands from self then other
// //          }
// //      }
// //
// //   3. evaluate() must dispatch signing opcodes (172=OP_CHECKSIG, etc.)
// //      with the z parameter.
// //
// #[test]
// fn test_p2pkh_script_evaluation() {
//     // From the book - a known valid P2PKH spend.
//     // z is the signature hash used in the book's OP_CHECKSIG test.
//     let z = U256::from_big_endian(
//         &hex::decode("7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d").unwrap(),
//     );
//
//     // The signature (DER-encoded + SIGHASH_ALL byte 0x01 appended)
//     let sig = hex::decode(
//         "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601"
//     ).unwrap();
//
//     // The public key (uncompressed SEC format, 65 bytes, starts with 0x04)
//     let pubkey = hex::decode(
//         "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
//     ).unwrap();
//
//     // Compute the expected pubkey hash (hash160 of the pubkey)
//     use programmign_bitcoin_in_rust::utils::hash160::hash160;
//     let pubkey_hash = hash160(&pubkey);
//
//     // scriptSig: <sig> <pubkey>
//     let script_sig = Script::new(vec![Command::Data(sig), Command::Data(pubkey)]);
//
//     // scriptPubKey: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
//     let script_pubkey = Script::new(vec![
//         Command::Op(0x76),                   // OP_DUP
//         Command::Op(0xa9),                   // OP_HASH160
//         Command::Data(pubkey_hash.to_vec()), // <20-byte hash>
//         Command::Op(0x88),                   // OP_EQUALVERIFY
//         Command::Op(0xac),                   // OP_CHECKSIG
//     ]);
//
//     // Combine and evaluate: scriptSig + scriptPubKey
//     let combined = script_sig + script_pubkey;
//     assert!(
//         combined.evaluate(z),
//         "Valid P2PKH script should evaluate to true"
//     );
//
//     // Negative case: wrong z should fail verification
//     let wrong_z = U256::from(12345);
//     let sig2 = hex::decode(
//         "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601"
//     ).unwrap();
//     let pubkey2 = hex::decode(
//         "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
//     ).unwrap();
//     let pubkey_hash2 = hash160(&pubkey2);
//
//     let combined_bad = Script::new(vec![
//         Command::Data(sig2),
//         Command::Data(pubkey2),
//         Command::Op(0x76),
//         Command::Op(0xa9),
//         Command::Data(pubkey_hash2.to_vec()),
//         Command::Op(0x88),
//         Command::Op(0xac),
//     ]);
//     assert!(
//         !combined_bad.evaluate(wrong_z),
//         "Wrong z should cause P2PKH to fail"
//     );
// }
//
// // ========================================================================
// // TEST 7: Script pattern detection
// // ========================================================================
// //
// // To pass this test, implement:
// //   pub fn is_p2pkh_script_pubkey(&self) -> bool
// //
// // Returns true when commands match exactly:
// //   [Op(0x76), Op(0xa9), Data(20 bytes), Op(0x88), Op(0xac)]
// //
// #[test]
// fn test_p2pkh_script_pattern_detection() {
//     // A valid P2PKH scriptPubKey (parsed from raw bytes)
//     let script_pubkey_hex = "1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac";
//     let raw = hex::decode(script_pubkey_hex).unwrap();
//     let mut cursor = Cursor::new(raw);
//     let script = Script::decode(&mut cursor).unwrap();
//
//     assert!(
//         script.is_p2pkh_script_pubkey(),
//         "Standard P2PKH scriptPubKey should be detected"
//     );
//
//     // Manually constructed P2PKH should also match
//     let manual_p2pkh = Script::new(vec![
//         Command::Op(0x76),
//         Command::Op(0xa9),
//         Command::Data(vec![0u8; 20]), // any 20-byte hash
//         Command::Op(0x88),
//         Command::Op(0xac),
//     ]);
//     assert!(manual_p2pkh.is_p2pkh_script_pubkey());
//
//     // A scriptSig should NOT match P2PKH pattern
//     let script_sig = Script::new(vec![
//         Command::Data(vec![0u8; 71]),
//         Command::Data(vec![0u8; 33]),
//     ]);
//     assert!(!script_sig.is_p2pkh_script_pubkey());
//
//     // Wrong hash length (19 bytes instead of 20)
//     let bad_hash_len = Script::new(vec![
//         Command::Op(0x76),
//         Command::Op(0xa9),
//         Command::Data(vec![0u8; 19]),
//         Command::Op(0x88),
//         Command::Op(0xac),
//     ]);
//     assert!(!bad_hash_len.is_p2pkh_script_pubkey());
//
//     // Empty script
//     let empty = Script::new(vec![]);
//     assert!(!empty.is_p2pkh_script_pubkey());
// }
