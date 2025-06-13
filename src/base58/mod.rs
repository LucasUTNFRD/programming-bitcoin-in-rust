use primitive_types::U256;

// use crate::ecc::ecdsa::hash256;
use crate::utils::hash256::hash256;

const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn encode(s: &[u8]) -> String {
    let mut result = String::new();
    let mut count = 0;
    let i = 0;
    while i < s.len() && s[i] != 0 {
        count += 1
    }
    let mut num = U256::from_big_endian(s);
    // This is the loop that figures out what Base58 digit to use.
    while num > U256::zero() {
        let div_rem = num.div_mod(U256::from(58u32));
        num = div_rem.0; // quotient
        let remainder = div_rem.1; // remainder
        result.push(
            BASE58_ALPHABET
                .chars()
                .nth(remainder.as_u32() as usize)
                .unwrap(),
        );
    }

    for _ in 0..count {
        result.push(BASE58_ALPHABET.chars().next().unwrap());
    }
    result.chars().rev().collect()
}

pub fn encode_with_checksum(b: &[u8]) -> String {
    let mut buff = Vec::with_capacity(b.len());
    buff.copy_from_slice(b);
    let hash = hash256(b);
    buff.extend_from_slice(&hash[0..4]);
    encode(&buff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base58_encoding_case1() {
        let hex_input = "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d";
        let bytes_input = hex::decode(hex_input).expect("Failed to decode hex");
        let expected_base58 = "9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6";
        let actual_base58 = encode(&bytes_input);
        assert_eq!(actual_base58, expected_base58);
        println!("Test 1 passed: {} -> {}", hex_input, actual_base58);
    }

    #[test]
    fn test_base58_encoding_case2() {
        let hex_input = "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c";
        let bytes_input = hex::decode(hex_input).expect("Failed to decode hex");
        let expected_base58 = "4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd";
        let actual_base58 = encode(&bytes_input);
        assert_eq!(actual_base58, expected_base58);
        println!("Test 2 passed: {} -> {}", hex_input, actual_base58);
    }

    #[test]
    fn test_base58_encoding_case3() {
        let hex_input = "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6";
        let bytes_input = hex::decode(hex_input).expect("Failed to decode hex");
        let expected_base58 = "EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7";
        let actual_base58 = encode(&bytes_input);
        assert_eq!(actual_base58, expected_base58);
        println!("Test 3 passed: {} -> {}", hex_input, actual_base58);
    }

    #[test]
    fn test_base58_encoding_with_leading_zeros() {
        let hex_input = "0000000000000000000000000000000000000000000000000000000000000001"; // 32 bytes with leading zeros
        let bytes_input = hex::decode(hex_input).expect("Failed to decode hex");
        // A single 0x01 byte is "2" in Base58. Many leading zeros turn into '1's.
        let expected_base58 = "11111111111111111111111111111111111111111111111111111111111111112";
        let actual_base58 = encode(&bytes_input);
        assert_eq!(actual_base58, expected_base58);
        println!(
            "Test with leading zeros passed: {} -> {}",
            hex_input, actual_base58
        );
    }

    #[test]
    fn test_base58_encoding_zero() {
        let hex_input = "00";
        let bytes_input = hex::decode(hex_input).expect("Failed to decode hex");
        let expected_base58 = "1"; // Single zero byte is '1' in Base58
        let actual_base58 = encode(&bytes_input);
        assert_eq!(actual_base58, expected_base58);
        println!("Test for zero passed: {} -> {}", hex_input, actual_base58);
    }
}
