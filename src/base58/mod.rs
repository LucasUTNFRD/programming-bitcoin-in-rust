use crate::utils::hash256::hash256;

const BITCOIN_BASE58_ALPHABET: &[u8] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn encode(bytes: &[u8]) -> String {
    let zcount = bytes.iter().take_while(|x| **x == 0).count();
    let size = (bytes.len() - zcount) * 138 / 100 + 1;
    let mut buffer = vec![0u8; size];

    let mut i = zcount;
    let mut high = size - 1;

    while i < bytes.len() {
        let mut carry = bytes[i] as u32;
        let mut j = size - 1;

        while j > high || carry != 0 {
            carry += 256 * buffer[j] as u32;
            buffer[j] = (carry % 58) as u8;
            carry /= 58;

            // in original trezor implementation it was underflowing
            j = j.saturating_sub(1)
        }

        i += 1;
        high = j;
    }

    let mut j = buffer.iter().take_while(|x| **x == 0).count();

    let mut result = String::with_capacity(zcount + size);
    for _ in 0..zcount {
        result.push('1');
    }

    while j < size {
        result.push(BITCOIN_BASE58_ALPHABET[buffer[j] as usize] as char);
        j += 1;
    }

    result
}

const CHECKSUM_SIZE: usize = 4;
pub fn encode_with_checksum(b: &[u8]) -> String {
    let total_size = b.len() + CHECKSUM_SIZE;
    let mut buffer = Vec::with_capacity(total_size);
    buffer.extend_from_slice(b);

    let hash = hash256(b);
    buffer.extend_from_slice(&hash[0..4]);

    encode(&buffer)
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
    fn test_base58_encoding_zero() {
        let hex_input = "00";
        let bytes_input = hex::decode(hex_input).expect("Failed to decode hex");
        let expected_base58 = "1"; // Single zero byte is '1' in Base58
        let actual_base58 = encode(&bytes_input);
        assert_eq!(actual_base58, expected_base58);
        println!("Test for zero passed: {} -> {}", hex_input, actual_base58);
    }
}
