use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// The result is a 20-byte (160-bit) hash.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    // First, compute SHA256 hash
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(data);
    let sha256_result = sha256_hasher.finalize();

    // Then, compute RIPEMD160 of the SHA256 result
    let mut ripemd160_hasher = Ripemd160::new();
    ripemd160_hasher.update(sha256_result);
    let ripemd160_result = ripemd160_hasher.finalize();

    ripemd160_result.into()
}
