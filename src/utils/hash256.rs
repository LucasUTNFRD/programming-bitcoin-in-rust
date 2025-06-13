use sha2::{Digest, Sha256};

///The hash256() function in Bitcoin programming contexts typically refers to double SHA256, which is used extensively in Bitcoin for security reasons. This double hashing helps prevent certain types of cryptographic attacks
pub fn hash256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(first_hash);
    let double_hash = hasher2.finalize();

    double_hash.into()
}
