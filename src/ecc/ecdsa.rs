use std::{fmt::Display, ops::Div};

use crate::ecc::point::G1Point;

use super::{
    field_element::FiniteField,
    secp256k1::{F256K1, G1AffinityPoint},
};
use hmac::{Hmac, Mac};
use primitive_types::U256;
use sha2::Sha256;
/// Represents an ECDSA signature, consisting of two scalar values, r and s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub r: F256K1,
    pub s: F256K1,
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({}{})", self.r, self.s)
    }
}

impl Signature {
    pub fn new(r: F256K1, s: F256K1) -> Self {
        Self { r, s }
    }
}

/// Represents a secp256k1 private key.
/// It's a scalar value within the order of the generator point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateKey {
    secret: F256K1,

    /// Represents a secp256k1 public key.
    /// It's a point on the elliptic curve.
    pub publick_key: PublicKey,
}

type HmacSha256 = Hmac<Sha256>;

impl PrivateKey {
    pub fn new(secret: U256) -> Self {
        let secret = F256K1::from(secret);
        let g = G1AffinityPoint::generator();
        Self {
            secret,
            publick_key: PublicKey::new(g * secret),
        }
    }

    /// Signs a message hash using the ECDSA algorithm with deterministic 'k' (RFC 6979).
    ///
    /// # Arguments
    /// * `message_hash` - The hash of the message to be signed (as U256).
    ///
    /// # Returns
    /// An `Signature`
    pub fn sign(&self, message_hash: U256) -> Option<Signature> {
        let n = G1AffinityPoint::N; // Order of the generator point (scalar field modulus)

        //Convert message_hash to a field element of the scalar field (F256K1)
        let z = F256K1::new(message_hash);

        // Generate k deterministically using the new module
        let k_candidate =
            Self::generate_deterministic_k_scalar(self.secret.as_u256(), message_hash, n)?;

        let k_field = F256K1::new(k_candidate);

        let generator = G1AffinityPoint::generator();
        let r_point = generator * k_field;

        // If r_point is the point at infinity, this k value is not suitable.
        // This only happens if k_field is equal to N
        if r_point.is_identity() {
            eprintln!("Error: r_point is identity. Cannot sign with this k.");
            return None;
        }

        let r = F256K1::new(r_point.x().as_u256() % n);
        if r.is_zero() {
            eprintln!("Error: r is zero. Cannot sign.");
            return None;
        }

        let s = (z + r * self.secret)
            .div(k_field)
            .expect("Error: k_field  has no inverse, cannot sign");

        let half_n = n / 2;
        let s_val = s.as_u256();
        let s_final = if s_val > half_n {
            F256K1::new(n - s_val)
        } else {
            s
        };

        if s_final.is_zero() {
            eprintln!("Error: s is zero after low-s normalization. Cannot sign.");
            return None;
        }

        Some(Signature { r, s: s_final })
    }

    /// Generates a deterministic 'k' scalar for ECDSA signing according to RFC 6979.
    ///
    /// This function ensures that 'k' is unique and reproducible for a given
    /// private key and message hash, eliminating the need for a cryptographically
    /// secure random number generator during signing and preventing side-channel
    /// attacks related to 'k' generation.
    ///
    /// # Arguments
    /// * `private_key_scalar` - The private key scalar (U256).
    /// * `message_hash` - The hash of the message to be signed (U256).
    /// * `n` - The order of the generator point (SECP256K1_ORDER).
    ///
    /// # Returns
    /// An `Option<U256>` which is `Some(k_candidate)` if a valid `k` is found
    /// that results in non-zero `r` and `s` values, or `None` if a suitable
    /// `k` could not be found after repeated attempts (though RFC 6979 ensures
    /// one is always found for valid inputs).
    pub fn generate_deterministic_k_scalar(
        private_key_scalar: U256,
        message_hash: U256,
        n: U256,
    ) -> Option<U256> {
        // Prepare message_hash as a byte array for HMAC.
        let z_bytes = message_hash.to_big_endian(); // Convert U256 to 32-byte big-endian array

        // Prepare private key as bytes for HMAC
        let priv_key_bytes = private_key_scalar.to_big_endian();

        // Initialize V and K as per RFC 6979 Section 3.2, Step b
        let mut v = [0x01u8; 32]; // V is a 32-byte array initialized to all 0x01
        let mut k_hmac = [0x00u8; 32]; // K is a 32-byte array initialized to all 0x00

        // Step c: k = HMAC_SHA256(k, V || 0x00 || int2octets(x) || bits2octets(h))
        // Here, x is the private key (priv_key_bytes), h is the message hash (z_bytes)
        let mut hmac = HmacSha256::new_from_slice(&k_hmac).expect("HMAC can be created");
        hmac.update(&v); // V
        hmac.update(&[0x00]); // 0x00
        hmac.update(&priv_key_bytes); // x (private key)
        hmac.update(&z_bytes); // h (message hash)
        k_hmac.copy_from_slice(&hmac.finalize().into_bytes());

        // Step d: V = HMAC_SHA256(k, V)
        let mut hmac = HmacSha256::new_from_slice(&k_hmac).expect("HMAC can be created");
        hmac.update(&v); // V
        v.copy_from_slice(&hmac.finalize().into_bytes());

        // Step e: k = HMAC_SHA256(k, V || 0x01 || int2octets(x) || bits2octets(h))
        let mut hmac = HmacSha256::new_from_slice(&k_hmac).expect("HMAC can be created");
        hmac.update(&v); // V
        hmac.update(&[0x01]); // 0x01
        hmac.update(&priv_key_bytes); // x (private key)
        hmac.update(&z_bytes); // h (message hash)
        k_hmac.copy_from_slice(&hmac.finalize().into_bytes());

        // Step f: V = HMAC_SHA256(k, V)
        let mut hmac = HmacSha256::new_from_slice(&k_hmac).expect("HMAC can be created");
        hmac.update(&v); // V
        v.copy_from_slice(&hmac.finalize().into_bytes());

        // Step g: Loop to find a suitable k_candidate
        loop {
            // Step g.1: T = HMAC_SHA256(k, V)
            let mut t_bytes = [0u8; 32];
            let mut hmac = HmacSha256::new_from_slice(&k_hmac).expect("HMAC can be created");
            hmac.update(&v); // V
            t_bytes.copy_from_slice(&hmac.finalize().into_bytes());

            let k_candidate = U256::from_big_endian(&t_bytes);

            // Step g.2: Check if 1 <= k_candidate < n
            if k_candidate > U256::zero() && k_candidate < n {
                return Some(k_candidate); // Valid k_candidate found
            }

            // Step g.3: k = HMAC_SHA256(k, V || 0x00)
            let mut hmac = HmacSha256::new_from_slice(&k_hmac).expect("HMAC can be created");
            hmac.update(&v); // V
            hmac.update(&[0x00]); // 0x00
            k_hmac.copy_from_slice(&hmac.finalize().into_bytes());

            // Step g.4: V = HMAC_SHA256(k, V)
            let mut hmac = HmacSha256::new_from_slice(&k_hmac).expect("HMAC can be created");
            hmac.update(&v); // V
            v.copy_from_slice(&hmac.finalize().into_bytes());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    pub point: G1AffinityPoint,
}

impl PublicKey {
    pub fn new(point: G1AffinityPoint) -> Self {
        Self { point }
    }

    // Add the verify_signature method here
    pub fn verify_signature(&self, message_hash: U256, signature: &Signature) -> bool {
        let n = G1AffinityPoint::N;
        let z = F256K1::from(message_hash);
        let u = z.div(signature.s).unwrap().as_u256() % n;
        let u = F256K1::from(u);
        let v = signature.r.div(signature.s).unwrap().as_u256() % n;
        let v = F256K1::from(v);
        let g = G1AffinityPoint::generator();
        let total = g * u + self.point * v;
        total.x().as_u256() == signature.r.as_u256()
    }
}

#[cfg(test)]
mod test {
    use sha2::Digest;

    use super::*;

    #[test]
    fn test_simple_signature_verification() {
        // Simple test to ensure basic sign and verify works
        let private_key_scalar = U256::from(42); // A simple private key scalar
        let private_key = PrivateKey::new(private_key_scalar);
        let public_key = private_key.publick_key;

        let message = b"Test message for simple verification.";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = U256::from_big_endian(&hasher.finalize());

        let signature = private_key
            .sign(message_hash)
            .expect("Signing failed in simple test");

        let is_valid = public_key.verify_signature(message_hash, &signature);
        assert!(is_valid, "Simple signature verification failed");
        println!(
            "Simple signature verification passed for message: {:?}",
            String::from_utf8_lossy(message)
        );
    }

    #[test]
    fn test_rfc6979_k_reproducibility() {
        // Test that k is deterministic for the same private key and message hash
        let private_key_scalar =
            U256::from("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let private_key_1 = PrivateKey::new(private_key_scalar);
        let private_key_2 = PrivateKey::new(private_key_scalar); // Same private key

        let message = b"Deterministic k test message";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash = U256::from_big_endian(&hasher.finalize());

        let sig1 = private_key_1.sign(message_hash).expect("Sig1 failed");
        let sig2 = private_key_2.sign(message_hash).expect("Sig2 failed");

        // The signatures should be identical if k generation is truly deterministic
        assert_eq!(sig1.r, sig2.r);
        assert_eq!(sig1.s, sig2.s);
        println!("Deterministic k test passed: Signatures are identical.");
    }

    #[test]
    fn test_verify_from_book() {
        let z_scalar = U256::from_str_radix(
            "0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423",
            16,
        )
        .unwrap();
        let r_scalar = U256::from_str_radix(
            "0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .unwrap();
        let s_scalar = U256::from_str_radix(
            "0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .unwrap();
        let px_scalar = U256::from_str_radix(
            "0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574",
            16,
        )
        .unwrap();
        let py_scalar = U256::from_str_radix(
            "0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4",
            16,
        )
        .unwrap();

        // Convert scalars to F256K1 field elements
        let z = F256K1::new(z_scalar);
        let r = F256K1::new(r_scalar);
        let s = F256K1::new(s_scalar);
        let px = F256K1::new(px_scalar);
        let py = F256K1::new(py_scalar);

        let public_key_point = G1AffinityPoint::new(px, py).expect("Point not in curve");

        // Calculate u = z * s_inv % N
        let u = z.div(s).expect("s should have an inverse");

        // Calculate v = r * s_inv % N
        let v = r.div(s).expect("s should have inverse");

        // Get the generator point G
        let g = G1AffinityPoint::generator();

        // Calculate the combined point (u*G + v*point)
        let total_point = (g * u) + (public_key_point * v);

        // Compare the x-coordinate of the combined point with r
        let result = total_point.x().as_u256() == r.as_u256();

        assert!(result, "Raw verification from book example failed.");
    }
}
