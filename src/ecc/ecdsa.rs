use std::fmt::Display;

use crate::ecc::point::G1Point;

use super::{
    error::Error,
    field_element::{FiniteField, biguint_to_u256, mod_exp, mul_and_mod, u256_to_biguint},
    secp256k1::{A, F256K1, G1AffinityPoint},
};
use hmac::{Hmac, Mac};
use primitive_types::U256;
use sha2::{Digest, Sha256};

/// Represents an ECDSA signature, consisting of two scalar values, r and s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    r: F256K1,
    s: F256K1,
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
}

type HmacSha256 = Hmac<Sha256>;

impl PrivateKey {
    pub fn new(secret: U256) -> Self {
        let secret = F256K1::from(secret);
        let g = G1AffinityPoint::g();
        Self { secret }
    }

    /// Derives the public key corresponding to this private key.
    /// pubKey = privateKey * G (where G is the generator point)
    pub fn public_key(&self) -> PublicKey {
        let generator = G1AffinityPoint::g();
        PublicKey {
            point: generator * self.secret,
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
        let n = G1AffinityPoint::N;
        let k =
            Self::generate_deterministic_k_scalar(self.secret.as_u256(), message_hash, n).unwrap();

        let k_inv = mod_exp(k, n - 2, n);

        let r = (G1AffinityPoint::g() * k.into()).x().as_u256();

        // Calculate s = (z + r * e) * k_inv % N
        let z_big = u256_to_biguint(message_hash);
        let r_big = u256_to_biguint(r);
        let e_big = u256_to_biguint(self.secret.as_u256());
        let k_inv_big = u256_to_biguint(k_inv);
        let n_big = u256_to_biguint(n);
        let s = biguint_to_u256((z_big + r_big * e_big) * k_inv_big % n_big);

        let final_s = if s > n / 2 { n - s } else { s };

        // TODO: we should do this until we get Some(siganture);
        Some(Signature::new(r.into(), final_s.into()))
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
    // Add the verify_signature method here
    pub fn verify_signature(&self, message_hash: U256, signature: &Signature) -> bool {
        let n = G1AffinityPoint::N;

        let s_inv = mod_exp(
            signature.s.as_u256(),
            G1AffinityPoint::N - 2,
            G1AffinityPoint::N,
        );
        let u = mul_and_mod(message_hash, s_inv, n);
        let v = mul_and_mod(signature.r.as_u256(), s_inv, n);
        let total = G1AffinityPoint::g() * u.into() + self.point * v.into();
        total.x() == signature.r
    }

    pub fn parse(p: &[u8; 65]) -> Result<Self, Error> {
        if p[0] != 4 {
            return Err(Error::InvalidPublicKey);
        }
        let x = U256::from_big_endian(&p[1..33]);
        let y = U256::from_big_endian(&p[33..65]);

        let point = G1AffinityPoint::new(x.into(), y.into())?;

        Ok(Self { point })
    }

    pub fn parse_compressed(p: &[u8; 33]) -> Result<Self, Error> {
        if p[0] != 0x2 && p[0] != 0x3 {
            return Err(Error::InvalidPublicKey);
        }
        let is_even = p[0] == 2;

        let x = F256K1::from(U256::from_big_endian(&p[1..33]));
        let alpha = x.pow(3.into()) + F256K1::from(A);
        let beta = alpha.sqrt();
        let p = F256K1::modulus();
        let (even_beta, odd_beta) = if beta.is_even() {
            (beta, F256K1::from(p - beta.as_u256()))
        } else {
            (F256K1::from(p - beta.as_u256()), beta)
        };
        let point = if is_even {
            G1AffinityPoint::new(x.into(), even_beta)
        } else {
            G1AffinityPoint::new(x.into(), odd_beta)
        }?;

        Ok(Self { point })
    }

    pub fn serialize(&self) -> [u8; 33] {
        let mut result = [0u8; 33];
        let x_bytes = self.point.x().as_u256().to_big_endian();
        result[0] = if self.point.y().is_even() { 0x02 } else { 0x03 };
        result[1..33].copy_from_slice(&x_bytes);
        result
    }

    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        let x_bytes = self.point.x().as_u256().to_big_endian();
        let y_bytes = self.point.y().as_u256().to_big_endian();

        let mut result = [0u8; 65];
        result[0] = 0x04;
        result[1..33].copy_from_slice(&x_bytes);
        result[33..65].copy_from_slice(&y_bytes);
        result
    }
}

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

#[cfg(test)]
mod test {
    use sha2::Digest;

    use crate::ecc::field_element::{biguint_to_u256, mod_exp, mul_and_mod, u256_to_biguint};

    use super::*;

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
        // let s = F256K1::new(s_scalar);
        let px = F256K1::new(px_scalar);
        let py = F256K1::new(py_scalar);
        let n = G1AffinityPoint::N;
        let g = G1AffinityPoint::g();
        // dbg!(z, r, s, px, py);

        let public_key_point = G1AffinityPoint::new(px, py).expect("Point not in curve");

        // >>> s_inv = pow(s, N-2, N)  # <1>
        let s_inv = mod_exp(s_scalar, G1AffinityPoint::N - 2, G1AffinityPoint::N);
        let expect_s_inv = U256::from_str_radix(
            "0xb83305e1d30225f64091c2cb21aa08e938cea1b3ffbdc9397ff139411c21ccc5",
            16,
        )
        .unwrap();
        assert_eq!(s_inv, expect_s_inv);

        let expected_u = U256::from_str_radix(
            "0x35833101b5a69ad2433064be2790cbe7d932dfcd5220ce787b6b547ea26b6f7e",
            16,
        )
        .unwrap();

        // >>> u = z * s_inv % N  # <2>
        let u = mul_and_mod(z_scalar, s_inv, n);

        assert_eq!(u, expected_u);
        //
        // >>> v = r * s_inv % N  # <3>
        let expected_v = U256::from_str_radix(
            "0x7e375e66cdf9ee88ec757e65fe3eacc5847819e89586d140c52f6f02797662c",
            16,
        )
        .unwrap();
        let v = mul_and_mod(r_scalar, s_inv, n);
        assert_eq!(v, expected_v);

        // >>> print((u*G + v*point).x.num == r)  # <4>
        let total = g * u.into() + public_key_point * v.into();
        assert_eq!(total.x(), r)
    }

    #[test]
    fn test_ecdsa_signature_verification() {
        // 1. Generate a private key
        let private_key_scalar =
            U256::from("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        let private_key = PrivateKey::new(private_key_scalar);

        // 2. Derive the public key from the private key
        let public_key = private_key.public_key(); // Corrected: calling method on PrivateKey instance

        // 3. Define a message and hash it
        let message = b"Hello, world!";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let message_hash_bytes = hasher.finalize();
        let message_hash = U256::from_big_endian(&message_hash_bytes); // This is 'z'

        // 4. Sign the message hash (k is now generated deterministically internally)
        let signature = private_key.sign(message_hash).expect("Signature failed");

        dbg!("Original Message: {:?}", String::from_utf8_lossy(message));
        dbg!("Message Hash: 0x{:x}", message_hash);
        dbg!("Private Key Scalar: 0x{:x}", private_key.secret.as_u256());
        dbg!("Public Key Point: {}", public_key.point); // Access the point field of PublicKey
        dbg!(
            "Signature (r, s): (0x{:x}, 0x{:x})",
            signature.r.as_u256(),
            signature.s.as_u256()
        );

        // 5. Verify the signature using the PublicKey instance
        let is_valid = public_key.verify_signature(message_hash, &signature);
        dbg!("Signature valid: {}", is_valid);
        assert!(
            is_valid,
            "Signature should be valid for the original message"
        );

        // Test with a tampered message
        let tampered_message = b"Hello, earth!";
        let mut tampered_hasher = Sha256::new();
        tampered_hasher.update(tampered_message);
        let tampered_message_hash_bytes = tampered_hasher.finalize();
        let tampered_message_hash = U256::from_big_endian(&tampered_message_hash_bytes);

        let is_tampered_valid = public_key.verify_signature(tampered_message_hash, &signature);
        dbg!(
            "Tampered Message: {:?}",
            String::from_utf8_lossy(tampered_message)
        );
        dbg!("Tampered Message Hash: 0x{:x}", tampered_message_hash);
        dbg!("Tampered signature valid: {}", is_tampered_valid);
        assert!(
            !is_tampered_valid,
            "Signature should be invalid for a tampered message"
        );

        // Test with a tampered signature (e.g., change r)
        let mut bad_signature = signature;
        // Increment r, ensuring it stays within the field if possible for a subtle change
        bad_signature.r = F256K1::new((signature.r.as_u256() + U256::from(1)) % G1AffinityPoint::N);
        let is_bad_signature_valid = public_key.verify_signature(message_hash, &bad_signature);
        dbg!(
            "Bad Signature (r changed) valid: {}",
            is_bad_signature_valid
        );
        assert!(
            !is_bad_signature_valid,
            "Signature should be invalid if r is changed"
        );
    }
    //
    #[test]
    fn test_signature_from_book() {
        let private_key_scalar = U256::from(12345);
        let k_scalar = U256::from(1234567890);

        // Hash the message "Programming Bitcoin!"
        let message = b"Programming Bitcoin!";
        let hashed_message = hash256(message);
        let z_scalar = U256::from_big_endian(&hashed_message);
        // Expected values from the book's Python output
        let expected_z_scalar = U256::from_str_radix(
            "0x969f6056aa26f7d2795fd013fe88868d09c9f6aed96965016e1936ae47060d48",
            16,
        )
        .unwrap();
        let expected_r_scalar = U256::from_str_radix(
            "0x2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            16,
        )
        .unwrap();
        let expected_s_scalar = U256::from_str_radix(
            "0x1dbc63bfef4416705e602a7b564161167076d8b20990a0f26f316cff2cb0bc1a",
            16,
        )
        .unwrap();

        // Assert the computed hash matches the expected hash from the book
        assert_eq!(z_scalar, expected_z_scalar, "Message hash 'z' mismatch");

        let n = G1AffinityPoint::N;
        let g = G1AffinityPoint::g();

        // Calculate r = (k*G).x.num
        let r_point = g * k_scalar.into();
        let r = r_point.x().as_u256();
        assert_eq!(r, expected_r_scalar);

        // Calculate k_inv = pow(k, N-2, N)
        let k_inv = mod_exp(k_scalar, n - 2, n);
        dbg!(k_inv);

        // Calculate s = (z + r * e) * k_inv % N
        let z = u256_to_biguint(z_scalar);
        dbg!(&z);
        let r = u256_to_biguint(r);
        dbg!(&r);
        let e = u256_to_biguint(private_key_scalar);
        // dbg!(&r * &e);
        let k_inv_big = u256_to_biguint(k_inv);
        let mod_big = u256_to_biguint(n);
        let s = (z + r * e) * k_inv_big % mod_big;
        dbg!(&s);
        let s = biguint_to_u256(s);

        // Apply low-s normalization: if s > N / 2: s = N - s
        let half_n = n / 2;
        let s_val = s;
        let s_final = if s_val > half_n {
            F256K1::new(n - s_val)
        } else {
            s.into()
        };
        dbg!(s);

        // Assert calculated r and s match expected values
        // assert_eq!(r, expected_r_scalar, "Signature R value mismatch");
        assert_eq!(
            s_final.as_u256(),
            expected_s_scalar,
            "Signature S value mismatch"
        );

        println!("Signature generation from book example passed!");
        // println!("Calculated r: 0x{:x}", r);
        println!("Calculated s: 0x{:x}", s_final.as_u256());
    }
}
