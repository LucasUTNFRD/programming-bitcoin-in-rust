use std::fmt::Display;

use crate::{
    base58::{self},
    ecc::point::G1Point,
    error::Error,
};

use super::{
    field_element::{FiniteField, biguint_to_u256, mod_exp, mul_and_mod, u256_to_biguint},
    secp256k1::{A, F256K1, G1AffinityPoint},
};
use hmac::{Hmac, Mac};
use primitive_types::{H256, U256};
use sha2::Sha256;

const WIF_MAINNET_PREFIX: u8 = 0x80;
const WIF_TESTNET_PREFIX: u8 = 0xEF;
const WIF_COMPRESSED_SUFFIX: u8 = 0x01;
const SECRET_KEY_SIZE: usize = 32;
const CHECKSUM_SIZE: usize = 4;

const WIF_UNCOMPRESSED_SIZE: usize = 1 + SECRET_KEY_SIZE + CHECKSUM_SIZE; // 37 bytes
const WIF_COMPRESSED_SIZE: usize = 1 + SECRET_KEY_SIZE + 1 + CHECKSUM_SIZE; // 38 bytes

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

    // TODO: enconde_der_integer without vec<u8>

    /// Helper function to encode a U256 into DER INTEGER format.
    /// This produces a byte vector: [0x02, len, value_bytes].
    fn encode_der_integer(value: U256) -> Vec<u8> {
        let mut bytes = value.to_big_endian().to_vec(); // Start with 32 bytes (for U256)
        // 1. Trim leading zero bytes (unless the number itself is 0, or the zero is needed for positive encoding)
        let mut first_non_zero_idx = 0;
        // Keep at least one byte if the number is 0 (i.e., `bytes` becomes `[0x00]`)
        // or if `bytes` contains other non-zero values after leading zeros.
        while first_non_zero_idx < bytes.len() - 1 && bytes[first_non_zero_idx] == 0x00 {
            first_non_zero_idx += 1;
        }
        bytes = bytes[first_non_zero_idx..].to_vec();

        // Handle the special case where the value itself is 0
        if bytes.is_empty() {
            bytes.push(0x00);
        }

        // 2. Prepend 0x00 if the most significant bit of the first byte is set.
        // This ensures positive numbers are not interpreted as negative in DER.
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0x00);
        }

        let value_len = bytes.len();
        let mut der_int = Vec::with_capacity(2 + value_len); // Tag + Length + Value

        der_int.push(0x02); // DER INTEGER tag
        der_int.push(value_len as u8); // Length of the integer's value (fits in one byte for U256)
        der_int.extend_from_slice(&bytes); // Add the actual value bytes

        der_int
    }

    const SEQUENCE_TAG: u8 = 0x30;
    pub fn serialize_der(&self) -> Vec<u8> {
        // Encode r and s as DER integers
        let r_der = Signature::encode_der_integer(self.r.as_u256());
        let s_der = Signature::encode_der_integer(self.s.as_u256());

        let total_content_len = r_der.len() + s_der.len();

        let mut der_signature = Vec::new();
        der_signature.push(Self::SEQUENCE_TAG); // DER SEQUENCE tag

        // Encode the total content length.
        // For secp256k1 signatures, r and s are U256, max DER integer length is 33 bytes.
        // So, r_der or s_der max length is 2 (tag+len) + 33 (value) = 35 bytes.
        // Max total_content_len = 35 + 35 = 70 bytes.
        // Since 70 < 128, a single byte is sufficient for the length.
        der_signature.push(total_content_len as u8);

        // Append the DER-encoded r and s integers
        der_signature.extend_from_slice(&r_der);
        der_signature.extend_from_slice(&s_der);

        der_signature
    }

    pub fn parse(raw_signature: &[u8]) -> Result<Self, Error> {
        // Check for DER sequence tag
        if raw_signature.len() < 2 || raw_signature[0] != 0x30 {
            return Err(Error::InvalidDER);
        }
        let total_len = raw_signature[1] as usize;
        if raw_signature.len() < 2 + total_len {
            return Err(Error::InvalidDER);
        }
        let mut pos = 2;

        // Parse r
        if raw_signature[pos] != 0x02 {
            return Err(Error::InvalidDER);
        }
        pos += 1;
        let r_len = raw_signature[pos] as usize;
        pos += 1;
        let r_bytes = &raw_signature[pos..pos + r_len];
        pos += r_len;

        // Parse s
        if raw_signature[pos] != 0x02 {
            return Err(Error::InvalidDER);
        }
        pos += 1;
        let s_len = raw_signature[pos] as usize;
        pos += 1;
        let s_bytes = &raw_signature[pos..pos + s_len];
        // pos += s_len;

        // Convert r and s to U256
        // Handle DER integers that may have leading zeros or be longer than 32 bytes
        let r = if r_bytes.len() <= 32 {
            let mut r_arr = [0u8; 32];
            // Pad left with zeros if shorter than 32 bytes
            r_arr[32 - r_bytes.len()..].copy_from_slice(r_bytes);
            U256::from_big_endian(&r_arr)
        } else {
            // If longer than 32 bytes, it likely has a leading zero for DER encoding
            // Skip leading zeros and take the last 32 bytes
            let start_idx = r_bytes.len().saturating_sub(32);
            let relevant_bytes = &r_bytes[start_idx..];
            U256::from_big_endian(relevant_bytes)
        };

        let s = if s_bytes.len() <= 32 {
            let mut s_arr = [0u8; 32];
            // Pad left with zeros if shorter than 32 bytes
            s_arr[32 - s_bytes.len()..].copy_from_slice(s_bytes);
            U256::from_big_endian(&s_arr)
        } else {
            // If longer than 32 bytes, it likely has a leading zero for DER encoding
            // Skip leading zeros and take the last 32 bytes
            let start_idx = s_bytes.len().saturating_sub(32);
            let relevant_bytes = &s_bytes[start_idx..];
            U256::from_big_endian(relevant_bytes)
        };

        Ok(Signature::new(r.into(), s.into()))
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

    pub fn serialize_wif(&self, testnet: bool, compressed: bool) -> String {
        let data_size = if compressed {
            WIF_COMPRESSED_SIZE - CHECKSUM_SIZE
        } else {
            WIF_UNCOMPRESSED_SIZE - CHECKSUM_SIZE
        };
        let mut data = Vec::with_capacity(data_size + CHECKSUM_SIZE);

        data.push(if testnet {
            WIF_TESTNET_PREFIX
        } else {
            WIF_MAINNET_PREFIX
        });

        let secret_bytes = self.secret.as_u256().to_big_endian();
        data.extend_from_slice(&secret_bytes);

        if compressed {
            data.push(WIF_COMPRESSED_SUFFIX);
        }

        base58::encode_with_checksum(&data)
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
    fn generate_deterministic_k_scalar(
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
            G1AffinityPoint::new(x, even_beta)
        } else {
            G1AffinityPoint::new(x, odd_beta)
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

#[cfg(test)]
mod test {
    use hex::ToHex;
    use sha2::Digest;

    use super::*;

    #[test]
    fn test_rfc6979_k_reproducibility() {
        // Test thatsec k is deterministic for the same private key and message hash
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

    #[test]
    fn test_der_serialization() {
        let r = U256::from_str_radix(
            "0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .unwrap();
        let s = U256::from_str_radix(
            "0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .unwrap();

        let sig = Signature::new(r.into(), s.into());

        let serialized_der = sig.serialize_der();
        println!("{serialized_der:?}");
        let sig_der_serialized = hex::encode(serialized_der);

        let expected_der_signature = "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6022100\
8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";
        assert_eq!(sig_der_serialized, expected_der_signature)
    }

    #[test]
    fn test_der_parsing() {
        let signature_bytes = [
            48, 69, 2, 32, 55, 32, 106, 6, 16, 153, 92, 88, 7, 73, 153, 203, 151, 103, 184, 122,
            244, 196, 151, 141, 182, 140, 6, 232, 230, 232, 29, 40, 32, 71, 167, 198, 2, 33, 0,
            140, 166, 55, 89, 193, 21, 126, 190, 174, 192, 208, 60, 236, 202, 17, 159, 201, 167,
            91, 248, 230, 208, 250, 101, 200, 65, 200, 226, 115, 140, 218, 236,
        ];

        let sig_from_bytes = Signature::parse(&signature_bytes).unwrap();

        let r = U256::from_str_radix(
            "0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .unwrap();
        let s = U256::from_str_radix(
            "0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .unwrap();

        let sig = Signature::new(r.into(), s.into());

        assert_eq!(sig, sig_from_bytes)
    }

    #[test]
    fn test_parse_signature() {
        let r = U256::from_str_radix(
            "0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .unwrap();
        let s = U256::from_str_radix(
            "0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .unwrap();

        let sig = "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";
        let sig_encode = hex::decode(sig).unwrap();
        let sig_parsed = Signature::parse(&sig_encode).unwrap();
        assert_eq!(sig_parsed.r, r.into());
        assert_eq!(sig_parsed.s, s.into());
    }

    #[test]
    fn serialize_wif() {
        let secret_key = U256::from(5003);
        let private_key = PrivateKey::new(secret_key);
        let wif = private_key.serialize_wif(true, true);
        assert_eq!(wif, "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK");
    }
}
