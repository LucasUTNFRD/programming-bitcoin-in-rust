//! Implementation of secp256k1 Bitcoin Elliptic Curve
// • a = 0, b = 7, making the equation y2 = x3 + 7
// • p = 2^256 – 2^32 – 977
// • Gx =
// 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
// • Gy =
// 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
// • n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

use primitive_types::U256;

use super::{
    field_element::{FieldElement, FieldParameter, FiniteField},
    point::G1Point,
};

const SECP256K1_PRIME: U256 = U256([
    0xFFFFFFFFFFFFFFFF, // First 64 bits (little-endian)
    0xFFFFFFFFFFFFFFFF, // Next 64 bits
    0xFFFFFFFFFFFFFFFF, // Next 64 bits
    0xFFFFFFFEFFFFFC2F, // Last 64 bits
]);

#[derive(Eq, PartialEq, Debug, Clone, Copy, PartialOrd, Ord)]
pub struct Mod {}

impl FieldParameter for Mod {
    const MODULUS: U256 = SECP256K1_PRIME;
}

type F256K1 = FieldElement<Mod>;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum G1AffinityPoint {
    Coordinate { x: F256K1, y: F256K1 },
    Infinity,
}
