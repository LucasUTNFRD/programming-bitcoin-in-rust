//! Implementation of secp256k1 Bitcoin Elliptic Curve
// • a = 0, b = 7, making the equation y2 = x3 + 7
// • p = 2^256 – 2^32 – 977
// • Gx =
// 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
// • Gy =
// 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
// • n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

use std::{
    fmt::Display,
    ops::{Add, Div, Mul, Neg, Sub},
};

use primitive_types::U256;

use super::{
    ecdsa::Signature,
    field_element::{FieldElement, FieldParameter, FiniteField},
    point::{Error, G1Point},
};

pub const SECP256K1_PRIME: U256 = U256([
    0xFFFFFFFEFFFFFC2F, // Last 64 bits
    0xFFFFFFFFFFFFFFFF, // First 64 bits (little-endian)
    0xFFFFFFFFFFFFFFFF, // Next 64 bits
    0xFFFFFFFFFFFFFFFF, // Next 64 bits
]);

const G_X_HEX: &str = "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G_Y_HEX: &str = "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

const A: U256 = U256([7, 0, 0, 0]);

#[derive(Eq, PartialEq, Debug, Clone, Copy, PartialOrd, Ord)]
pub struct Mod {}

impl FieldParameter for Mod {
    const MODULUS: U256 = SECP256K1_PRIME;
}

pub type F256K1 = FieldElement<Mod>;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum G1AffinityPoint {
    Coordinate { x: F256K1, y: F256K1 },
    Infinity,
}

impl G1AffinityPoint {
    pub fn is_valid(self) -> bool {
        match self {
            G1AffinityPoint::Infinity => true,
            G1AffinityPoint::Coordinate { x, y } => {
                let y_squared = y * y;
                let x_cubed = x * x * x;
                let a_term = F256K1::new(A);
                let result = y_squared - x_cubed - a_term;

                result == F256K1::zero()
            }
        }
    }

    pub fn verify_signature(&self, message_hash: U256, signatura: &Signature) -> bool {
        let n = G1AffinityPoint::N;
        todo!()
    }

    pub fn x(&self) -> F256K1 {
        match self {
            Self::Coordinate { x, y: _ } => *x,
            _ => unimplemented!(),
        }
    }

    pub fn y(&self) -> F256K1 {
        match self {
            Self::Coordinate { x: _, y } => *y,
            _ => unimplemented!(),
        }
    }
}

impl G1Point for G1AffinityPoint {
    type Field = F256K1;
    type SubField = F256K1; //Scalar Field

    const N: U256 = SECP256K1_ORDER;

    fn new(x: Self::Field, y: Self::Field) -> Result<Self, Error> {
        let coord = Self::Coordinate { x, y };
        if !coord.is_valid() {
            Err(Error::CoordinateNotInCurve)
        } else {
            Ok(coord)
        }
    }

    fn is_identity(&self) -> bool {
        matches!(self, Self::Infinity)
    }

    fn generator() -> Self {
        let gx = U256::from_str_radix(G_X_HEX, 16).unwrap();
        let gy = U256::from_str_radix(G_Y_HEX, 16).unwrap();
        Self::Coordinate {
            x: F256K1::new(gx),
            y: F256K1::new(gy),
        }
    }

    fn identity() -> Self {
        Self::Infinity
    }
}

impl Display for G1AffinityPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Infinity => write!(f, "infinite"),
            Self::Coordinate { x, y } => write!(f, "({},{})", x, y),
        }
    }
}

impl Add for G1AffinityPoint {
    type Output = G1AffinityPoint;

    fn add(self, rhs: Self) -> Self::Output {
        // anything added to Infinity is itself
        match (self, rhs) {
            (_, Self::Infinity) => self,
            (Self::Infinity, _) => rhs,
            _ if self == -rhs => G1AffinityPoint::identity(),
            _ => {
                // let lambda;
                // Rule: P + P (Point Doubling)
                let lambda = if self == rhs {
                    // lambda = (3x^2) / (2y)
                    let three = F256K1::new(U256::from(3));
                    let two = F256K1::new(U256::from(2));
                    let x_squared = self.x() * self.x();
                    let numerator = three * x_squared;
                    let denominator = two * self.y();
                    numerator
                        .div(denominator)
                        .expect("Division by zero in point doubling (y-coordinate is zero)")
                } else {
                    // Rule: P1 + P2 (General point addition for distinct points)
                    // lambda = (y2 - y1) / (x2 - x1)
                    let numerator = rhs.y() - self.y();
                    let denominator = rhs.x() - self.x();
                    numerator.div(denominator).expect(
                        "Division by zero in point addition (x-coordinates are same, not inverses)",
                    )
                };

                // New point coordinates:
                // x3 = lambda^2 - x1 - x2
                let x = lambda.pow(U256::from(2)) - self.x() - rhs.x();
                // y3 = lambda * (x1 - x3) - y1
                let y = lambda * (self.x() - x) - self.y();

                // It's important to ensure the resulting point is on the curve.
                // The math for elliptic curve addition ensures this, so we unwrap here assuming correctness
                G1AffinityPoint::new(x, y).unwrap()
            }
        }
    }
}

impl Sub for G1AffinityPoint {
    type Output = G1AffinityPoint;
    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs) // P - Q = P + (-Q)
    }
}

impl Neg for G1AffinityPoint {
    type Output = G1AffinityPoint;
    fn neg(self) -> Self::Output {
        match self {
            Self::Infinity => self,
            Self::Coordinate { x, y } => G1AffinityPoint::new(x, -y).unwrap(),
        }
    }
}

const SECP256K1_ORDER: U256 = U256([
    0xbfd25e8cd0364141,
    0xbaaedce6af48a03b,
    0xfffffffffffffffe,
    0xffffffffffffffff,
]);

impl Mul<F256K1> for G1AffinityPoint {
    type Output = G1AffinityPoint;
    fn mul(self, rhs: F256K1) -> Self::Output {
        let mut scalar = rhs.as_u256() % SECP256K1_ORDER;

        if scalar.is_zero() || self.is_identity() {
            return Self::Infinity;
        }

        let mut result = G1AffinityPoint::identity();
        let mut base = self;

        while scalar > U256::zero() {
            if scalar.bit(0) {
                result = result + base
            }
            scalar >>= 1;
            base = base + base;
        }

        result
    }
}

#[cfg(test)]
mod test {
    use primitive_types::U256;

    use crate::ecc::{point::G1Point, secp256k1::SECP256K1_ORDER};

    use super::{F256K1, G_X_HEX, G_Y_HEX, G1AffinityPoint};

    #[test]
    fn test_generator_on_curve() {
        let gx = U256::from_str_radix(G_X_HEX, 16).unwrap();
        let gy = U256::from_str_radix(G_Y_HEX, 16).unwrap();

        let x = F256K1::new(gx);
        let y = F256K1::new(gy);
        let g = G1AffinityPoint::new(x, y);
        assert!(g.is_ok())
    }

    #[test]
    //We can now define G directly and keep it around since we’ll be using it a lot going
    // forward:
    // G = S256Point(
    //     0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    //     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
    // Now checking that the order of G is n is trivial:
    // >>> from ecc import G, N
    // >>> print(N*G)
    // S256Point(infinity)
    fn n_times_g_gives_identity() {
        let n = F256K1::new(SECP256K1_ORDER);

        let g = G1AffinityPoint::generator();
        let result = g * n;
        assert_eq!(result, G1AffinityPoint::Infinity)
    }

    #[test]
    fn test_mul_and_sum() {
        let g = G1AffinityPoint::generator();
        let scalar = F256K1::new(U256::from(2));
        assert_eq!(g + g, g * scalar);
    }

    #[test]
    fn test_mul_and_sum_1() {
        let g = G1AffinityPoint::generator();
        let scalar = F256K1::new(U256::from(3));
        assert_eq!(g + g + g, g * scalar);
    }

    #[test]
    fn test_order() {
        let n = U256::from_str_radix(
            "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap();

        assert_eq!(SECP256K1_ORDER, n);
    }
}
