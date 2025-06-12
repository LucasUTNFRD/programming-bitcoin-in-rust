use std::{
    fmt::{Debug, Display},
    ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num_bigint::BigUint;
use primitive_types::U256;

pub trait FiniteField:
    Sized               // Size known at compile time
    + From<U256>         // Can create an element from u256
    + Debug+ Display // For debugging and printing
    + Copy              // Easy to copy during assignment
    // Mathemetical Operations ----
    + Neg<Output=Self>
    + Add<Self, Output=Self> + AddAssign<Self> // For + and +=
    + Sub<Self, Output=Self> + SubAssign<Self> // For - and -=
    + Mul<Self, Output=Self> + MulAssign<Self> // For * and *=
    + Div<Self, Output=Option<Self>>
    // Mathemetical Operations ----
{
    /// Order or cardinality of the field
    fn modulus() -> U256;

    /// Gives the zero element and one element
    /// the multiplicative and additive identities
    fn one() -> Self;
    fn zero() -> Self;

    /// Check whether element is identity
    /// element
    fn is_one(&self) -> bool;
    fn is_zero(&self) -> bool;

    /// Calculates the inverse of a non-zeo
    /// element. Returns `None` if is_zero
    fn inverse(&self) -> Option<Self>;

    /// Raise element to some power
    fn pow(&self, exp: U256) -> Self;

    /// Export to u256
    fn as_u256(&self) -> U256;
}

pub trait FieldParameter: Copy + Debug {
    const MODULUS: U256;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldElement<P: FieldParameter> {
    value: U256,
    _phantom: std::marker::PhantomData<P>,
}

impl<P: FieldParameter> FieldElement<P> {
    pub fn new(value: U256) -> Self {
        assert!(
            value < P::MODULUS,
            "FieldElement value must be less than the modulus"
        );

        Self {
            value,
            _phantom: std::marker::PhantomData,
        }
    }
}

pub fn u256_to_biguint(u: U256) -> BigUint {
    let base_bytes = U256::to_big_endian(&u);
    BigUint::from_bytes_be(&base_bytes)
}

pub fn biguint_to_u256(b: BigUint) -> U256 {
    let bytes = b.to_bytes_be();
    dbg!(&bytes.len());
    U256::from_big_endian(&bytes)
}

pub fn mod_exp(base: U256, exp: U256, modulus: U256) -> U256 {
    let base_biguint = u256_to_biguint(base);
    let exp_biguint = u256_to_biguint(exp);
    let modulus_biguint = u256_to_biguint(modulus);

    // Perform modular exponentiation with BigUint
    let result_biguint = base_biguint.modpow(&exp_biguint, &modulus_biguint);

    // Convert back to U256
    let result_bytes = result_biguint.to_bytes_be();
    U256::from_big_endian(&result_bytes)
}

impl<P: FieldParameter> Display for FieldElement<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Point_{}({})", P::MODULUS, self.value)
    }
}

impl<P: FieldParameter> From<U256> for FieldElement<P> {
    fn from(value: U256) -> Self {
        Self::new(value)
    }
}

impl<P: FieldParameter> FiniteField for FieldElement<P> {
    fn modulus() -> U256 {
        P::MODULUS
    }

    fn one() -> Self {
        Self::new(U256::one())
    }

    fn zero() -> Self {
        Self::new(U256::zero())
    }

    fn is_one(&self) -> bool {
        self.value == U256::one()
    }

    fn is_zero(&self) -> bool {
        self.value.is_zero()
    }

    fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        // Use Fermat's Little Theorem: a^(p-2) ≡ a^(-1) (mod p) for prime p
        let modulus = P::MODULUS;
        let exp = modulus - U256::from(2u64);
        let inv_value = mod_exp(self.value, exp, modulus);
        Some(Self::new(inv_value))
    }

    fn pow(&self, exp: U256) -> Self {
        let result = mod_exp(self.value, exp, P::MODULUS);
        Self::new(result)
    }

    fn as_u256(&self) -> U256 {
        self.value
    }
}

/// util function for signature verification where we use an specific inverse using as modulus the
/// order of the group
pub fn mul_and_mod(lhs: U256, rhs: U256, modulus: U256) -> U256 {
    let self_big = u256_to_biguint(lhs);
    let rhs_big = u256_to_biguint(rhs);
    let mod_big = u256_to_biguint(modulus);

    let result_big = (self_big * rhs_big) % mod_big;
    biguint_to_u256(result_big)
}

// Arithmetic Operations
impl<P: FieldParameter> Add for FieldElement<P> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let a = u256_to_biguint(self.value);
        let b = u256_to_biguint(rhs.value);
        let modulus = u256_to_biguint(P::MODULUS);
        let sum = (a + b) % modulus;
        Self::new(biguint_to_u256(sum))
    }
}

impl<P: FieldParameter> AddAssign for FieldElement<P> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<P: FieldParameter> Sub for FieldElement<P> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        // let modulus = P::MODULUS;
        // let diff = if self.value >= rhs.value {
        //     self.value - rhs.value
        // } else {
        //     modulus - (rhs.value - self.value)
        // };
        let a = u256_to_biguint(self.value);
        let b = u256_to_biguint(rhs.value);
        let modulus = u256_to_biguint(P::MODULUS);
        let diff = if a > b {
            (a - b) % modulus
        } else {
            (&modulus - (b - a)) % &modulus
        };
        Self::new(biguint_to_u256(diff))
    }
}

impl<P: FieldParameter> SubAssign for FieldElement<P> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<P: FieldParameter> Mul for FieldElement<P> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let self_big = u256_to_biguint(self.value);
        let rhs_big = u256_to_biguint(rhs.value);
        let mod_big = u256_to_biguint(P::MODULUS);

        let result_big = dbg!(self_big * rhs_big) % mod_big;

        Self::new(biguint_to_u256(result_big))
    }
}

impl<P: FieldParameter> MulAssign for FieldElement<P> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<P: FieldParameter> Div for FieldElement<P> {
    type Output = Option<Self>;

    fn div(self, rhs: Self) -> Self::Output {
        rhs.inverse().map(|inv| self * inv)
    }
}

impl<P: FieldParameter> Neg for FieldElement<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self.is_zero() {
            self
        } else {
            Self::new(P::MODULUS - self.value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;

    // Test field parameters for different primes
    #[derive(Copy, PartialEq, Clone, Debug)]
    struct SmallPrime;
    impl FieldParameter for SmallPrime {
        const MODULUS: U256 = U256([17, 0, 0, 0]); // 17
    }

    #[derive(Copy, Clone, Debug)]
    struct MediumPrime;
    impl FieldParameter for MediumPrime {
        const MODULUS: U256 = U256([223, 0, 0, 0]); // 223
    }

    #[derive(Copy, Clone, Debug)]
    struct LargePrime;
    impl FieldParameter for LargePrime {
        // A large prime for more realistic testing
        const MODULUS: U256 = U256([0xFFFFFFFFFFFFFFC5, 0, 0, 0]); // 2^64 - 59
    }

    type SmallField = FieldElement<SmallPrime>;
    type MediumField = FieldElement<MediumPrime>;
    type LargeField = FieldElement<LargePrime>;

    // Basic construction and properties tests
    #[test]
    fn test_field_construction() {
        let zero = SmallField::zero();
        let one = SmallField::one();
        let five = SmallField::new(U256::from(5));

        assert!(zero.is_zero());
        assert!(!zero.is_one());
        assert!(one.is_one());
        assert!(!one.is_zero());
        assert!(!five.is_zero());
        assert!(!five.is_one());
    }

    #[test]
    #[should_panic]
    fn test_from_u256_with_bigger_number() {
        let val = U256::from(42);
        let field_elem: SmallField = val.into();
        assert_eq!(field_elem.as_u256(), val);
    }

    #[test]
    fn test_modulus() {
        assert_eq!(SmallField::modulus(), U256::from(17));
        assert_eq!(MediumField::modulus(), U256::from(223));
    }

    // Addition tests
    #[test]
    fn test_addition_basic() {
        let a = SmallField::new(U256::from(5));
        let b = SmallField::new(U256::from(7));
        let c = a + b;
        assert_eq!(c.as_u256(), U256::from(12));
    }

    #[test]
    fn test_addition_with_modulo() {
        let a = SmallField::new(U256::from(10));
        let b = SmallField::new(U256::from(15));
        let c = a + b; // 25 % 17 = 8
        assert_eq!(c.as_u256(), U256::from(8));
    }

    #[test]
    fn test_addition_identity() {
        let a = SmallField::new(U256::from(5));
        let zero = SmallField::zero();
        assert_eq!(a + zero, a);
        assert_eq!(zero + a, a);
    }

    #[test]
    fn test_addition_commutative() {
        let a = SmallField::new(U256::from(5));
        let b = SmallField::new(U256::from(7));
        assert_eq!(a + b, b + a);
    }

    #[test]
    fn test_addition_associative() {
        let a = SmallField::new(U256::from(3));
        let b = SmallField::new(U256::from(5));
        let c = SmallField::new(U256::from(7));
        assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn test_add_assign() {
        let mut a = SmallField::new(U256::from(5));
        let b = SmallField::new(U256::from(7));
        a += b;
        assert_eq!(a.as_u256(), U256::from(12));
    }

    // Subtraction tests
    #[test]
    fn test_subtraction_basic() {
        let a = SmallField::new(U256::from(10));
        let b = SmallField::new(U256::from(3));
        let c = a - b;
        assert_eq!(c.as_u256(), U256::from(7));
    }

    #[test]
    fn test_subtraction_with_modulo() {
        let a = SmallField::new(U256::from(3));
        let b = SmallField::new(U256::from(10));
        let c = a - b; // 3 - 10 = -7 ≡ 10 (mod 17)
        assert_eq!(c.as_u256(), U256::from(10));
    }

    #[test]
    fn test_subtraction_identity() {
        let a = SmallField::new(U256::from(5));
        let zero = SmallField::zero();
        assert_eq!(a - zero, a);
    }

    #[test]
    fn test_subtraction_self_is_zero() {
        let a = SmallField::new(U256::from(5));
        assert_eq!(a - a, SmallField::zero());
    }

    #[test]
    fn test_sub_assign() {
        let mut a = SmallField::new(U256::from(10));
        let b = SmallField::new(U256::from(3));
        a -= b;
        assert_eq!(a.as_u256(), U256::from(7));
    }

    // Multiplication tests
    #[test]
    fn test_multiplication_basic() {
        let a = SmallField::new(U256::from(3));
        let b = SmallField::new(U256::from(4));
        let c = a * b;
        assert_eq!(c.as_u256(), U256::from(12));
    }

    #[test]
    fn test_multiplication_with_modulo() {
        let a = SmallField::new(U256::from(5));
        let b = SmallField::new(U256::from(7));
        let c = a * b; // 35 % 17 = 1
        assert_eq!(c.as_u256(), U256::from(1));
    }

    #[test]
    fn test_multiplication_identity() {
        let a = SmallField::new(U256::from(5));
        let one = SmallField::one();
        assert_eq!(a * one, a);
        assert_eq!(one * a, a);
    }

    #[test]
    fn test_multiplication_zero() {
        let a = SmallField::new(U256::from(5));
        let zero = SmallField::zero();
        assert_eq!(a * zero, zero);
        assert_eq!(zero * a, zero);
    }

    #[test]
    fn test_multiplication_commutative() {
        let a = SmallField::new(U256::from(5));
        let b = SmallField::new(U256::from(7));
        assert_eq!(a * b, b * a);
    }

    #[test]
    fn test_multiplication_associative() {
        let a = SmallField::new(U256::from(3));
        let b = SmallField::new(U256::from(5));
        let c = SmallField::new(U256::from(7));
        assert_eq!((a * b) * c, a * (b * c));
    }

    #[test]
    fn test_mul_assign() {
        let mut a = SmallField::new(U256::from(3));
        let b = SmallField::new(U256::from(4));
        a *= b;
        assert_eq!(a.as_u256(), U256::from(12));
    }

    // Division and inverse tests
    #[test]
    fn test_inverse_basic() {
        let a = SmallField::new(U256::from(3));
        let inv = a.inverse().unwrap();
        assert_eq!((a * inv).as_u256(), U256::from(1));
    }

    #[test]
    fn test_inverse_zero() {
        let zero = SmallField::zero();
        assert!(zero.inverse().is_none());
    }

    #[test]
    fn test_inverse_one() {
        let one = SmallField::one();
        let inv = one.inverse().unwrap();
        assert_eq!(inv, one);
    }

    #[test]
    fn test_division_basic() {
        let a = SmallField::new(U256::from(6));
        let b = SmallField::new(U256::from(3));
        let c = (a / b).unwrap();
        assert_eq!(c.as_u256(), U256::from(2));
    }

    #[test]
    fn test_division_by_zero() {
        let a = SmallField::new(U256::from(5));
        let zero = SmallField::zero();
        assert!((a / zero).is_none());
    }

    #[test]
    fn test_division_identity() {
        let a = SmallField::new(U256::from(5));
        let one = SmallField::one();
        assert_eq!((a / one).unwrap(), a);
    }

    #[test]
    fn test_division_self_is_one() {
        let a = SmallField::new(U256::from(5));
        assert_eq!((a / a).unwrap(), SmallField::one());
    }

    // Negation tests
    #[test]
    fn test_negation_basic() {
        let a = SmallField::new(U256::from(5));
        let neg_a = -a;
        assert_eq!(neg_a.as_u256(), U256::from(12)); // -5 ≡ 12 (mod 17)
    }

    #[test]
    fn test_negation_zero() {
        let zero = SmallField::zero();
        assert_eq!(-zero, zero);
    }

    #[test]
    fn test_negation_double() {
        let a = SmallField::new(U256::from(5));
        assert_eq!(-(-a), a);
    }

    #[test]
    fn test_negation_additive_inverse() {
        let a = SmallField::new(U256::from(5));
        assert_eq!(a + (-a), SmallField::zero());
    }

    // Power tests
    #[test]
    fn test_power_zero() {
        let a = SmallField::new(U256::from(5));
        let result = a.pow(U256::zero());
        assert_eq!(result, SmallField::one());
    }

    #[test]
    fn test_power_one() {
        let a = SmallField::new(U256::from(5));
        let result = a.pow(U256::one());
        assert_eq!(result, a);
    }

    #[test]
    fn test_power_two() {
        let a = SmallField::new(U256::from(3));
        let result = a.pow(U256::from(2));
        assert_eq!(result.as_u256(), U256::from(9));
    }

    #[test]
    fn test_power_large() {
        let a = SmallField::new(U256::from(2));
        let result = a.pow(U256::from(4));
        assert_eq!(result.as_u256(), U256::from(16));
    }

    #[test]
    fn test_fermats_little_theorem() {
        // For prime p and a ≠ 0 (mod p): a^(p-1) ≡ 1 (mod p)
        let a = SmallField::new(U256::from(3));
        let p_minus_1 = SmallField::modulus() - U256::one();
        let result = a.pow(p_minus_1);
        assert_eq!(result, SmallField::one());
    }

    // Distributive property tests
    #[test]
    fn test_distributive_property() {
        let a = SmallField::new(U256::from(3));
        let b = SmallField::new(U256::from(5));
        let c = SmallField::new(U256::from(7));

        // a * (b + c) = a * b + a * c
        assert_eq!(a * (b + c), a * b + a * c);
    }

    #[test]
    fn test_large_field_operations() {
        let a = LargeField::new(U256::from(1000000));
        let b = LargeField::new(U256::from(2000000));

        let sum = a + b;
        assert_eq!(sum.as_u256(), U256::from(3000000));

        // Test that multiplication doesn't overflow
        let product = a * b;
        assert!(product.as_u256() < LargeField::modulus());
    }

    // Comprehensive field axiom tests
    #[test]
    fn test_field_axioms_comprehensive() {
        let elements = [
            SmallField::new(U256::from(1)),
            SmallField::new(U256::from(2)),
            SmallField::new(U256::from(3)),
            SmallField::new(U256::from(5)),
            SmallField::new(U256::from(7)),
            SmallField::new(U256::from(11)),
            SmallField::new(U256::from(13)),
        ];

        for &a in &elements {
            for &b in &elements {
                // Addition commutativity
                assert_eq!(a + b, b + a);

                // Multiplication commutativity
                assert_eq!(a * b, b * a);

                // Additive identity
                assert_eq!(a + SmallField::zero(), a);

                // Multiplicative identity
                assert_eq!(a * SmallField::one(), a);

                // Additive inverse
                assert_eq!(a + (-a), SmallField::zero());

                // Multiplicative inverse (if not zero)
                if !a.is_zero() {
                    assert_eq!(a * a.inverse().unwrap(), SmallField::one());
                }

                for &c in &elements {
                    // Addition associativity
                    assert_eq!((a + b) + c, a + (b + c));

                    // Multiplication associativity
                    assert_eq!((a * b) * c, a * (b * c));

                    // Distributivity
                    assert_eq!(a * (b + c), a * b + a * c);
                    assert_eq!((a + b) * c, a * c + b * c);
                }
            }
        }
    }

    // Display and Debug tests
    #[test]
    fn test_display_format() {
        let a = SmallField::new(U256::from(5));
        let display_str = format!("{}", a);
        assert!(display_str.contains("17")); // Should contain the modulus
        assert!(display_str.contains("5")); // Should contain the value
    }

    #[test]
    fn test_debug_format() {
        let a = SmallField::new(U256::from(5));
        let debug_str = format!("{:?}", a);
        assert!(debug_str.contains("FieldElement"));
    }

    // Copy and Clone tests
    #[test]
    fn test_copy_semantics() {
        let a = SmallField::new(U256::from(5));
        let b = a; // Copy
        let c = a; // Another copy

        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(b, c);
    }

    #[test]
    fn test_clone_semantics() {
        let a = SmallField::new(U256::from(5));
        let b = a.clone();

        assert_eq!(a, b);
    }

    // Equality tests
    #[test]
    fn test_equality() {
        let a = SmallField::new(U256::from(5));
        let b = SmallField::new(U256::from(5));
        let c = SmallField::new(U256::from(7));

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    // Test inverse using extended Euclidean algorithm property
    #[test]
    fn test_inverse_correctness() {
        for i in 1..17 {
            let a = SmallField::new(U256::from(i));
            let inv = a.inverse().unwrap();

            // a * a^(-1) ≡ 1 (mod p)
            assert_eq!(a * inv, SmallField::one());

            // (a^(-1))^(-1) ≡ a (mod p)
            assert_eq!(inv.inverse().unwrap(), a);
        }
    }
}
