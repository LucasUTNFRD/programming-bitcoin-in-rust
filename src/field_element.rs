use std::{
    num,
    ops::{Add, Mul, Sub},
};

use anyhow::{Ok, bail};

#[derive(Debug, Eq, PartialEq)]
struct FieldElement {
    n: u64,
    prime: u64,
}

impl FieldElement {
    pub fn new(n: u64, prime: u64) -> anyhow::Result<Self> {
        if n >= prime {
            bail!("Number {} must be less than prime {}", n, prime);
        }
        Ok(Self { n, prime })
    }
}

impl Add for FieldElement {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        assert_eq!(
            self.prime, other.prime,
            "Cannot add elements from different fields"
        );
        Self {
            n: (self.n + other.n) % self.prime,
            prime: self.prime,
        }
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        assert_eq!(
            self.prime, other.prime,
            "Cannot substract elements from different fields"
        );

        let result = if self.n >= other.n {
            self.n - other.n
        } else {
            self.prime - (other.n - self.n)
        };
        Self {
            n: result,
            prime: self.prime,
        }
    }
}

impl Mul for FieldElement {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        assert_eq!(
            self.prime, other.prime,
            "Cannot substract elements from different fields"
        );
        Self {
            n: (self.n * other.n) % self.prime,
            prime: self.prime,
        }
    }
}

trait Pow<EXP = u32> {
    type Output;

    fn pow(self, rhs: EXP) -> Self::Output;
}

impl Pow for FieldElement {
    type Output = Self;

    fn pow(self, exp: u32) -> Self::Output {
        let result = self.n.pow(exp) % self.prime;
        Self {
            n: result,
            prime: self.prime,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_element_creation() {
        // Valid creation
        let element = FieldElement::new(5, 7).unwrap();
        assert_eq!(element.n, 5);
        assert_eq!(element.prime, 7);

        // Edge case: n = 0
        let zero_element = FieldElement::new(0, 7).unwrap();
        assert_eq!(zero_element.n, 0);

        // Edge case: n = prime - 1
        let max_element = FieldElement::new(6, 7).unwrap();
        assert_eq!(max_element.n, 6);
    }

    #[test]
    fn test_field_element_creation_failure() {
        // n >= prime should fail
        assert!(FieldElement::new(7, 7).is_err());
        assert!(FieldElement::new(8, 7).is_err());
        assert!(FieldElement::new(100, 7).is_err());
    }

    #[test]
    fn test_field_element_comparison() {
        let element1 = FieldElement::new(5, 7).unwrap();
        let element2 = FieldElement::new(5, 7).unwrap();
        let element3 = FieldElement::new(3, 7).unwrap();
        let element4 = FieldElement::new(5, 11).unwrap(); // Different prime

        // Same elements should be equal
        assert_eq!(element1, element2);

        // Different n values
        assert_ne!(element1, element3);

        // Different prime values
        assert_ne!(element1, element4);
    }

    #[test]
    fn test_field_element_addition() {
        let prime = 7;
        let a = FieldElement::new(2, prime).unwrap();
        let b = FieldElement::new(3, prime).unwrap();

        // Regular addition: 2 + 3 = 5 (mod 7)
        let result = a + b;
        assert_eq!(result.n, 5);
        assert_eq!(result.prime, prime);

        // Addition with wraparound: 5 + 4 = 2 (mod 7)
        let c = FieldElement::new(5, prime).unwrap();
        let d = FieldElement::new(4, prime).unwrap();
        let result2 = c + d;
        assert_eq!(result2.n, 2);

        // Addition with zero
        let zero = FieldElement::new(0, prime).unwrap();
        let e = FieldElement::new(4, prime).unwrap();
        let result3 = zero + e;
        assert_eq!(result3.n, 4);
    }

    #[test]
    fn test_field_element_subtraction() {
        let prime = 7;
        let a = FieldElement::new(5, prime).unwrap();
        let b = FieldElement::new(3, prime).unwrap();

        // Regular subtraction: 5 - 3 = 2 (mod 7)
        let result = a - b;
        assert_eq!(result.n, 2);
        assert_eq!(result.prime, prime);

        // Subtraction with wraparound: 2 - 5 = 4 (mod 7)
        // Because (2 - 5 + 7) % 7 = 4
        let c = FieldElement::new(2, prime).unwrap();
        let d = FieldElement::new(5, prime).unwrap();
        let result2 = c - d;
        assert_eq!(result2.n, 4);

        // Subtraction resulting in zero: 3 - 3 = 0 (mod 7)
        let e = FieldElement::new(3, prime).unwrap();
        let f = FieldElement::new(3, prime).unwrap();
        let result3 = e - f;
        assert_eq!(result3.n, 0);

        // Subtract zero
        let zero = FieldElement::new(0, prime).unwrap();
        let g = FieldElement::new(4, prime).unwrap();
        let result4 = g - zero;
        assert_eq!(result4.n, 4);
    }

    #[test]
    fn test_field_element_mul() {
        let prime = 7;
        let a = FieldElement::new(5, prime).unwrap();
        let b = FieldElement::new(3, prime).unwrap();

        let result = a * b;
        let expected_result = FieldElement::new(1, 7).unwrap();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn test_field_element_pow() {
        let prime = 13;
        let a = FieldElement::new(3, prime).unwrap();
        let b = FieldElement::new(1, prime).unwrap();

        let result = a.pow(3);
        assert_eq!(result, b)
    }

    #[test]
    #[should_panic]
    fn test_addition_different_primes_panics() {
        let a = FieldElement::new(2, 7).unwrap();
        let b = FieldElement::new(3, 11).unwrap();
        let _ = a + b; // Should panic
    }

    #[test]
    #[should_panic]
    fn test_subtraction_different_primes_panics() {
        let a = FieldElement::new(5, 7).unwrap();
        let b = FieldElement::new(3, 11).unwrap();
        let _ = a - b; // Should panic
    }
}
