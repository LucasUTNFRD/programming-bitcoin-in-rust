use std::{
    fmt::{Debug, Display},
    ops::{Add, Mul, Neg, Sub},
};

use primitive_types::U256;

use crate::error::Error;

use super::field_element::FiniteField;

pub trait G1Point:
    Copy                // Representation small enough for efficient copy
    + Debug+ Display// For debugging and printing
    + PartialEq         // Allow for equality testing but may not be transitively equal
    + Ord               // Total order 
    // Mathemetical Operations ----
    + Neg<Output=Self>
    + Sub<Output=Self>
    + Add<Output=Self>
    + Mul<Self::SubField, Output = Self>
    // Mathemetical Operations ----
{
    type Field: FiniteField; // The field containg x,y coordinates
    type SubField: FiniteField; //The scalar field for multiplication

    /// the "order" of a generator point G on an elliptic curve, 
    /// denoted as n, is the smallest positive integer such that $n \dot G=O$,
    /// where $O$ is the "point at infinity"
    const N:U256;

    /// Constructor
    fn new(x: Self::Field, y: Self::Field) -> Result<Self,Error>;

    /// Provide generator element
    fn g() -> Self;

    /// Give the identity element
    fn identity() -> Self;
    /// Check wheter current point is an identity point
    fn is_identity(&self) -> bool;

}
