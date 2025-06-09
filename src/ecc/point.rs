use std::{
    fmt::{Debug, Display},
    ops::{Add, Mul, Neg, Sub},
};

use thiserror::Error;

use super::field_element::FiniteField;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Coordinate not in curve")]
    CoordinateNotInCurve,
}

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

    /// Constructor
    fn new(x: Self::Field, y: Self::Field) -> Result<Self,Error>;

    /// Provide generator element
    fn generator() -> Self;

    /// Give the identity element
    fn identity() -> Self;
    /// Check wheter current point is an identity point
    fn is_identity(&self) -> bool;

}
