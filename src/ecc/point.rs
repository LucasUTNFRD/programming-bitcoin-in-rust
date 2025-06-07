use std::{
    fmt::{Debug, Display},
    ops::{Add, Mul, Neg, Sub},
};

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

    /// Constructor
    fn new(x: Self::Field, y: Self::Field) -> Self;

    /// Provide generator element
    fn generator() -> Self;

    /// Give the identity element
    fn identity() -> Self;
    /// Check wheter current point is an identity point
    fn is_identity(&self) -> bool;

    /// Provide the x and y coordinates of the point
    fn x(&self) -> &Self::Field;
    fn y(&self) -> &Self::Field;
}
