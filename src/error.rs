use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Coordinate not in curve")]
    CoordinateNotInCurve,
    #[error("Invalid Public Key")]
    InvalidPublicKey,
    #[error("Empty Stack")]
    EmptyStack,
    #[error("Invalid Stack Size expected")]
    InvalidStackSize,
    #[error("Invalid Stack Operation")]
    InvalidStackOperation,
    #[error("Deserializer DER Signature")]
    InvalidDER,
    #[error("Missing Z")]
    MissingZ,
}
