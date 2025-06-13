use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Coordinate not in curve")]
    CoordinateNotInCurve,
    #[error("Invalid Public Key")]
    InvalidPublicKey,
    // InvalidSecretKey,
    // InvalidRecoveryId,
    // InvalidMessage,
    // InvalidInputLength,
    // TweakOutOfRange,
    // InvalidAffine,
}
