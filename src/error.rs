use config_file::ConfigFileError;
use keri_controller::identifier::query::WatcherResponseError;
use thiserror::Error;

use crate::{
    keri::KeriError,
    mesagkesto::MesagkestoError,
    said::SaidError,
    utils::{ExtractionError, LoadingError},
    verification_status::VerificationStatus,
};

#[derive(Error, Debug)]
pub enum CliError {
    #[error(transparent)]
    ConfigUnparsable(#[from] ConfigFileError),
    #[error("Keys derivation error")]
    KeysDerivationError,
    #[error(transparent)]
    FileError(#[from] std::io::Error),
    #[error("Missing 'd' field")]
    MissingDigest,
    #[error(transparent)]
    MesagkestoError(#[from] MesagkestoError),
    #[error("{0}")]
    SaidError(#[from] SaidError),
    #[error("Unknown identifier: {0}")]
    UnknownIdentifier(String),
    #[error(transparent)]
    KeriError(#[from] KeriError),
    #[error(transparent)]
    LoadingError(#[from] LoadingError),
    #[error("The provided string {0} is not valid secret key. {1}. Please verify your input.")]
    SecretKeyError(String, keri_core::prefix::error::Error),
    #[error("Invalid base64: {0}")]
    B64Error(String),
    #[error("Invalid seed code: {0}")]
    SeedError(String),
    #[error("Can't parse provided oobi. {0}")]
    UnparsableOobi(#[from] ExtractionError),
    #[error("{0}")]
    Verification(VerificationStatus),
    #[error("Invalid input. Only valid json can be signed")]
    JsonExpected,
    #[error("{0:?}")]
    KelGetting(Vec<WatcherResponseError>),
}
