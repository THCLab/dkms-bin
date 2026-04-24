use thiserror::Error;

use crate::{
    utils::{ed25519_sig, load, load_identifier, load_signer},
    CliError,
};

#[derive(Error, Debug)]
pub enum MesagkestoError {
    #[error("Signing error")]
    SigningError,
}

/// Generates exchange message with provided data. Message is signed and ready
/// to be sent to mesagkesto.
pub fn handle_exchange(alias: &str, data: &str, receiver_alias: &str) -> Result<String, CliError> {
    let receiver = load_identifier(receiver_alias)?;
    let exn = messagebox::forward_message(receiver.to_string(), data.to_string());

    let signer_id = load(alias)?;
    let signer = load_signer(alias)?;

    let signature = ed25519_sig(&signer, exn.to_string().as_bytes())
        .map_err(|_| MesagkestoError::SigningError)?;
    Ok(signer_id
        .sign_to_cesr(&exn.to_string(), &[signature])
        .map_err(|_e| MesagkestoError::SigningError)?)
}

/// Generates query message of identifier's mesagkesto. Message is signed and
/// ready to be sent to mesagkesto.
pub fn handle_pull(alias: &str) -> Result<String, CliError> {
    let signer_id = load(alias)?;
    let signer = load_signer(alias)?;

    let qry = messagebox::query_by_sn(signer_id.id().to_string(), 0);

    let signature = ed25519_sig(&signer, qry.to_string().as_bytes())
        .map_err(|_| MesagkestoError::SigningError)?;
    Ok(signer_id
        .sign_to_cesr(&qry.to_string(), &[signature])
        .map_err(|_e| MesagkestoError::SigningError)?)
}
