use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    utils::{load, load_identifier, load_signer},
    CliError,
};

#[derive(Error, Debug)]
pub enum MesagkestoError {
    #[error("Signing error")]
    SigningError,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
enum MessageType {
    Qry(QueryArguments),
    Exn(ExchangeArguments),
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum QueryArguments {
    BySn { i: String, s: usize },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "r")]
#[serde(rename_all = "lowercase")]
enum ExchangeArguments {
    Fwd { i: String, a: String },
}

fn forward_message(receiver: String, data: String) -> MessageType {
    MessageType::Exn(ExchangeArguments::Fwd {
        i: receiver,
        a: data,
    })
}

fn query_by_sn(receiver: String, sn: usize) -> MessageType {
    MessageType::Qry(QueryArguments::BySn {
        i: receiver,
        s: sn,
    })
}

/// Generates exchange message with provided data. Message is signed and ready
/// to be sent to mesagkesto.
pub fn handle_exchange(alias: &str, data: &str, receiver_alias: &str) -> Result<String, CliError> {
    let receiver = load_identifier(receiver_alias)?;
    let exn = forward_message(receiver.to_string(), data.to_string());
    let exn_str = serde_json::to_string(&exn).unwrap();

    let signer_id = load(alias)?;
    let signer = load_signer(alias)?;

    let signature = keri_sdk::SelfSigningPrefix::Ed25519Sha512(
        signer
            .sign(exn_str.as_bytes())
            .map_err(|_e| MesagkestoError::SigningError)?,
    );
    Ok(signer_id
        .sign_to_cesr(&exn_str, &[signature])
        .map_err(|_e| MesagkestoError::SigningError)?)
}

/// Generates query message of identifier's mesagkesto. Message is signed and
/// ready to be sent to mesagkesto.
pub fn handle_pull(alias: &str) -> Result<String, CliError> {
    let signer_id = load(alias)?;
    let signer = load_signer(alias)?;

    let qry = query_by_sn(signer_id.id().to_string(), 0);
    let qry_str = serde_json::to_string(&qry).unwrap();

    let signature = keri_sdk::SelfSigningPrefix::Ed25519Sha512(
        signer
            .sign(qry_str.as_bytes())
            .map_err(|_e| MesagkestoError::SigningError)?,
    );
    Ok(signer_id
        .sign_to_cesr(&qry_str, &[signature])
        .map_err(|_e| MesagkestoError::SigningError)?)
}
