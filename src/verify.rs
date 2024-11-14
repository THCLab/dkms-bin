use std::{sync::Arc, thread::sleep, time::Duration};

use keri_controller::{error::ControllerError, IdentifierPrefix, Oobi, TelState};
use keri_core::processor::validator::VerificationError;
use said::SelfAddressingIdentifier;
use serde::Deserialize;

use crate::{
    keri::query_tel,
    utils::{load, load_signer},
};

#[derive(Debug)]
pub enum ACDCState {
    FaultySignature,
    VerificationSuccess,
    Issued,
    Revoked,
    NotFound,
}

pub async fn handle_verify(
    alias: &str,
    oobi: &[&str],
    message: String,
) -> Result<ACDCState, ControllerError> {
    let who_id = load(alias).unwrap();

    // parse and resolve oobis
    let oobis: Vec<Oobi> = oobi
        .iter()
        .map(|oobi_str| serde_json::from_str::<Vec<Oobi>>(&oobi_str).unwrap())
        .flatten()
        .collect();
    for oobi in oobis {
        let _ = who_id.resolve_oobi(&oobi).await;
        who_id.send_oobi_to_watcher(who_id.id(), &oobi).await?;
    }

    // Parse cesr stream of message
    let (_rest, cesr) = cesrox::parse(message.as_bytes()).unwrap();
    let attachments = cesr.attachments;
    if !attachments.is_empty() {
        match who_id.verify_from_cesr(&message) {
            Ok(_) => Ok(ACDCState::VerificationSuccess),
            Err(ControllerError::VerificationError(e)) => {
                if e.iter().any(|(e, _)| {
                    if let VerificationError::VerificationFailure = e {
                        true
                    } else {
                        false
                    }
                }) {
                    Ok(ACDCState::FaultySignature)
                } else {
                    Err(ControllerError::VerificationError(e))
                }
            }
            Err(e) => Err(e),
        }
    } else {
        // We expect that message got fields: d, ii, ri.
        let h: NecessaryFields = serde_json::from_str(&message).unwrap();

        let issuer: IdentifierPrefix = h.issuer_identifier.parse().unwrap();
        let said: SelfAddressingIdentifier = h.digest.parse().unwrap();
        let registry_id: SelfAddressingIdentifier = h.registry_id.parse().unwrap();

        let signer = Arc::new(load_signer(alias).unwrap());
        for _i in 0..5 {
            query_tel(&said, registry_id.clone(), &issuer, &who_id, signer.clone())
                .await
                .unwrap();
            match who_id.find_vc_state(&said) {
                Ok(Some(_state)) => {
                    break;
                }
                _ => sleep(Duration::from_secs(1)),
            }
        }

        let st = who_id.find_vc_state(&h.digest.parse().unwrap()).unwrap();
        match st {
            Some(TelState::Issued(_said)) => Ok(ACDCState::Issued),
            Some(TelState::NotIssued) => Ok(ACDCState::NotFound),
            Some(TelState::Revoked) => Ok(ACDCState::Revoked),
            None => Ok(ACDCState::NotFound),
        }
    }
}

#[derive(Debug, Deserialize)]
struct NecessaryFields {
    #[serde(rename = "ri")]
    registry_id: String,
    #[serde(rename = "d")]
    digest: String,
    #[serde(rename = "i")]
    issuer_identifier: String,
}
