use std::{sync::Arc, thread::sleep, time::Duration};

use keri_controller::{
    communication::SendingError, error::ControllerError, IdentifierPrefix, Oobi, TelState,
};
use keri_core::{
    event::sections::seal::EventSeal,
    processor::validator::{MoreInfoError, VerificationError},
};
// use keri_core::processor::validator::VerificationError;
use said::SelfAddressingIdentifier;
use serde::Deserialize;
use serde_json::{from_value, Value};

use crate::{
    keri::query_tel,
    utils::{load, load_signer},
};

#[derive(thiserror::Error, Debug)]
pub enum VerifyHandleError {
    // #[error("Signature doesn't match")]
    // FaultySignature,
    #[error("Unknown identifier: {0}. You can provide its oobi with --oobi option")]
    MissingOobi(IdentifierPrefix),
    #[error("Wrong signature format: {0}")]
    WrongSignatureFormat(String),
    #[error("Wrong oobi format. {0}")]
    WrongOobiFormat(String),
    #[error("{0}")]
    VerError(VerificationErrorWrapper),

    #[error(transparent)]
    SendingError(#[from] SendingError),
    #[error("{0}")]
    List(ErrorList),
}

impl From<VerificationError> for VerifyHandleError {
    fn from(value: VerificationError) -> Self {
        VerifyHandleError::VerError(VerificationErrorWrapper(value))
    }
}

#[derive(Debug)]
pub struct ErrorList(Vec<VerifyHandleError>);

#[derive(Debug)]
pub struct VerificationErrorWrapper(VerificationError);

impl std::fmt::Display for VerificationErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match &self.0 {
            VerificationError::VerificationFailure => "Signature doesn't match provided data",
            VerificationError::SignatureError(signature_error) => {
                &format!("Signature error: {}", signature_error)
            }
            VerificationError::NotEstablishment(event_seal) => &format!(
                "Event corresponding to provided seal {:?} should be establishment event.",
                event_seal
            ),
            VerificationError::MissingSignerId => "Signature doesn't contain signing identifier",
            VerificationError::MoreInfo(more_info_error) => &more_info_error.to_string(),
        };
        write!(f, "{}", message)
    }
}

impl std::fmt::Display for ErrorList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for err in &self.0 {
            write!(f, "{}\n", err)?;
        }
        write!(f, "")
    }
}

#[derive(Debug)]
pub enum ACDCState {
    FaultySignature,
    VerificationSuccess,
    Issued,
    Revoked,
    NotFound,
}

fn extract_objects(value: &serde_json::Value) -> Result<Vec<Oobi>, VerifyHandleError> {
    match value {
        Value::Array(vec) => vec
            .into_iter()
            .fold(Ok(vec![]), |mut acc, el| match extract_objects(el) {
                Ok(mut obj) => {
                    acc.as_mut().map(|oobis| oobis.append(&mut obj));
                    acc
                }
                Err(e) => return Err(e),
            }),
        Value::Object(map) => match from_value::<Oobi>(Value::Object(map.clone())) {
            Ok(value) => Ok(vec![value]),
            Err(e) => {
                return Err(VerifyHandleError::WrongOobiFormat(format!(
                    "Provided json isn't valid oobi: {}",
                    serde_json::to_string(&value).unwrap()
                )))
            }
        },
        _ => Err(VerifyHandleError::WrongOobiFormat(
            "Expected oobi or list of oobis".to_string(),
        )),
    }
}

pub async fn handle_verify(
    alias: &str,
    oobi: &[&str],
    message: String,
) -> Result<ACDCState, VerifyHandleError> {
    let who_id = load(alias).unwrap();

    // parse and resolve oobis
    let oobis: Vec<Oobi> = oobi.iter().fold(Ok(vec![]), |mut acc, oobi_str| {
        match serde_json::from_str::<Value>(&oobi_str) {
            Ok(ok) => {
                let objects = extract_objects(&ok);
                match objects {
                    Ok(mut obj) => {
                        acc.as_mut().map(|oobis| oobis.append(&mut obj));
                    }
                    Err(e) => {
                        acc = Err(e);
                    }
                };
                acc
            }
            Err(_e) => Err(VerifyHandleError::WrongOobiFormat(format!(
                "Provided json isn't valid oobi: {}",
                oobi_str
            ))),
        }
    })?;
    for oobi in oobis {
        let _ = who_id.resolve_oobi(&oobi).await;
        match who_id.send_oobi_to_watcher(who_id.id(), &oobi).await {
            Ok(_) => (),
            Err(e) => match e {
                ControllerError::SendingError(sending_error) => {
                    return Err(sending_error.into());
                }
                _ => unreachable!(),
            },
        };
    }

    // Parse cesr stream of message
    let (_rest, cesr) = cesrox::parse(message.as_bytes()).unwrap();
    let attachments = cesr.attachments;
    if !attachments.is_empty() {
        match who_id.verify_from_cesr(&message) {
            Ok(_) => Ok(ACDCState::VerificationSuccess),
            Err(ControllerError::VerificationError(e)) => {
                let err_list = ErrorList(
                    e.into_iter()
                        .map(|(e, _)| {
                            match &e {
                                VerificationError::MoreInfo(MoreInfoError::EventNotFound(
                                    EventSeal {
                                        prefix,
                                        sn,
                                        event_digest,
                                    },
                                )) => {
                                    // check if identifier oobi is known
                                    let oobis = who_id
                                        .get_end_role(&prefix, keri_core::oobi::Role::Witness)
                                        .unwrap();
                                    if oobis.is_empty() {
                                        VerifyHandleError::MissingOobi(prefix.clone())
                                    } else {
                                        e.into()
                                    }
                                }
                                _ => e.into(),
                            }
                            //    e.into()
                        })
                        .collect(),
                );
                Err(VerifyHandleError::List(err_list))
            }
            Err(ControllerError::CesrFormatError) => Err(VerifyHandleError::WrongSignatureFormat(
                "Wrong format".to_string(),
            )),
            Err(_e) => todo!(),
        }
    } else {
        // We expect that message got fields: d, ii, ri.
        let fields: NecessaryFields = serde_json::from_str(&message).unwrap();

        let issuer: IdentifierPrefix = fields.issuer_identifier.parse().unwrap();
        let said: SelfAddressingIdentifier = fields.digest.parse().unwrap();
        let registry_id: SelfAddressingIdentifier = fields.registry_id.parse().unwrap();

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

        let st = who_id.find_vc_state(&said).unwrap();
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
