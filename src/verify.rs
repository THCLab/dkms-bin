use std::{sync::Arc, thread::sleep, time::Duration};

use keri_controller::{
    communication::SendingError, error::ControllerError, IdentifierPrefix, Oobi, TelState,
};
use keri_core::{
    event::sections::seal::EventSeal,
    processor::validator::{MoreInfoError, VerificationError},
};
use said::SelfAddressingIdentifier;
use serde::Deserialize;

use crate::{
    keri::query_tel,
    utils::{load, load_signer, parse_json_arguments},
};

#[derive(thiserror::Error, Debug)]
pub enum VerifyHandleError {
    #[error("Unknown identifier: {0}. You can provide its oobi with --oobi option")]
    MissingOobi(IdentifierPrefix),
    #[error("Wrong signature format: {0}")]
    WrongSignatureFormat(String),
    #[error("Wrong oobi format. {0}")]
    WrongOobiFormat(String),
    #[error("{0}")]
    VerError(VerificationErrorWrapper),
    #[error("The message contains unexpected characters at the end.")]
    RemainingCESR(String),
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
            writeln!(f, "{}", err)?;
        }
        write!(f, "")
    }
}

#[derive(Debug)]
pub enum ACDCState {
    VerificationSuccess,
    Issued,
    Revoked,
    NotFound,
}

pub async fn handle_verify(
    alias: &str,
    oobi: &[&str],
    message: String,
) -> Result<ACDCState, VerifyHandleError> {
    let who_id = load(alias).unwrap();

    // parse and resolve oobis
    let oobis = parse_json_arguments::<Oobi>(oobi)
        .map_err(|e| VerifyHandleError::WrongOobiFormat(e.to_string()))?;
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
    let (rest, cesr) = cesrox::parse(message.as_bytes()).unwrap();
    if !rest.is_empty() {
        return Err(VerifyHandleError::RemainingCESR(
            String::from_utf8(rest.to_vec()).unwrap(),
        ));
    };
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
                                        sn: _,
                                        event_digest: _,
                                    },
                                )) => {
                                    // check if identifier oobi is known
                                    let oobis = who_id
                                        .get_end_role(prefix, keri_core::oobi::Role::Witness)
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
