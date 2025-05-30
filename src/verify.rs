use std::{sync::Arc, thread::sleep, time::Duration};

use acdc::Attestation;
use base64::{prelude::BASE64_STANDARD, Engine};
use keri_controller::{
    communication::SendingError, error::ControllerError, identifier::Identifier, IdentifierPrefix,
    LocationScheme, Oobi, TelState,
};
use keri_core::processor::validator::{MoreInfoError, VerificationError};
use said::SelfAddressingIdentifier;

use crate::{
    keri::query_tel,
    resolve::find_locations,
    utils::{load, load_signer, parse_json_arguments},
};

#[derive(thiserror::Error, Debug)]
pub enum VerifyHandleError {
    #[error("Unknown identifier alias: {0}")]
    UnknownIdentifier(String),
    #[error("Unknown oobi of identifier {0}. You can provide its oobi with --oobi option")]
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
    #[error("Signature doesn't match provided data")]
    FaultySignatures,
    #[error("No watchers are configured for {0}")]
    NoWatchersConfigured(IdentifierPrefix),
    #[error("Invalid credential: {0}")]
    InvalidCredential(String),
    #[error("{0}")]
    OtherError(String),
}

impl From<VerificationError> for VerifyHandleError {
    fn from(value: VerificationError) -> Self {
        match value {
            VerificationError::VerificationFailure => VerifyHandleError::FaultySignatures,
            e => VerifyHandleError::VerError(VerificationErrorWrapper(e)),
        }
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
    let who_id =
        load(alias).map_err(|_| VerifyHandleError::UnknownIdentifier(alias.to_string()))?;

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
    let message = message.trim();
    let is_json = message.starts_with('{') || message.starts_with('[');
    let message_bytes = if is_json {
        message.as_bytes().to_vec()
    } else {
        BASE64_STANDARD.decode(message).unwrap()
    };

    // Parse cesr stream of message
    let (rest, cesr) = cesrox::parse(&message_bytes).unwrap();
    if !rest.is_empty() {
        return Err(VerifyHandleError::RemainingCESR(
            String::from_utf8(rest.to_vec()).unwrap(),
        ));
    };
    let attachments = cesr.attachments;
    if !attachments.is_empty() {
        match who_id.known_events.verify_from_cesr(&message_bytes) {
            Ok(_) => Ok(ACDCState::VerificationSuccess),
            Err(ControllerError::VerificationError(e)) => {
                if e.iter().any(|(e, _)| {
                    if let VerificationError::VerificationFailure = e {
                        true
                    } else {
                        false
                    }
                }) {
                    return Err(VerifyHandleError::FaultySignatures);
                };
                let err_list = ErrorList(
                    e.into_iter()
                        .map(|(e, _)| {
                            match &e {
                                VerificationError::MoreInfo(MoreInfoError::EventNotFound(seal)) => {
                                    // check if identifier oobi is known
                                    let oobis = find_oobis(&who_id, &seal.prefix);
                                    if oobis.is_empty() {
                                        VerifyHandleError::MissingOobi(seal.prefix.clone())
                                    } else {
                                        e.into()
                                    }
                                }
                                _ => e.into(),
                            }
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
        let att: Attestation = match cesr.payload {
            cesrox::payload::Payload::JSON(items) => serde_json::from_slice(&items)
                .map_err(|e| VerifyHandleError::InvalidCredential(e.to_string()))?,
            cesrox::payload::Payload::CBOR(items) => serde_cbor::from_slice(&items)
                .map_err(|e| VerifyHandleError::InvalidCredential(e.to_string()))?,
            cesrox::payload::Payload::MGPK(_items) => todo!(),
        };
        let issuer: IdentifierPrefix = att.issuer.parse().unwrap();
        let said = att.digest.unwrap();
        let registry_id: SelfAddressingIdentifier = att.registry_identifier.parse().unwrap();

        if find_oobis(&who_id, &issuer).is_empty() {
            return Err(VerifyHandleError::MissingOobi(issuer.clone()));
        };

        let signer = Arc::new(load_signer(alias).unwrap());
        let cached_state = who_id.find_vc_state(&said).unwrap();
        let mut delay = Duration::from_secs(1);
        for _i in 0..5 {
            let _ = query_tel(&said, registry_id.clone(), &issuer, &who_id, signer.clone()).await;
            if who_id.find_vc_state(&said).unwrap() != cached_state {
                break;
            } else {
                sleep(delay);
                delay *= 2;
            }
        }

        // Try to verify vc
        match who_id.find_vc_state(&said) {
            Ok(Some(state)) => match_tel_state(Some(state)),
            Ok(None) => Err(VerifyHandleError::OtherError("TEL not found".to_string())),
            Err(e) => {
                // check if any watcher was configured
                match who_id.watchers() {
                    Ok(watchers) if watchers.is_empty() => {
                        Err(VerifyHandleError::NoWatchersConfigured(who_id.id().clone()))
                    }
                    Ok(_watchers) => Err(VerifyHandleError::OtherError(e.to_string())),
                    Err(_) => Err(VerifyHandleError::NoWatchersConfigured(who_id.id().clone())),
                }
            }
        }
    }
}

fn find_oobis(who_id: &Identifier, issuer: &IdentifierPrefix) -> Vec<LocationScheme> {
    let oobis = match who_id.find_state(issuer) {
        Ok(state) => state.witness_config.witnesses,
        Err(_) => vec![],
    };
    find_locations(&who_id, oobis.into_iter().map(IdentifierPrefix::Basic))
}

fn match_tel_state(ts: Option<TelState>) -> Result<ACDCState, VerifyHandleError> {
    match ts {
        Some(TelState::Issued(_said)) => Ok(ACDCState::Issued),
        Some(TelState::NotIssued) => Ok(ACDCState::NotFound),
        Some(TelState::Revoked) => Ok(ACDCState::Revoked),
        None => Ok(ACDCState::NotFound),
    }
}
