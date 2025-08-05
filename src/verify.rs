use std::{sync::Arc, thread::sleep, time::Duration};

use acdc::Attestation;
use base64::{prelude::BASE64_STANDARD, Engine};
use keri_controller::{
    communication::SendingError,
    error::ControllerError,
    identifier::{query::QueryResponse, Identifier},
    IdentifierPrefix, LocationScheme, Oobi, SelfSigningPrefix, TelState,
};
use keri_core::{
    event::sections::seal::EventSeal,
    event_message::signature::{get_signatures, Signature, SignerData},
    processor::validator::{MoreInfoError, VerificationError},
    query::query_event::QueryEvent,
};
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
    let signatures: Vec<_> = attachments
        .iter()
        .flat_map(|att| get_signatures(att.clone()).unwrap())
        .collect();
    for sig in signatures.iter() {
        match sig {
            Signature::Transferable(signer_data, _) => match signer_data {
                SignerData::EventSeal(event_seal) => {
                    let state = who_id.find_state(&event_seal.prefix);
                    match state {
                        Ok(state) if state.sn <= event_seal.sn => {
                            update_kel_with_seal(alias, &who_id, event_seal).await?;
                        }
                        Ok(_) => (),
                        Err(_e) => {
                            update_kel_with_seal(alias, &who_id, event_seal).await?;
                        }
                    }
                }
                SignerData::LastEstablishment(identifier_prefix) => {
                    update_kel(alias, &who_id, identifier_prefix).await?
                }
                SignerData::JustSignatures => (),
            },
            Signature::NonTransferable(_) => (),
        };
    }
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

        update_kel(alias, &who_id, &issuer).await?;

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

async fn update_kel(
    alias: &str,
    who_id: &Identifier,
    about_who: &IdentifierPrefix,
) -> Result<(), VerifyHandleError> {
    let signer =
        load_signer(alias).map_err(|_| VerifyHandleError::UnknownIdentifier(alias.to_string()))?;
    for watcher in who_id
        .watchers()
        .map_err(|_| VerifyHandleError::NoWatchersConfigured(who_id.id().clone()))?
    {
        let qry = who_id
            .query_full_log(about_who, watcher)
            .map_err(|e| VerifyHandleError::OtherError(e.to_string()))?;
        let signature =
            SelfSigningPrefix::Ed25519Sha512(signer.sign(qry.encode().unwrap()).unwrap());
        query_with_retries(who_id, qry, signature).await?;
    }

    Ok(())
}

async fn update_kel_with_seal(
    alias: &str,
    who_id: &Identifier,
    event_seal: &EventSeal,
) -> Result<(), VerifyHandleError> {
    let signer =
        load_signer(alias).map_err(|_| VerifyHandleError::UnknownIdentifier(alias.to_string()))?;
    for query in who_id.query_watchers(event_seal).unwrap() {
        let signature =
            SelfSigningPrefix::Ed25519Sha512(signer.sign(query.encode().unwrap()).unwrap());
        query_with_retries(who_id, query, signature).await?;
    }

    Ok(())
}

async fn query_with_retries(
    who_id: &Identifier,
    qry: QueryEvent,
    signature: SelfSigningPrefix,
) -> Result<(), VerifyHandleError> {
    let mut qr = QueryResponse::NoUpdates;

    let mut delay = Duration::from_secs(1);
    for _i in 0..5 {
        let (qry_reps, _errs) = who_id
            .finalize_query(vec![(qry.clone(), signature.clone())])
            .await;
        qr = qry_reps;
        if qr == QueryResponse::NoUpdates {
            sleep(delay);
            delay *= 2;
        } else {
            break;
        }
    }
    Ok(())
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
