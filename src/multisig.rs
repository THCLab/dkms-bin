use std::sync::Arc;

use cesrox::primitives::codes::self_signing::SelfSigning;
use keri_controller::{
    identifier::Identifier, mailbox_updating::ActionRequired, IdentifierPrefix, LocationScheme,
    Oobi, SelfSigningPrefix,
};
use keri_core::{
    actor::event_generator,
    event::KeyEvent,
    event_message::{
        msg::{KeriEvent, TypedEvent},
        signature::{Signature, SignerData},
        timestamped::Timestamped,
        EventTypeTag,
    },
    mailbox::exchange::{ExchangeMessage, ForwardTopic},
    prefix::IndexedSignature,
    query::mailbox::MailboxRoute,
    signer::Signer,
};
use said::SelfAddressingIdentifier;

use crate::{error::CliError, keri::KeriError, utils::Requests};

pub async fn group_incept(
    initiator_id: &mut Identifier,
    initiator_signer: Arc<Signer>,
    members: Vec<IdentifierPrefix>,
    key_threshold: u64,
    next_keys_threshold: Option<u64>,
    witness: Vec<LocationScheme>,
    witness_threshold: u64,
) -> Result<IdentifierPrefix, KeriError> {
    // proces witness oobis
    for witness_oobi in &witness {
        initiator_id
            .resolve_oobi(&Oobi::Location(witness_oobi.clone()))
            .await?;
    }

    let witnesses_id = witness
        .into_iter()
        .map(|witness| match witness.eid {
            IdentifierPrefix::Basic(id) => id,
            _ => todo!(),
        })
        .collect();

    // Incept group
    let (group_inception, exn_messages) = initiator_id.incept_group(
        members,
        key_threshold,
        next_keys_threshold,
        Some(witnesses_id),
        Some(witness_threshold),
        None,
    )?;

    let signature_icp =
        SelfSigningPrefix::Ed25519Sha512(initiator_signer.sign(group_inception.as_bytes())?);
    let signature_exn =
        SelfSigningPrefix::Ed25519Sha512(initiator_signer.sign(exn_messages[0].as_bytes())?);

    let exn_index_signature = initiator_id.sign_with_index(signature_exn, 0)?;

    let group_id = initiator_id
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), exn_index_signature)],
        )
        .await?;

    Ok(group_id)
}

pub async fn pull_mailbox(
    identifier: &mut Identifier,
    signer: Arc<Signer>,
) -> Result<Vec<ActionRequired>, CliError> {
    let witnesses = identifier.witnesses();

    // Quering mailbox to get multisig request
    let query: Vec<TypedEvent<EventTypeTag, Timestamped<MailboxRoute>>> = identifier
        .query_mailbox(&identifier.id(), &witnesses.collect::<Vec<_>>())
        .unwrap();

    let mut out = Vec::new();
    for qry in query {
        let signature =
            SelfSigningPrefix::Ed25519Sha512(signer.clone().sign(&qry.encode().unwrap()).unwrap());
        let mut action_required = identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
        out.append(&mut action_required);
    }
    Ok(out)
}

pub async fn pull_group_mailbox(
    identifier: &mut Identifier,
    group_id: &IdentifierPrefix,
    signer: Arc<Signer>,
) -> Result<Vec<ActionRequired>, CliError> {
    let witnesses = identifier.witnesses();

    // Quering mailbox to get multisig request
    let query: Vec<TypedEvent<EventTypeTag, Timestamped<MailboxRoute>>> = identifier
        .query_mailbox(group_id, &witnesses.collect::<Vec<_>>())
        .unwrap();

    let mut out = Vec::new();
    for qry in query {
        let signature =
            SelfSigningPrefix::Ed25519Sha512(signer.clone().sign(&qry.encode().unwrap()).unwrap());
        let mut action_required = identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
        out.append(&mut action_required);
    }
    Ok(out)
}

pub async fn accept(
    id: &mut Identifier,
    req: Requests,
    signer: Arc<Signer>,
    index: usize,
) -> Option<IdentifierPrefix> {
    let action = req.accept(index).unwrap();
    match action {
        Some((event, exchanges)) => process_multisig_request(id, signer, event, exchanges)
            .await
            .unwrap(),
        None => None,
    }
}

async fn process_multisig_request(
    identifier: &mut Identifier,
    signer: Arc<Signer>,
    multisig_event: KeriEvent<KeyEvent>,
    exchanges: Vec<ExchangeMessage>,
) -> Result<Option<IdentifierPrefix>, CliError> {
    println!(
        "Got multisig request: {}",
        String::from_utf8(multisig_event.encode().unwrap()).unwrap()
    );
    let signature_ixn =
        SelfSigningPrefix::Ed25519Sha512(signer.sign(&multisig_event.encode().unwrap()).unwrap());

    let signed_exchanges = exchanges
        .into_iter()
        .map(|exn| {
            let serialized_exn = exn.encode().unwrap();
            let signature_exn =
                SelfSigningPrefix::Ed25519Sha512(signer.sign(&serialized_exn).unwrap());

            let exn_index_signature = identifier.sign_with_index(signature_exn, 0).unwrap();
            (serialized_exn, exn_index_signature)
        })
        .collect();
    match multisig_event.event_type {
        EventTypeTag::Icp | EventTypeTag::Dip => {
            let id = identifier
                .finalize_group_incept(
                    &multisig_event.encode().unwrap(),
                    signature_ixn.clone(),
                    signed_exchanges,
                )
                .await
                .unwrap();
            Ok(Some(id))
        }
        _ => {
            identifier
                .finalize_group_event(
                    &multisig_event.encode().unwrap(),
                    signature_ixn.clone(),
                    signed_exchanges,
                )
                .await
                .unwrap();
            Ok(None)
        }
    }
}

pub async fn issue_group(
    group_identifier: &mut Identifier,
    participant_id: &IdentifierPrefix,
    cred_said: SelfAddressingIdentifier,
    km: Arc<Signer>,
    requests: &Requests,
) -> Result<(), KeriError> {
    let (vc_id, ixn) = group_identifier.issue(cred_said.clone()).unwrap();

    let exn =
        event_generator::exchange(group_identifier.id(), &ixn, ForwardTopic::Multisig).encode()?;
    let ixn_encoded = ixn.encode()?;

    let signature = SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, km.sign(&ixn_encoded)?);

    let exn_signature = SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, km.sign(&exn)?);
   
    let exn_index_signature = Signature::Transferable(
        SignerData::LastEstablishment(participant_id.clone()),
        vec![IndexedSignature::new_both_same(exn_signature, 0)],
    );

    assert_eq!(vc_id.to_string(), cred_said.to_string());
    group_identifier
        .finalize_group_event(&ixn_encoded, signature, vec![(exn, exn_index_signature)])
        .await
        .unwrap();
    requests
        .save_accepted(&ixn.data.prefix, &ixn.digest().unwrap())
        .unwrap();

    Ok(())
}
