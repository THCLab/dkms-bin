use std::sync::Arc;

use keri_sdk::advanced::{ActionRequired, IdentifierPrefix, LocationScheme, Oobi};
use keri_sdk::advanced::raw::keri_core::{
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
use keri_sdk::advanced::{Identifier, MultisigConfig, SelfAddressingIdentifier};

use crate::{error::CliError, keri::KeriError, utils::Requests};

pub async fn group_incept(
    initiator_id: &mut Identifier,
    initiator_signer: Arc<Signer>,
    members: Vec<IdentifierPrefix>,
    key_threshold: u64,
    witness: Vec<LocationScheme>,
    witness_threshold: u64,
) -> Result<IdentifierPrefix, KeriError> {
    // Resolve witness OOBIs so the group inception can reference them.
    for witness_oobi in &witness {
        initiator_id
            .resolve_oobi(&Oobi::Location(witness_oobi.clone()))
            .await?;
    }

    let config = MultisigConfig {
        members,
        threshold: key_threshold,
        witnesses: witness,
        witness_threshold,
        delegator: None,
    };
    Ok(
        keri_sdk::advanced::operations::create_multisig(initiator_id, &initiator_signer, config)
            .await?,
    )
}

pub async fn pull_mailbox(
    identifier: &mut Identifier,
    signer: Arc<Signer>,
) -> Result<Vec<ActionRequired>, CliError> {
    let witnesses = identifier.witnesses();

    // Quering mailbox to get multisig request
    let query: Vec<TypedEvent<EventTypeTag, Timestamped<MailboxRoute>>> = identifier
        .query_mailbox(&identifier.id(), &witnesses)
        .unwrap();

    let mut out = Vec::new();
    for qry in query {
        let signature = crate::utils::ed25519_sig(&signer, &qry.encode().unwrap()).unwrap();
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
        .query_mailbox(group_id, &witnesses)
        .unwrap();

    let mut out = Vec::new();
    for qry in query {
        let signature = crate::utils::ed25519_sig(&signer, &qry.encode().unwrap()).unwrap();
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
        crate::utils::ed25519_sig(&signer, &multisig_event.encode().unwrap()).unwrap();

    let signed_exchanges = exchanges
        .into_iter()
        .map(|exn| {
            let serialized_exn = exn.encode().unwrap();
            let signature_exn = crate::utils::ed25519_sig(&signer, &serialized_exn).unwrap();

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

    let signature = crate::utils::ed25519_sig(&km, &ixn_encoded)?;
    let exn_signature = crate::utils::ed25519_sig(&km, &exn)?;

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
