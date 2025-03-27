use std::sync::Arc;

use keri_controller::{
    identifier::Identifier, mailbox_updating::ActionRequired, IdentifierPrefix, LocationScheme,
    Oobi, SelfSigningPrefix,
};
use keri_core::{
    event_message::{msg::TypedEvent, timestamped::Timestamped, EventTypeTag},
    query::mailbox::MailboxRoute,
    signer::Signer,
};

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

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let group_id = initiator_id
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), signature_exn)],
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

pub async fn accept(id: &mut Identifier, signer: Arc<Signer>, index: usize) -> IdentifierPrefix {
    let mut req = Requests::new();
    let action = req.remove(id.id(), index);
    process_action(id, signer, &action).await.unwrap()
}

async fn process_action(
    identifier: &mut Identifier,
    signer: Arc<Signer>,
    action: &ActionRequired,
) -> Result<IdentifierPrefix, CliError> {
    let id = match action {
        ActionRequired::DelegationRequest(_, _) => {
            todo!()
        }
        ActionRequired::MultisigRequest(multisig_event, exn) => {
            println!(
                "Got multisig request: {}",
                String::from_utf8(multisig_event.encode().unwrap()).unwrap()
            );
            let signature_ixn = SelfSigningPrefix::Ed25519Sha512(
                signer.sign(&multisig_event.encode().unwrap()).unwrap(),
            );
            let signature_exn =
                SelfSigningPrefix::Ed25519Sha512(signer.sign(&exn.encode().unwrap()).unwrap());
            identifier
                .finalize_group_incept(
                    &multisig_event.encode().unwrap(),
                    signature_ixn.clone(),
                    vec![(exn.encode().unwrap(), signature_exn)],
                )
                .await
                .unwrap()
        }
    };
    Ok(id)
}
