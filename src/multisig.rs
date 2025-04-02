use std::{f64::consts::E, sync::Arc};

use keri_controller::{
    identifier::Identifier, mailbox_updating::ActionRequired, IdentifierPrefix, LocationScheme,
    Oobi, SelfSigningPrefix,
};
use keri_core::{
    actor::event_generator, event_message::{msg::TypedEvent, signature::{Signature, SignerData}, timestamped::Timestamped, EventTypeTag}, mailbox::exchange::ForwardTopic, prefix::IndexedSignature, query::mailbox::MailboxRoute, signer::Signer
};
use said::SelfAddressingIdentifier;

use crate::{error::CliError, keri::{query_mailbox, KeriError}, utils::Requests};

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
    let kc = initiator_id.find_state(initiator_id.id()).unwrap().current;
    let index = initiator_id.index_in_current_keys(&kc).unwrap();
    let sig_exn = Signature::Transferable(
        SignerData::LastEstablishment(initiator_id.id().clone()),
        vec![IndexedSignature::new_both_same(signature_exn, index as u16)],
    );

    let group_id = initiator_id
        .finalize_group_event(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), sig_exn)],
        )
        .await?;

    Ok(group_id.unwrap())
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

pub async fn accept(id: &mut Identifier, signer: Arc<Signer>, index: usize) -> Option<IdentifierPrefix> {
    let mut req = Requests::new();
    let action = req.remove(id.id(), index);
    process_action(id, signer, &action).await.unwrap()
}

async fn process_action(
    identifier: &mut Identifier,
    signer: Arc<Signer>,
    action: &ActionRequired,
) -> Result<Option<IdentifierPrefix>, CliError> {
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

            let kc = identifier.find_state(identifier.id()).unwrap().current;
            let index = identifier.index_in_current_keys(&kc).unwrap();
            let sig_exn = Signature::Transferable(
                SignerData::LastEstablishment(identifier.id().clone()),
                vec![IndexedSignature::new_both_same(signature_exn, index as u16)],
            );

            identifier
                .finalize_group_event(
                    &multisig_event.encode().unwrap(),
                    signature_ixn.clone(),
                    vec![(exn.encode().unwrap(), sig_exn)],
                )
                .await
                .unwrap()
        }
    };
    Ok(id)
}


pub async fn issue_group(
    identifier: &mut Identifier,
    cred_said: SelfAddressingIdentifier,
    km: Arc<Signer>,
) -> Result<(), KeriError> {
    let (vc_id, ixn) = identifier.issue(cred_said.clone()).unwrap();

    let exn = event_generator::exchange(identifier.id(), &ixn, ForwardTopic::Multisig).encode()?;
    let ixn = ixn.encode()?;

    let signature = SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        km.sign(&ixn)?,
    );

    let exn_signature = SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        km.sign(&exn)?,
    );
    todo!();

    // assert_eq!(vc_id.to_string(), cred_said.to_string());
    // identifier.finalize_group_anchor(&ixn, signature, vec![(exn, exn_signature)]).await.unwrap();

    // identifier.notify_witnesses().await?;
    // let witnesses = identifier
    //     .find_state(identifier.id())?
    //     .witness_config
    //     .witnesses;
    // for witness in witnesses {
    //     let _qry = query_mailbox(identifier, km.clone(), &witness).await?;
    // }

    // identifier.notify_backers().await?;

    Ok(())
}
