use std::sync::Arc;

use keri_sdk::{
    operations::{
        accept_multisig, create_multisig, poll_pending_requests, sync_multisig,
    },
    types::{MultisigConfig, PendingRequest},
    Identifier, IdentifierPrefix, LocationScheme, SelfSigningPrefix,
    Signer,
};
use keri_core::{
    actor::event_generator,
    event::KeyEvent,
    event_message::{
        msg::KeriEvent,
        signature::{Signature, SignerData},
    },
    mailbox::exchange::ForwardTopic,
    prefix::IndexedSignature,
};
use said::SelfAddressingIdentifier;

use crate::{error::CliError, keri::KeriError, utils::Requests};

/// Create a multisig group identifier (initiator side).
///
/// Resolves witness OOBIs, creates the group inception event, signs it,
/// and sends invitations to all members. Returns the group `IdentifierPrefix`.
pub async fn group_incept(
    initiator_id: &mut Identifier,
    initiator_signer: Arc<Signer>,
    members: Vec<IdentifierPrefix>,
    key_threshold: u64,
    _next_keys_threshold: Option<u64>,
    witnesses: Vec<LocationScheme>,
    witness_threshold: u64,
) -> Result<IdentifierPrefix, KeriError> {
    // Resolve witness OOBIs before creating the group.
    for witness_oobi in &witnesses {
        initiator_id
            .resolve_oobi(&keri_sdk::Oobi::Location(witness_oobi.clone()))
            .await?;
    }

    let config = MultisigConfig {
        members,
        threshold: key_threshold,
        witnesses,
        witness_threshold,
        delegator: None,
    };

    let group_id = create_multisig(initiator_id, &initiator_signer, config).await?;
    Ok(group_id)
}

/// Poll the identifier's mailbox for pending requests (delegation or multisig).
pub async fn pull_mailbox(
    identifier: &mut Identifier,
    signer: Arc<Signer>,
) -> Result<Vec<PendingRequest>, CliError> {
    let requests = poll_pending_requests(identifier, &signer)
        .await
        .map_err(|e| CliError::KeriError(KeriError::Sdk(e)))?;
    Ok(requests)
}

/// Synchronise multisig state: collect co-signatures and witness receipts.
pub async fn pull_group_mailbox(
    identifier: &mut Identifier,
    group_id: &IdentifierPrefix,
    signer: Arc<Signer>,
) -> Result<(), CliError> {
    sync_multisig(identifier, &signer, group_id)
        .await
        .map_err(|e| CliError::KeriError(KeriError::Sdk(e)))?;
    Ok(())
}

/// Accept a pending multisig request from the Requests DB.
pub async fn accept(
    id: &mut Identifier,
    req: Requests,
    signer: Arc<Signer>,
    index: usize,
) -> Option<IdentifierPrefix> {
    let action = req.accept(index).unwrap();
    match action {
        Some((event, exchanges)) => {
            process_multisig_request(id, signer, event, exchanges)
                .await
                .unwrap()
        }
        None => None,
    }
}

/// Process a raw multisig request from the local request DB.
///
/// For inception/delegated-inception events, this reconstructs an
/// `ActionRequired::MultisigRequest` and passes it through the SDK's
/// `accept_multisig`. For other event types (e.g., group interactions),
/// it uses the lower-level `finalize_group_event` path.
async fn process_multisig_request(
    identifier: &mut Identifier,
    signer: Arc<Signer>,
    multisig_event: KeriEvent<KeyEvent>,
    exchanges: Vec<keri_core::mailbox::exchange::ExchangeMessage>,
) -> Result<Option<IdentifierPrefix>, CliError> {
    use keri_core::event_message::EventTypeTag;
    use keri_sdk::ActionRequired;

    println!(
        "Got multisig request: {}",
        String::from_utf8(multisig_event.encode().unwrap()).unwrap()
    );

    match multisig_event.event_type {
        EventTypeTag::Icp | EventTypeTag::Dip => {
            // Reconstruct ActionRequired and convert to MultisigRequest for SDK.
            let action = ActionRequired::MultisigRequest(
                multisig_event,
                exchanges.into_iter().next().unwrap(),
            );
            let request = keri_sdk::MultisigRequest::try_from(action).unwrap();
            let group_prefix = request.group_prefix();
            accept_multisig(identifier, &signer, request)
                .await
                .map_err(|e| CliError::KeriError(KeriError::Sdk(e)))?;
            Ok(Some(group_prefix))
        }
        _ => {
            // Non-inception group events (e.g. ixn for credential issuance)
            // still need the lower-level path.
            let signature_ixn = SelfSigningPrefix::Ed25519Sha512(
                signer.sign(&multisig_event.encode().unwrap()).unwrap(),
            );

            let signed_exchanges: Vec<(Vec<u8>, Signature)> = exchanges
                .into_iter()
                .map(|exn| {
                    let serialized_exn = exn.encode().unwrap();
                    let signature_exn =
                        SelfSigningPrefix::Ed25519Sha512(signer.sign(&serialized_exn).unwrap());
                    let exn_index_signature =
                        identifier.sign_with_index(signature_exn, 0).unwrap();
                    (serialized_exn, exn_index_signature)
                })
                .collect();

            identifier
                .finalize_group_event(
                    &multisig_event.encode().unwrap(),
                    signature_ixn,
                    signed_exchanges,
                )
                .await
                .unwrap();
            Ok(None)
        }
    }
}

/// Issue a credential from a group identifier.
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

    let signature = SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        km.sign(&ixn_encoded)?,
    );

    let exn_signature = SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        km.sign(&exn)?,
    );

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
