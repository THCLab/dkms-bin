use std::sync::Arc;

use keri_sdk::keri_controller::{
    identifier::mechanics::MechanicsError, BasicPrefix, IdentifierPrefix, LocationScheme,
};
use keri_sdk::keri_core::{
    actor::prelude::SelfAddressingIdentifier, keys::KeysError, signer::Signer,
};
use keri_sdk::Identifier;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeriError {
    #[error(transparent)]
    ControllerError(#[from] keri_sdk::keri_controller::error::ControllerError),
    #[error(transparent)]
    MechanicsError(#[from] MechanicsError),
    #[error(transparent)]
    Keri(#[from] keri_sdk::keri_core::error::Error),
    #[error(transparent)]
    SigningError(#[from] KeysError),
    #[error(transparent)]
    Sdk(#[from] keri_sdk::Error),
}

/// Query the TEL for a specific credential. Signs and submits the query to
/// watchers; the caller is responsible for subsequently reading
/// [`Identifier::find_vc_state`] to observe the result.
pub async fn query_tel(
    acdc_d: &SelfAddressingIdentifier,
    registry_id: SelfAddressingIdentifier,
    _issuer_id: &IdentifierPrefix,
    id: &Identifier,
    km: Arc<Signer>,
) -> Result<(), KeriError> {
    let qry = id.query_tel(
        IdentifierPrefix::self_addressing(registry_id),
        IdentifierPrefix::self_addressing(acdc_d.clone()),
    )?;
    let signature = crate::utils::ed25519_sig(&km, &qry.encode()?)?;
    id.finalize_query_tel(qry, signature).await?;
    Ok(())
}

/// Rotate keys. Thin wrapper over [`keri_sdk::operations::rotate`] that also
/// lets callers specify `new_next_threshold` (not currently exposed through
/// [`keri_sdk::types::RotationConfig`]) and a prebuilt `new_next_keys` vec.
pub async fn rotate(
    id: &mut Identifier,
    current_signer: Arc<Signer>,
    new_next_keys: Vec<BasicPrefix>,
    new_next_threshold: u64,
    witness_to_add: Vec<LocationScheme>,
    witness_to_remove: Vec<BasicPrefix>,
    witness_threshold: u64,
) -> Result<(), KeriError> {
    let current_keys_prefix = vec![BasicPrefix::Ed25519NT(current_signer.public_key())];

    let rotation = id
        .rotate(
            current_keys_prefix,
            new_next_keys,
            new_next_threshold,
            witness_to_add,
            witness_to_remove,
            witness_threshold,
        )
        .await?;
    let signature = crate::utils::ed25519_sig(&current_signer, rotation.as_bytes())?;
    id.finalize_rotate(rotation.as_bytes(), signature).await?;
    id.notify_witnesses().await?;

    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in witnesses {
        keri_sdk::operations::query_mailbox(id, current_signer.clone(), &witness).await?;
    }

    Ok(())
}
