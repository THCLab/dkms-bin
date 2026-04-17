use anyhow::Result;
use keri_sdk::{
    operations::{incept_registry, issue, revoke, rotate},
    types::RotationConfig,
    BasicPrefix, IdentifierPrefix, LocationScheme, SelfSigningPrefix,
    Identifier, Signer,
};
use keri_sdk::SelfAddressingIdentifier;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeriError {
    #[error(transparent)]
    ControllerError(#[from] keri_sdk::protocol::ControllerError),
    #[error(transparent)]
    MechanicsError(#[from] keri_sdk::protocol::MechanicsError),
    #[error(transparent)]
    Keri(#[from] keri_sdk::protocol::CoreError),
    #[error(transparent)]
    SigningError(#[from] keri_sdk::protocol::KeysError),
    #[error(transparent)]
    Sdk(#[from] keri_sdk::Error),
}

pub async fn handle_incept_registry(
    id: &mut Identifier,
    signer: Arc<Signer>,
) -> Result<(), KeriError> {
    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
    if witnesses.is_empty() {
        println!(
            "No witnesses are configured for {} identifier, so TEL won't be publicly available.",
            &id.id()
        );
    }
    incept_registry(id, signer).await?;
    Ok(())
}

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
    let signature = SelfSigningPrefix::new(
        keri_sdk::protocol::SelfSigning::Ed25519Sha512,
        km.sign(qry.encode()?)?,
    );

    id.finalize_query_tel(qry, signature).await?;
    Ok(())
}

pub async fn handle_rotate(
    id: &mut Identifier,
    current_signer: Arc<Signer>,
    new_next_keys: Vec<BasicPrefix>,
    _new_next_threshold: u64,
    witness_to_add: Vec<LocationScheme>,
    witness_to_remove: Vec<BasicPrefix>,
    witness_threshold: u64,
) -> Result<(), KeriError> {
    let config = RotationConfig {
        new_next_pk: new_next_keys.into_iter().next().unwrap(),
        witness_to_add,
        witness_to_remove,
        witness_threshold,
    };
    rotate(id, current_signer, config).await?;
    Ok(())
}

pub async fn handle_issue(
    identifier: &mut Identifier,
    cred_said: SelfAddressingIdentifier,
    km: Arc<Signer>,
) -> Result<(), KeriError> {
    issue(identifier, km, cred_said).await?;
    Ok(())
}

pub async fn handle_revoke(
    identifier: &mut Identifier,
    cred_said: &SelfAddressingIdentifier,
    km: Arc<Signer>,
) -> Result<(), KeriError> {
    revoke(identifier, km, cred_said).await?;
    Ok(())
}

