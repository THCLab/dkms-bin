use std::{
    fs::{self, File},
    io::Write,
    sync::Arc,
};

use acdc::attributes::InlineAttributes;
use keri_controller::{EndRole, IdentifierPrefix, Oobi};
use keri_core::actor::prelude::SelfAddressingIdentifier;
use said::{derivation::HashFunctionCode, sad::SerializationFormats, version::Encode};

use crate::{
    keri::{issue, query_tel, revoke},
    said::SaidError,
    utils::{load, load_signer, working_directory, LoadingError},
    CliError,
};

pub fn save_registry(alias: &str, registry_id: &str) -> Result<(), LoadingError> {
    let mut store_path = working_directory()?;
    store_path.push(alias);

    let mut reg_path = store_path.clone();
    reg_path.push("reg_id");
    let mut file = File::create(reg_path)?;
    file.write_all(registry_id.as_bytes())?;
    Ok(())
}

pub fn remove_registry(alias: &str) -> Result<(), CliError> {
    let mut store_path = working_directory()?;
    store_path.push(alias);

    let mut reg_path = store_path.clone();
    reg_path.push("reg_id");

    if fs::metadata(&reg_path).is_ok() {
        fs::remove_file(reg_path)?;
    };
    Ok(())
}

pub async fn handle_issue(alias: &str, data: &str) -> Result<(), CliError> {
    let mut id = load(alias)?;

    if let Ok(root) = serde_json::from_str::<indexmap::IndexMap<String, serde_json::Value>>(data) {
        let mut attributes = InlineAttributes::default();
        for attr in root.iter() {
            attributes.insert(attr.0.clone(), attr.1.clone());
        }
        let signer = Arc::new(load_signer(alias)?);
        if id.registry_id().is_none() {
            // incept TEL if not incepted
            crate::keri::incept_registry(&mut id, signer.clone()).await?;
            let registry_id = id.registry_id().as_ref().unwrap().to_string();
            save_registry(alias, &registry_id)?;
        };
        let attestation = acdc::Attestation::new_public_untargeted(
            &id.id().to_string(),
            id.registry_id().unwrap().to_string(),
            "schema".to_string(),
            attributes,
        );

        let said = attestation.digest.clone().unwrap();

        issue(&mut id, said, signer).await?;
        let attestation_str = String::from_utf8(
            attestation
                .encode(&HashFunctionCode::Blake3_256, &SerializationFormats::JSON)
                .unwrap(),
        )
        .unwrap();
        println!("{}", attestation_str);
    } else {
        println!("Wrong json format: {}", data);
    };
    Ok(())
}

pub fn extract_said(data: &str) -> Result<SelfAddressingIdentifier, CliError> {
    if let Ok(root) = serde_json::from_str::<indexmap::IndexMap<String, serde_json::Value>>(data) {
        let digest: &str = root
            .get("d")
            .and_then(|v| v.as_str())
            .ok_or(CliError::MissingDigest)?;
        Ok(digest.parse().map_err(SaidError::InvalidSaid)?)
    } else {
        println!("Wrong json format: {}", data);
        Err(CliError::JsonExpected)
    }
}

pub async fn handle_revoke(alias: &str, said: &SelfAddressingIdentifier) -> Result<(), CliError> {
    let mut id = load(alias)?;
    let signer = Arc::new(load_signer(alias)?);
    revoke(&mut id, said, signer).await?;
    println!("Revoked {}", said);

    Ok(())
}

pub async fn handle_query(
    alias: &str,
    said: &str,
    registry_id: &str,
    issuer_id: &str,
) -> Result<(), CliError> {
    let who_id = load(alias)?;
    let issuer: IdentifierPrefix = issuer_id.parse().unwrap();
    let said: SelfAddressingIdentifier = said.parse().unwrap();
    let registry_id: SelfAddressingIdentifier = registry_id.parse().unwrap();

    let signer = Arc::new(load_signer(alias)?);
    query_tel(&said, registry_id, &issuer, &who_id, signer).await?;

    match who_id.find_vc_state(&said) {
        Ok(Some(state)) => println!("{:?}", state),
        Ok(None) => println!("Tel not found"),
        Err(e) => println!("{}", e),
    }

    Ok(())
}

pub fn handle_tel_oobi(alias: &str) -> Result<(), CliError> {
    let identifier = load(alias)?;
    if let Some(registry_id) = identifier.registry_id() {
        let oobis = identifier
            .witnesses()
            .map(|wit_id| {
                Oobi::EndRole(EndRole {
                    cid: registry_id.clone(),
                    role: keri_core::oobi::Role::Witness,
                    eid: IdentifierPrefix::Basic(wit_id),
                })
            })
            .collect::<Vec<_>>();

        println!("{}", serde_json::to_string(&oobis).unwrap());
    }

    Ok(())
}
