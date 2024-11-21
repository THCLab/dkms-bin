use std::{fs::File, io::Write, sync::Arc};

use keri_controller::{EndRole, IdentifierPrefix, Oobi};
use keri_core::actor::prelude::SelfAddressingIdentifier;
use serde_json::Value;

use crate::{
    keri::{issue, query_tel},
    said::SaidError,
    utils::{load, load_signer, working_directory},
    CliError,
};

pub async fn handle_tel_incept(alias: &str) -> Result<(), CliError> {
    let mut id = load(alias)?;
    let signer = Arc::new(load_signer(alias)?);
    crate::keri::incept_registry(&mut id, signer).await?;

    // Save registry identifier
    let mut store_path = working_directory()?;
    store_path.push(alias);

    let mut reg_path = store_path.clone();
    reg_path.push("reg_id");
    let mut file = File::create(reg_path)?;
    file.write_all(id.registry_id().as_ref().unwrap().to_string().as_bytes())?;

    Ok(())
}

pub async fn handle_issue(alias: &str, data: &str) -> Result<(), CliError> {
    let mut id = load(alias)?;

    if let Ok(root) = serde_json::from_str::<Value>(data) {
        let digest: &str = root
            .get("d")
            .and_then(|v| v.as_str())
            .ok_or(CliError::MissingDigest)?;
        let said: SelfAddressingIdentifier =
            digest.parse().map_err(|e| SaidError::InvalidSaid(e))?;

        let signer = Arc::new(load_signer(alias)?);
        issue(&mut id, said, signer).await?;
    } else {
        println!("Wrong json format: {}", data);
    };
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
    let registry_id = identifier.registry_id().unwrap();
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

    Ok(())
}
