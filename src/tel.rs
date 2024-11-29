use std::{fs::File, io::Write, sync::Arc};

use keri_controller::{EndRole, IdentifierPrefix, Oobi};
use keri_core::actor::prelude::SelfAddressingIdentifier;

use crate::{
    keri::{issue, query_tel},
    said::{compute_and_update_digest, SaidError},
    utils::{load, load_signer, working_directory},
    CliError,
};

pub fn save_registry(alias: &str, registry_id: &str) -> Result<(), CliError> {
    let mut store_path = working_directory()?;
    store_path.push(alias);

    let mut reg_path = store_path.clone();
    reg_path.push("reg_id");
    let mut file = File::create(reg_path)?;
    file.write_all(registry_id.as_bytes())?;
    Ok(())
}

pub async fn handle_issue(alias: &str, data: &str) -> Result<(), CliError> {
    let mut id = load(alias)?;

    if let Ok(mut root) =
        serde_json::from_str::<indexmap::IndexMap<String, serde_json::Value>>(data)
    {
        let signer = Arc::new(load_signer(alias)?);
        if id.registry_id().is_none() {
            // incept TEL if not incepted
            crate::keri::incept_registry(&mut id, signer.clone()).await?;
            let registry_id = id.registry_id().as_ref().unwrap().to_string();
            save_registry(alias, &registry_id)?;
        };
        insert_issuer_and_registry(id.id(), id.registry_id().unwrap(), &mut root)?;
        let digest: &str = root
            .get("d")
            .and_then(|v| v.as_str())
            .ok_or(CliError::MissingDigest)?;
        let said: SelfAddressingIdentifier = digest.parse().map_err(SaidError::InvalidSaid)?;

        issue(&mut id, said, signer).await?;
        println!("{}", serde_json::to_string(&root).unwrap());
    } else {
        println!("Wrong json format: {}", data);
    };
    Ok(())
}

fn insert_issuer_and_registry(
    issuer: &IdentifierPrefix,
    registry: &IdentifierPrefix,
    data: &mut indexmap::IndexMap<String, serde_json::Value>,
) -> Result<(), SaidError> {
    data.insert_before(
        0,
        "i".to_string(),
        serde_json::Value::String(issuer.to_string()),
    );
    data.insert_before(
        1,
        "ri".to_string(),
        serde_json::Value::String(registry.to_string()),
    );
    data.insert_before(
        2,
        "d".to_string(),
        serde_json::Value::String("".to_string()),
    );
    compute_and_update_digest(data)
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
