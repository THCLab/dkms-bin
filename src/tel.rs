use std::{
    fs::{self, File},
    io::Write,
    sync::Arc,
};

use acdc::attributes::InlineAttributes;
use keri_controller::{identifier::Identifier, EndRole, IdentifierPrefix, Oobi, SelfSigningPrefix};
use keri_core::{
    actor::{event_generator, prelude::SelfAddressingIdentifier},
    event_message::signature::{Signature, SignerData},
    mailbox::exchange::ForwardTopic,
    prefix::IndexedSignature,
    signer::Signer,
};
use said::{derivation::HashFunctionCode, sad::SerializationFormats, version::Encode};

use crate::{
    keri::{issue, query_tel, revoke},
    multisig::issue_group,
    said::SaidError,
    subcommands::membership::Membership,
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

pub async fn handle_issue(alias: &str, data: &str, scheme: String) -> Result<(), CliError> {
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
            scheme,
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

pub async fn handle_group_registry_incept(
    group_id: &mut Identifier,
    participant_id: &IdentifierPrefix,
    signer: Arc<Signer>,
    mem: Arc<Membership>,
    group_alias: &str,
) -> Result<(), CliError> {
    if group_id.registry_id().is_none() {
        println!("Incepting registry");
        // incept TEL if not incept
        let (reg_id, ixn) = group_id.incept_registry().unwrap();

        let exn = event_generator::exchange(group_id.id(), &ixn, ForwardTopic::Multisig)
            .encode()
            .unwrap();
        let ixn = ixn.encode().unwrap();

        let signature = SelfSigningPrefix::new(
            cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
            signer.sign(&ixn).unwrap(),
        );

        let exn_signature = SelfSigningPrefix::new(
            cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
            signer.sign(&exn).unwrap(),
        );

        let exn_sig = Signature::Transferable(
            SignerData::LastEstablishment(participant_id.clone()),
            vec![IndexedSignature::new_both_same(exn_signature, 0)],
        );

        group_id
            .finalize_group_event(&ixn, signature, vec![(exn, exn_sig)])
            .await
            .unwrap();

        mem.save_group_registry(group_alias, &reg_id.to_string());
    };
    Ok(())
}

pub async fn handle_group_issue(
    mut group_id: Identifier,
    participant_id: &IdentifierPrefix,
    signer: Arc<Signer>,
    data: &str,
    scheme: String,
) -> Result<(), CliError> {
    if let Ok(root) = serde_json::from_str::<indexmap::IndexMap<String, serde_json::Value>>(data) {
        let mut attributes = InlineAttributes::default();
        for attr in root.iter() {
            attributes.insert(attr.0.clone(), attr.1.clone());
        }
        if group_id.registry_id().is_none() {
            // incept TEL if not incept
            println!("Registry not incepted for {}", group_id.id().to_string());
        };
        let attestation = acdc::Attestation::new_public_untargeted(
            &group_id.id().to_string(),
            group_id.registry_id().unwrap().to_string(),
            scheme,
            attributes,
        );

        let said = attestation.digest.clone().unwrap();

        issue_group(&mut group_id, participant_id, said, signer)
            .await
            .unwrap();
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
