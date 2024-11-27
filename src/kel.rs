use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
    sync::Arc,
};

use crate::{
    keri::KeriError,
    utils::{parse_json_arguments, working_directory},
    verify::VerifyHandleError,
};
use ed25519_dalek::SigningKey;
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use keri_controller::{
    identifier::{
        query::{QueryResponse, WatcherResponseError},
        Identifier,
    },
    BasicPrefix, CesrPrimitive, IdentifierPrefix, LocationScheme, Oobi, SeedPrefix,
    SelfSigningPrefix,
};
use keri_core::{actor::prelude::Message, signer::Signer};
use serde::{Deserialize, Serialize};

use crate::{
    keri::rotate,
    utils::{load, load_next_signer, load_signer},
    CliError,
};

#[derive(Debug, Deserialize, Serialize)]
struct RotationConfig {
    witness_to_add: Vec<LocationScheme>,
    witness_to_remove: Vec<BasicPrefix>,
    witness_threshold: u64,
    new_next_seed: Option<SeedPrefix>,
    new_next_threshold: u64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        let current = SigningKey::generate(&mut rand::rngs::OsRng);
        Self {
            witness_to_add: Default::default(),
            witness_to_remove: Default::default(),
            witness_threshold: 1,
            new_next_seed: Some(SeedPrefix::RandomSeed256Ed25519(
                current.as_bytes().to_vec(),
            )),
            new_next_threshold: 1,
        }
    }
}

pub async fn handle_kel_query(
    alias: &str,
    about_who: &IdentifierPrefix,
    oobi: Option<String>,
) -> Result<String, CliError> {
    let id = Arc::new(load(alias)?);
    let signer = Arc::new(load_signer(alias)?);

    let out = handle_get_identifier_kel(id.clone(), signer, about_who, oobi).await;
    Ok(match out {
        Ok(Some(kel)) => kel.to_string(),
        Ok(None) => {
            format!("Unknown identifier {}", about_who)
        }
        Err(err) => match err {
            CliError::KelGetting(vec) => {
                let err = vec
                    .iter()
                    .map(|e| {
                        match e {
                            WatcherResponseError::KELNotFound(identifier_prefix) => {
                                // check if identifier oobi is known
                                let oobis = id
                                    .clone()
                                    .get_end_role(identifier_prefix, keri_core::oobi::Role::Witness)
                                    .unwrap();
                                if oobis.is_empty() {
                                    VerifyHandleError::MissingOobi(identifier_prefix.clone())
                                        .to_string()
                                } else {
                                    e.to_string()
                                }
                            }
                            _ => e.to_string(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(". ");
                err.to_string()
            }
            _ => format!("{}", err),
        },
    })
}

pub async fn handle_rotate(alias: &str, config_path: Option<PathBuf>) -> Result<(), CliError> {
    let rotation_config = match config_path {
        Some(cfgs) => Figment::new()
            .merge(Yaml::file(cfgs.clone()))
            .extract()
            .unwrap_or_else(|_| panic!("Can't read file from path: {:?}", cfgs.to_str())),
        None => RotationConfig::default(),
    };

    let mut id = load(alias)?;
    // Load next keys as current
    let current_signer = Arc::new(load_next_signer(alias)?);

    let new_next_seed = rotation_config.new_next_seed.unwrap_or({
        let current = SigningKey::generate(&mut rand::rngs::OsRng);
        SeedPrefix::RandomSeed256Ed25519(current.as_bytes().to_vec())
    });

    let (npk, _nsk) = new_next_seed
        .derive_key_pair()
        .map_err(|_e| CliError::KeysDerivationError)?;
    let next_bp = BasicPrefix::Ed25519NT(npk);

    // Rotate keys
    rotate(
        &mut id,
        current_signer,
        vec![next_bp],
        rotation_config.new_next_threshold,
        rotation_config.witness_to_add,
        rotation_config.witness_to_remove,
        rotation_config.witness_threshold,
    )
    .await?;

    print!("\nKeys rotated for alias {} ({})", alias, id.id());

    // Save new settings in file
    let mut store_path = working_directory()?;
    store_path.push(alias);

    let mut nsk_path = store_path.clone();
    nsk_path.push("next_priv_key");

    let mut priv_key_path = store_path.clone();
    priv_key_path.push("priv_key");

    fs::copy(&nsk_path, priv_key_path)?;

    // Save new next key
    let mut file = File::create(nsk_path)?;
    file.write_all(new_next_seed.to_str().as_bytes())?;

    Ok(())
}

/// Returns KEL of identifier of provided alias that is stored locally.
pub async fn _handle_get_alias_kel(alias: &str) -> Result<Option<String>, CliError> {
    let id = load(alias)?;

    let kel = id
        .get_own_kel()
        .ok_or(CliError::UnknownIdentifier(id.id().to_string()))?;
    let kel_str = kel
        .into_iter()
        .flat_map(|kel| Message::Notice(kel).to_cesr().unwrap());
    Ok(Some(String::from_utf8(kel_str.collect()).unwrap()))
}

/// Queries identifier's watchers about identifier's KEL, and returns it. It will
/// query 5 times for each watcher, if KEL wasn't found, returns proper message.
pub async fn handle_get_identifier_kel(
    id: Arc<Identifier>,
    signer: Arc<Signer>,
    identifier: &IdentifierPrefix,
    oobi: Option<String>,
) -> Result<Option<String>, CliError> {
    if let Some(oobi) = oobi {
        for oobi in parse_json_arguments::<Oobi>(&[&oobi])? {
            id.send_oobi_to_watcher(id.id(), &oobi)
                .await
                .map_err(KeriError::ControllerError)?;
        }
    };

    for watcher_id in id
        .watchers()
        .map_err(super::keri::KeriError::ControllerError)?
    {
        let qry = id
            .query_full_log(identifier, watcher_id.clone())
            .map_err(KeriError::ControllerError)?;
        let signature =
            SelfSigningPrefix::Ed25519Sha512(signer.sign(qry.encode().unwrap()).unwrap());
        let (mut qry_reps, mut errs) = id.finalize_query(vec![(qry, signature)]).await;
        let mut loop_count = 0;
        while let QueryResponse::NoUpdates = qry_reps {
            if loop_count > 5 {
                return Err(CliError::KelGetting(errs));
            };
            let qry = id.query_full_log(identifier, watcher_id.clone()).unwrap();
            let signature =
                SelfSigningPrefix::Ed25519Sha512(signer.sign(qry.encode().unwrap()).unwrap());
            let (qry_resp, new_errs) = id.finalize_query(vec![(qry, signature)]).await;
            errs = new_errs;
            qry_reps = qry_resp;
            loop_count += 1;
        }
    }

    let kel = id
        .get_kel(identifier)
        .ok_or(CliError::UnknownIdentifier(identifier.to_string()))?;
    let kel_str = kel
        .into_iter()
        .flat_map(|kel| Message::Notice(kel).to_cesr().unwrap());
    Ok(Some(String::from_utf8(kel_str.collect()).unwrap()))
}
