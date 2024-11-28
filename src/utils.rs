use std::{fs, path::PathBuf, sync::Arc};

use anyhow::Result;
use keri_controller::{
    config::ControllerConfig,
    controller::Controller,
    identifier::{mechanics::MechanicsError, Identifier},
    IdentifierPrefix, LocationScheme, SeedPrefix,
};
use keri_core::signer::Signer;
use serde::de::DeserializeOwned;
use serde_json::{from_value, json, Value};
use thiserror::Error;

use crate::resolve::find_locations;

#[derive(Error, Debug)]
pub enum LoadingError {
    #[error("Unknown identifier alias: {0}")]
    UnknownIdentifier(String),
    #[error(transparent)]
    File(#[from] std::io::Error),
    #[error("Can't load a path: {0}")]
    PathError(PathBuf),
    #[error("Parsing error: {0}")]
    ParsingError(String),
    #[error("Controller error: {0}")]
    ControllerError(#[from] keri_controller::error::ControllerError),
    #[error("Signer error: {0}")]
    SignerError(String),
    #[error("Can't load home path")]
    HomePath,
    #[error(transparent)]
    Mechanics(#[from] MechanicsError),
}

pub fn working_directory() -> Result<PathBuf, LoadingError> {
    let mut working_directory = load_homedir()?;
    working_directory.push(".dkms-dev-cli");
    Ok(working_directory)
}

pub fn load(alias: &str) -> Result<Identifier, LoadingError> {
    let mut store_path = working_directory()?;
    store_path.push(alias);
    let mut id_path = store_path.clone();
    id_path.push("id");
    let mut registry_path = store_path.clone();
    registry_path.push("reg_id");

    let identifier: IdentifierPrefix = fs::read_to_string(id_path.clone())
        .map_err(|_e| LoadingError::UnknownIdentifier(alias.to_string()))?
        .parse()
        .map_err(|_e| {
            LoadingError::ParsingError(format!(
                "Can't parse identifier from file: {}",
                id_path.to_str().unwrap()
            ))
        })?;
    let registry_id = match fs::read_to_string(registry_path.clone()) {
        Ok(reg) => reg.parse().ok(),
        Err(_) => None,
    };

    let cont = Arc::new(load_controller(alias)?);
    Ok(Identifier::new(
        identifier,
        registry_id,
        cont.known_events.clone(),
        cont.communication.clone(),
    ))
}

pub fn load_identifier(alias: &str) -> Result<IdentifierPrefix, LoadingError> {
    let mut store_path = working_directory()?;
    store_path.push(alias);
    let mut id_path = store_path.clone();
    id_path.push("id");

    let identifier: IdentifierPrefix = fs::read_to_string(id_path.clone())
        .map_err(|_e| LoadingError::PathError(id_path.clone()))?
        .trim()
        .parse()
        .map_err(|_e| {
            LoadingError::ParsingError(format!(
                "Can't parse identifier from file: {}",
                id_path.to_str().unwrap()
            ))
        })?;
    Ok(identifier)
}

pub fn load_controller(alias: &str) -> Result<Controller, LoadingError> {
    let mut db_path = working_directory()?;
    db_path.push(alias);
    db_path.push("db");

    let cont = Controller::new(ControllerConfig {
        db_path,
        ..ControllerConfig::default()
    })
    .map_err(LoadingError::ControllerError)?;
    Ok(cont)
}

pub fn load_seed(alias: &str) -> Result<SeedPrefix, LoadingError> {
    let mut path = working_directory()?;
    path.push(alias);
    path.push("priv_key");
    let sk_str = fs::read_to_string(path)?;
    sk_str
        .parse()
        .map_err(|_e| LoadingError::SignerError("Seed parsing error".to_string()))
}

pub fn load_next_seed(alias: &str) -> Result<SeedPrefix, LoadingError> {
    let mut path = working_directory()?;
    path.push(alias);
    path.push("next_priv_key");
    let sk_str = fs::read_to_string(path)?;
    sk_str
        .parse()
        .map_err(|_e| LoadingError::SignerError("Seed parsing error".to_string()))
}

pub fn load_signer(alias: &str) -> Result<Signer, LoadingError> {
    let seed: SeedPrefix = load_seed(alias)?;
    let signer =
        Signer::new_with_seed(&seed).map_err(|e| LoadingError::SignerError(e.to_string()))?;

    Ok(signer)
}

pub fn load_next_signer(alias: &str) -> Result<Signer, LoadingError> {
    let seed = load_next_seed(alias)?;
    let signer =
        Signer::new_with_seed(&seed).map_err(|e| LoadingError::SignerError(e.to_string()))?;

    Ok(signer)
}

pub fn handle_info(alias: &str) -> Result<(), LoadingError> {
    let cont = load(alias)?;
    let (witness_locations, witness_threshold) = collect_witness_data(&cont)?;
    let watchers = collect_watchers_data(&cont)?;
    let info = if let Some(reg) = cont.registry_id() {
        json!({"id": cont.id(), "registry": reg, "witnesses" : witness_locations, "witness_threshold": witness_threshold, "watchers": watchers})
    } else {
        json!({"id": cont.id(), "witnesses" : witness_locations, "witness_threshold": witness_threshold, "watchers": watchers})
    };
    println!("{}", serde_json::to_string_pretty(&info).unwrap());

    Ok(())
}

pub fn load_homedir() -> Result<PathBuf, LoadingError> {
    home::home_dir().ok_or(LoadingError::HomePath)
}

#[derive(Debug, Error)]
pub enum ExtractionError {
    #[error("Provided json doesn't match expected type")]
    InvalidType(String),
    #[error("Provided string isn't valid json")]
    InvalidJson(String),
    #[error("Expected element or list of elements")]
    UnexpectedJsonValue,
}

pub fn extract_objects<T: DeserializeOwned>(
    value: &serde_json::Value,
) -> Result<Vec<T>, ExtractionError> {
    match value {
        Value::Array(vec) => vec.iter().try_fold(vec![], |mut acc, el| {
            acc.append(&mut extract_objects(el)?);
            Ok(acc)
        }),
        Value::Object(map) => match from_value::<T>(Value::Object(map.clone())) {
            Ok(value) => Ok(vec![value]),
            Err(_e) => Err(ExtractionError::InvalidType(
                serde_json::to_string(&value).unwrap(),
            )),
        },
        _ => Err(ExtractionError::UnexpectedJsonValue),
    }
}

pub fn collect_witness_data(
    identifier: &Identifier,
) -> Result<(Vec<LocationScheme>, u64), LoadingError> {
    let state = identifier.find_state(identifier.id())?;
    let witness_oobi = find_locations(
        identifier,
        state
            .witness_config
            .witnesses
            .into_iter()
            .map(IdentifierPrefix::Basic),
    );
    let witness_threshold = state.witness_config.tally;
    let witness_threshold = match witness_threshold {
        keri_core::event::sections::threshold::SignatureThreshold::Simple(i) => i,
        keri_core::event::sections::threshold::SignatureThreshold::Weighted(
            _weighted_threshold,
        ) => {
            todo!()
        }
    };
    Ok((witness_oobi, witness_threshold))
}

pub fn collect_watchers_data(identifier: &Identifier) -> Result<Vec<LocationScheme>, LoadingError> {
    let watchers = identifier.get_role_location(identifier.id(), keri_core::oobi::Role::Watcher)?;
    Ok(watchers)
}

pub fn parse_json_arguments<T: DeserializeOwned>(
    input_oobis: &[&str],
) -> Result<Vec<T>, ExtractionError> {
    let oobis: Vec<T> = input_oobis.iter().try_fold(vec![], |mut acc, oobi_str| {
        match serde_json::from_str::<Value>(oobi_str) {
            Ok(ok) => {
                let mut objects = crate::utils::extract_objects(&ok)?;
                acc.append(&mut objects);
                Ok(acc)
            }
            Err(_e) => Err(ExtractionError::InvalidJson(oobi_str.to_string())),
        }
    })?;
    Ok(oobis)
}

#[test]
pub fn test_parse_json_arguments() {
    use keri_controller::LocationScheme;

    let input_single = r#"{"eid":"BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4","scheme":"http","url":"http://witness2.sandbox.argo.colossi.network/"}"#;
    let loc = parse_json_arguments::<LocationScheme>(&[input_single]);
    assert!(loc.is_ok());

    let input_list = r#"[{"eid":"BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4","scheme":"http","url":"http://witness2.sandbox.argo.colossi.network/"}, {"eid":"BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4","scheme":"http","url":"http://witness2.sandbox.argo.colossi.network/"}]"#;
    let loc = parse_json_arguments::<LocationScheme>(&[input_list]);
    assert!(loc.is_ok());

    let input_wrong = r#"{"eid":"WRONG_ID","scheme":"http","url":"http://witness2.sandbox.argo.colossi.network/"}"#;
    let loc = parse_json_arguments::<LocationScheme>(&[input_wrong]);
    assert!(matches!(loc, Err(ExtractionError::InvalidType(_))));

    let input_wrong = r#"not_json"#;
    let loc = parse_json_arguments::<LocationScheme>(&[input_wrong]);
    assert!(matches!(loc, Err(ExtractionError::InvalidJson(_))));

    let input_multi = [input_list, input_single];
    let loc = parse_json_arguments::<LocationScheme>(&input_multi);
    assert!(loc.is_ok());
}
