use std::{fs, path::PathBuf, sync::Arc};

use anyhow::Result;
use keri_controller::{
    config::ControllerConfig, controller::Controller, identifier::Identifier, IdentifierPrefix,
    SeedPrefix,
};
use keri_core::signer::Signer;
use serde::de::DeserializeOwned;
use serde_json::{from_value, json, Value};
use thiserror::Error;

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
    ControllerError(keri_controller::error::ControllerError),
    #[error("Signer error: {0}")]
    SignerError(String),
    #[error("Can't load home path")]
    HomePath,
}

pub fn load(alias: &str) -> Result<Identifier, LoadingError> {
    let mut store_path = load_homedir()?;
    store_path.push(".dkms-dev-cli");
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
    let mut store_path = load_homedir()?;
    store_path.push(".dkms-dev-cli");
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
    let mut db_path = load_homedir()?;
    db_path.push(".dkms-dev-cli");
    db_path.push(alias);
    db_path.push("db");

    let cont = Controller::new(ControllerConfig {
        db_path,
        ..ControllerConfig::default()
    })
    .map_err(LoadingError::ControllerError)?;
    Ok(cont)
}

pub fn load_signer(alias: &str) -> Result<Signer, LoadingError> {
    let mut path = load_homedir()?;
    path.push(".dkms-dev-cli");
    path.push(alias);
    path.push("priv_key");
    let sk_str = fs::read_to_string(path)?;
    let seed: SeedPrefix = sk_str
        .parse()
        .map_err(|_e| LoadingError::SignerError("Seed parsing error".to_string()))?;
    let signer =
        Signer::new_with_seed(&seed).map_err(|e| LoadingError::SignerError(e.to_string()))?;

    Ok(signer)
}

pub fn load_next_signer(alias: &str) -> Result<Signer, LoadingError> {
    let mut path = load_homedir()?;
    path.push(".dkms-dev-cli");
    path.push(alias);
    path.push("next_priv_key");
    let sk_str = fs::read_to_string(path)?;
    let seed: SeedPrefix = sk_str
        .parse()
        .map_err(|_e| LoadingError::SignerError("Seed parsing error".to_string()))?;
    let signer =
        Signer::new_with_seed(&seed).map_err(|e| LoadingError::SignerError(e.to_string()))?;

    Ok(signer)
}

pub fn handle_info(alias: &str) -> Result<(), LoadingError> {
    let cont = load(alias)?;
    let info = if let Some(reg) = cont.registry_id() {
        json!({"id": cont.id(), "registry": reg})
    } else {
        json!({"id": cont.id()})
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
        Value::Array(vec) => vec
            .into_iter()
            .fold(Ok(vec![]), |mut acc, el| match extract_objects(el) {
                Ok(mut obj) => {
                    let _ = acc.as_mut().map(|oobis| oobis.append(&mut obj));
                    acc
                }
                Err(e) => return Err(e),
            }),
        Value::Object(map) => match from_value::<T>(Value::Object(map.clone())) {
            Ok(value) => Ok(vec![value]),
            Err(_e) => {
                return Err(ExtractionError::InvalidType(
                    serde_json::to_string(&value).unwrap(),
                ))
            }
        },
        _ => Err(ExtractionError::UnexpectedJsonValue),
    }
}

pub fn parse_json_arguments<T: DeserializeOwned>(
    input_oobis: &[&str],
) -> Result<Vec<T>, ExtractionError> {
    let oobis: Vec<T> = input_oobis.iter().fold(Ok(vec![]), |mut acc, oobi_str| {
        match serde_json::from_str::<Value>(&oobi_str) {
            Ok(ok) => {
                let objects = crate::utils::extract_objects(&ok);

                match objects {
                    Ok(mut obj) => {
                        let _ = acc.as_mut().map(|oobis| oobis.append(&mut obj));
                    }
                    Err(e) => {
                        acc = Err(e);
                    }
                };
                acc
            }
            Err(_e) => Err(ExtractionError::InvalidJson(oobi_str.to_string())),
        }
    })?;
    Ok(oobis)
}
