use keri_sdk::ActionRequired;
use keri_sdk::CesrPrimitive;
use keri_sdk::SelfAddressingIdentifier;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Result;
use keri_sdk::{
    Controller, Identifier, IdentifierPrefix, LocationScheme,
};
use keri_sdk::{
    SeedPrefix, Signer,
    protocol::{KeyEvent, KeriEvent, Exchange, ExchangeMessage},
};
use serde::de::DeserializeOwned;
use serde_json::{from_value, json, Value};
use thiserror::Error;

use crate::{resolve::find_locations, subcommands::membership::Membership};

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
    ControllerError(#[from] keri_sdk::protocol::ControllerError),
    #[error("Signer error: {0}")]
    SignerError(String),
    #[error("Can't load home path")]
    HomePath,
    #[error(transparent)]
    Mechanics(#[from] keri_sdk::protocol::MechanicsError),
    #[error(transparent)]
    Sdk(#[from] keri_sdk::Error),
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
        .unwrap()
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

    let mut db_path = store_path;
    db_path.push("db");
    let cont = Controller::new(db_path)?;
    Ok(cont.load_identifier(identifier, registry_id))
}

pub fn load_group_id(alias: &str, group_alias: &str) -> Result<Identifier, LoadingError> {
    let mem = Membership::new(alias);
    let identifier = mem.get_identifier(group_alias);

    let registry_id = mem.get_group_registry(group_alias);
    println!("Registry id  {:?} loaded for {}", registry_id, group_alias);

    let mut db_path = working_directory()?;
    db_path.push(alias);
    db_path.push("db");
    let cont = Controller::new(db_path)?;
    Ok(cont.load_identifier(identifier, registry_id))
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

pub fn save_identifier(id: &IdentifierPrefix, path: &Path) -> Result<(), std::io::Error> {
    let mut id_path = path.to_path_buf();
    id_path.push("id");
    let mut file = File::create(id_path)?;
    file.write_all(id.to_str().as_bytes())?;
    Ok(())
}

pub fn load_controller(alias: &str) -> Result<Controller, LoadingError> {
    let mut db_path = working_directory()?;
    db_path.push(alias);
    db_path.push("db");

    Controller::new(db_path).map_err(LoadingError::Sdk)
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

pub fn save_seed(seed: &SeedPrefix, path: &Path) -> Result<(), std::io::Error> {
    let mut sk_path = path.to_path_buf();
    sk_path.push("priv_key");
    let mut file = File::create(sk_path)?;
    file.write_all(seed.to_str().as_bytes())?;
    Ok(())
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

pub fn save_next_seed(seed: &SeedPrefix, path: &Path) -> Result<(), std::io::Error> {
    let mut nsk_path = path.to_path_buf();
    nsk_path.push("next_priv_key");
    let mut file = File::create(nsk_path)?;
    file.write_all(seed.to_str().as_bytes())?;
    Ok(())
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
        keri_sdk::protocol::SignatureThreshold::Simple(i) => i,
        keri_sdk::protocol::SignatureThreshold::Weighted(
            _weighted_threshold,
        ) => {
            todo!()
        }
    };
    Ok((witness_oobi, witness_threshold))
}

pub fn collect_watchers_data(identifier: &Identifier) -> Result<Vec<LocationScheme>, LoadingError> {
    let watchers = identifier.get_role_location(identifier.id(), keri_sdk::protocol::Role::Watcher)?;
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

use redb::{Database, MultimapTableDefinition, ReadableTable, TableDefinition};

/// Index -> digest of event mapping
const INDEX: TableDefinition<u8, &str> = TableDefinition::new("ordered_requests");
/// Identifier-> digest of event mapping
const ACCEPTED: MultimapTableDefinition<&str, &str> = MultimapTableDefinition::new("accepted");
/// digest of event -> event mapping
const EVENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("events");
/// digest of event -> exchange mapping
const EXCHANGES: MultimapTableDefinition<&str, &[u8]> = MultimapTableDefinition::new("exchanges");

#[derive(Debug, Error)]
pub enum RequestError {
    #[error("Database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("Transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("Table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("Transaction error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("Storafe error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    Loading(#[from] LoadingError),
}

/// Storage for requests from other participants
pub struct Requests {
    db: Database,
    index: u8,
}

impl Requests {
    pub fn new(alias: &str) -> Result<Self, RequestError> {
        let mut dir = working_directory()?;
        dir.push(alias);
        fs::create_dir_all(&dir)?;
        dir.push("requests");
        let db = Database::create(dir).unwrap();
        let write_txn = db.begin_write()?;
        let length = {
            let table = write_txn.open_table(INDEX)?;
            let _table = write_txn.open_table(EVENTS)?;
            let _table = write_txn.open_multimap_table(EXCHANGES)?;
            let _table = write_txn.open_multimap_table(ACCEPTED)?;
            table.iter()?.count()
        };
        write_txn.commit()?;
        Ok(Self {
            db,
            index: length as u8,
        })
    }

    fn _get(
        &self,
        index: usize,
    ) -> Result<Option<(KeriEvent<KeyEvent>, Vec<KeriEvent<Exchange>>)>, RequestError> {
        let read_txn = self.db.begin_read()?;
        let index_table = read_txn.open_table(INDEX)?;
        let table = read_txn.open_table(EVENTS)?;
        let exn_table = read_txn.open_multimap_table(EXCHANGES)?;
        match index_table.get(index as u8)? {
            None => Ok(None),
            Some(value) => {
                let said = value.value();
                let event = table.get(said)?.unwrap();
                let parsed_event = serde_json::from_slice(event.value()).unwrap();
                let exn = exn_table.get(said)?.map(|value| {
                    serde_json::from_slice::<KeriEvent<Exchange>>(value.unwrap().value()).unwrap()
                });
                Ok(Some((parsed_event, exn.collect())))
            }
        }
    }

    pub fn save_accepted(
        &self,
        id: &IdentifierPrefix,
        said: &SelfAddressingIdentifier,
    ) -> Result<(), RequestError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut accepted_table = write_txn.open_multimap_table(ACCEPTED)?;
            accepted_table.insert(id.to_str().as_str(), said.to_str().as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn accept(
        &self,
        index: usize,
    ) -> Result<Option<(KeriEvent<KeyEvent>, Vec<ExchangeMessage>)>, RequestError> {
        let write_txn = self.db.begin_write()?;
        let out = {
            let mut index_table = write_txn.open_table(INDEX)?;
            let mut accepted_table = write_txn.open_multimap_table(ACCEPTED)?;
            let table = write_txn.open_table(EVENTS)?;
            let mut exn_table = write_txn.open_multimap_table(EXCHANGES)?;
            let said = index_table.remove(index as u8)?;
            match said {
                Some(value) => {
                    let said = value.value();
                    let event = table.get(said)?.unwrap();
                    let parsed_event: KeriEvent<KeyEvent> =
                        serde_json::from_slice(event.value()).unwrap();
                    let exn = exn_table.remove_all(said)?;
                    let exn = exn.into_iter().map(|value| {
                        serde_json::from_slice::<ExchangeMessage>(value.unwrap().value()).unwrap()
                    });
                    let id = parsed_event.data.get_prefix();
                    accepted_table.insert(
                        id.to_str().as_str(),
                        parsed_event.digest().unwrap().to_str().as_str(),
                    )?;
                    Some((parsed_event, exn.collect()))
                }
                _ => None,
            }
        };
        write_txn.commit()?;
        Ok(out)
    }

    fn get_pending(
        &self,
    ) -> Result<Vec<(u8, KeriEvent<KeyEvent>, Vec<KeriEvent<Exchange>>)>, RequestError> {
        let read_txn = self.db.begin_read()?;
        let index_table = read_txn.open_table(INDEX)?;
        let table = read_txn.open_table(EVENTS)?;
        let exn_table = read_txn.open_multimap_table(EXCHANGES)?;
        index_table
            .iter()
            .unwrap()
            .map(|i| {
                let (key, value) = i?;
                let index = key.value();
                let digest = value.value();
                let event = table.get(digest)?.unwrap();
                let parsed_event = serde_json::from_slice(event.value()).unwrap();
                let exn = exn_table.get(digest)?.map(|value| {
                    serde_json::from_slice::<KeriEvent<Exchange>>(value.unwrap().value()).unwrap()
                });
                Ok((index, parsed_event, exn.collect()))
            })
            .collect()
    }

    /// Store a pending request using the raw `ActionRequired` from keri-controller.
    ///
    /// This is the bridge for code that still works with the lower-level mailbox
    /// types directly (e.g. `pull_mailbox_helper`).
    pub fn add(&mut self, request: ActionRequired) -> Result<Option<u8>, RequestError> {
        match request {
            ActionRequired::MultisigRequest(typed_event, exchange) => {
                let id = typed_event.data.get_prefix();
                let read_txn = self.db.begin_read()?;
                let accepted_table = read_txn.open_multimap_table(ACCEPTED)?;
                let events_table = read_txn.open_table(EVENTS)?;
                let said = typed_event.digest().unwrap();
                let said_str = said.to_str();
                // Check if already accepted
                let already_accepted = accepted_table
                    .get(id.to_str().as_str())?
                    .into_iter()
                    .any(|value| {
                        value.as_ref().unwrap().value().eq(said_str.as_str())
                    });
                // Check if already pending
                let already_pending = events_table.get(said_str.as_str())?.is_some();
                if !already_accepted && !already_pending {
                    let write_txn = self.db.begin_write()?;
                    {
                        let mut table = write_txn.open_table(INDEX)?;
                        table.insert(self.index, said.to_str().as_str())?;
                        self.index += 1;
                        let mut table = write_txn.open_table(EVENTS)?;
                        table.insert(
                            said.to_str().as_str(),
                            serde_json::to_vec(&typed_event).unwrap().as_slice(),
                        )?;
                        let mut table = write_txn.open_multimap_table(EXCHANGES)?;
                        table.insert(
                            said.to_str().as_str(),
                            serde_json::to_vec(&exchange).unwrap().as_slice(),
                        )?;
                    }
                    write_txn.commit()?;
                } else {
                    return Ok(None);
                }
            }
            ActionRequired::DelegationRequest(_typed_event, _typed_event1) => todo!(),
        };
        Ok(Some(self.index - 1))
    }

    pub fn show_one(index: u8, event: &KeriEvent<KeyEvent>) -> String {
        use keri_sdk::protocol::EventData;
        let prefix = event.data.get_prefix();
        let event_type = match &event.data.event_data {
            EventData::Icp(icp) => {
                let n_members = icp.key_config.public_keys.len();
                format!("group inception ({} members)", n_members)
            }
            EventData::Dip(dip) => {
                let n_members = dip.inception_data.key_config.public_keys.len();
                format!("delegated group inception ({} members)", n_members)
            }
            EventData::Ixn(_) => "group interaction".to_string(),
            EventData::Rot(_) | EventData::Drt(_) => "group rotation".to_string(),
        };
        format!("[{}] {} — {}", index, prefix, event_type)
    }

    pub fn show(&self) -> Result<Vec<String>, RequestError> {
        Ok(self
            .get_pending()?
            .iter()
            .map(|r| Self::show_one(r.0, &r.1))
            .collect())
    }
}

#[test]
pub fn test_parse_json_arguments() {
    use keri_sdk::LocationScheme;

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
