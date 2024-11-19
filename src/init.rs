use std::{
    error::Error,
    fmt::Display,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use config_file::{ConfigFileError, FromConfigFile};
use ed25519_dalek::SigningKey;

use keri_controller::{
    config::ControllerConfig, controller::Controller, identifier::Identifier, BasicPrefix,
    CesrPrimitive, LocationScheme, SeedPrefix,
};
use keri_core::signer::Signer;
use serde::{Deserialize, Serialize};

use crate::{
    keri::{setup_identifier, KeriError},
    utils::{self, parse_json_arguments},
    CliError,
};

#[derive(Deserialize, Serialize, Debug)]
pub(crate) struct KelConfig {
    pub witness: Option<Vec<LocationScheme>>,
    pub witness_threshold: u64,
    pub watcher: Option<Vec<LocationScheme>>,
}

#[derive(Debug)]
pub struct ConfigError(ConfigFileError);

impl Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ConfigFileError::FileAccess(error) => {
                write!(f, "Configuration file loading error: {}", error)
            }
            ConfigFileError::Toml(error) => write!(f, "Configuration file error: {}", error),
            ConfigFileError::Yaml(error) => write!(f, "Configuration file error: {}", error),
            ConfigFileError::UnsupportedFormat => write!(f, "Unsupported configuration file error"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

impl Default for KelConfig {
    fn default() -> Self {
        Self {
            witness: Some(vec![]),
            witness_threshold: 0,
            watcher: None,
        }
    }
}
impl KelConfig {
    pub fn _load_from_file(config_path: &Path) -> Result<Self, ConfigError> {
        KelConfig::from_config_file(config_path).map_err(ConfigError)
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct KeysConfig {
    pub current: SeedPrefix,
    pub next: SeedPrefix,
}

impl Default for KeysConfig {
    fn default() -> Self {
        let current = SigningKey::generate(&mut rand::rngs::OsRng);
        let next = SigningKey::generate(&mut rand::rngs::OsRng);
        Self {
            current: SeedPrefix::RandomSeed256Ed25519(current.as_bytes().to_vec()),
            next: SeedPrefix::RandomSeed256Ed25519(next.as_bytes().to_vec()),
        }
    }
}

fn _ask_for_confirmation(prompt: &str) -> bool {
    print!("{} ", prompt);
    std::io::stdout().flush().unwrap();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let input = input.trim().to_lowercase();
    input == "y" || input == "yes"
}

pub async fn handle_init(
    alias: String,
    keys_file: Option<PathBuf>,
    witnesses: Option<Vec<String>>,
    watchers: Option<Vec<String>>,
    witness_threshold: u64,
) -> Result<(), CliError> {
    let witnesses_oobi = witnesses
        .map(|list| {
            parse_json_arguments::<LocationScheme>(
                &list.iter().map(|el| el.as_str()).collect::<Vec<_>>(),
            )
        })
        .transpose()?;
    let watchers_oobi = watchers
        .map(|list| {
            parse_json_arguments::<LocationScheme>(
                &list.iter().map(|el| el.as_str()).collect::<Vec<_>>(),
            )
        })
        .transpose()?;
    let kel_config = KelConfig {
        witness: witnesses_oobi,
        witness_threshold,
        watcher: watchers_oobi,
    };

    let keys = match keys_file {
        Some(file_path) => KeysConfig::from_config_file(file_path)?,
        None => {
            // println!("Generating keypairs for {}", &alias);
            KeysConfig::default()
        }
    };

    // Compute kel database path
    let mut store_path = utils::load_homedir()?;
    store_path.push(".dkms-dev-cli");
    store_path.push(&alias);
    fs::create_dir_all(&store_path)?;
    let mut db_path = store_path.clone();
    db_path.push("db");

    let info = format!("No witnesses are configured for {} identifier, so KEL won't be publicly available. To configure witnesses, provide config file with -c option", &alias);
    match &kel_config.witness {
        Some(wits) if wits.is_empty() => println!("{}", info),
        None => println!("{}", info),
        Some(_) => (),
    };

    let id = handle_new_id(&keys, kel_config, &db_path).await;
    match id {
        Ok(id) => {
            // Save next keys seed
            let mut nsk_path = store_path.clone();
            nsk_path.push("next_priv_key");
            let mut file = File::create(nsk_path)?;
            file.write_all(keys.next.to_str().as_bytes())?;

            print!("\nIdentifier for alias {} initialized: {}", alias, id.id());

            // Save identifier
            let mut id_path = store_path.clone();
            id_path.push("id");
            let mut file = File::create(id_path)?;
            file.write_all(id.id().to_string().as_bytes())?;

            // Save private key
            let mut priv_key_path = store_path.clone();
            priv_key_path.push("priv_key");
            let mut file = File::create(priv_key_path)?;
            file.write_all(keys.current.to_str().as_bytes())?;
        }
        Err(e) => {
            println!("{}", e)
        }
    }

    Ok(())
}

pub(crate) async fn handle_new_id(
    keys: &KeysConfig,
    kel_config: KelConfig,
    db_path: &Path,
) -> Result<Identifier, CliError> {
    let (npk, _nsk) = keys
        .next
        .derive_key_pair()
        .map_err(|_e| CliError::KeysDerivationError)?;

    let id = incept(
        db_path.to_path_buf(),
        keys.current.clone(),
        keri_controller::BasicPrefix::Ed25519NT(npk),
        kel_config.witness.unwrap_or_default(),
        kel_config.witness_threshold,
        None,
        kel_config.watcher.unwrap_or_default(),
    )
    .await?;
    Ok(id)
}

async fn incept(
    db_path: PathBuf,
    priv_key: SeedPrefix,
    next_key: BasicPrefix,
    witness: Vec<LocationScheme>,
    witness_threshold: u64,
    messagebox: Option<LocationScheme>,
    watcher: Vec<LocationScheme>,
) -> Result<Identifier, KeriError> {
    let cont = Arc::new(Controller::new(ControllerConfig {
        db_path,
        ..ControllerConfig::default()
    })?);
    let signer = Arc::new(Signer::new_with_seed(&priv_key)?);
    let id = setup_identifier(
        cont,
        signer,
        next_key,
        witness,
        witness_threshold,
        messagebox,
        watcher,
    )
    .await?;

    Ok(id)
}

#[test]
fn test_keys_config_parse() {
    use figment::{
        providers::{Format, Yaml},
        Figment,
    };
    let keys_yaml = "current: AFmIICAHyx5VfLZR2hrpSlTYKFPE58updFl-U96YBhda
next: AFmIICAHyx5VfLZR2hrpSlTYKFPE58updFl-U96YBhda";

    let dir = tempfile::tempdir().unwrap();

    let file_path = dir.path().join("temporary_keys.yaml");
    let mut file = File::create(file_path.clone()).unwrap();
    writeln!(file, "{}", &keys_yaml).unwrap();

    let conf: Result<KeysConfig, _> = Figment::new().merge(Yaml::file(file_path)).extract();
    assert!(conf.is_ok());
}
