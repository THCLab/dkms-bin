use std::{
    error::Error,
    fmt::Display,
    fs::{self, remove_dir_all},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use config_file::{ConfigFileError, FromConfigFile};
use ed25519_dalek::SigningKey;

use keri_controller::{
    config::ControllerConfig, controller::Controller, identifier::Identifier, BasicPrefix,
    LocationScheme, SeedPrefix,
};
use keri_core::signer::Signer;
use serde::{Deserialize, Serialize};

use crate::{
    keri::{setup_identifier, KeriError},
    subcommands::identifier::IdentifierSubcommandError,
    tel::remove_registry,
    utils::{save_identifier, save_next_seed, save_seed, working_directory, LoadingError},
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
            ConfigFileError::Json(error) => write!(f, "Configuration file error: {}", error),
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

fn ask_for_confirmation(prompt: &str) -> bool {
    print!("{} (y|N)", prompt);
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
    keys_config: Option<KeysConfig>,
    witnesses: Vec<LocationScheme>,
    watchers: Vec<LocationScheme>,
    witness_threshold: u64,
) -> Result<(), IdentifierSubcommandError> {
    let witness_config = if witnesses.is_empty() {
        None
    } else {
        Some(witnesses)
    };
    let watcher_config = if watchers.is_empty() {
        None
    } else {
        Some(watchers)
    };
    let kel_config = KelConfig {
        witness: witness_config,
        witness_threshold,
        watcher: watcher_config,
    };

    let keys = keys_config.unwrap_or_default();

    // Compute kel database path
    let store_path = kel_database_path(&alias)?;

    println!("Initializing identifier for alias {:?}...", store_path);
    let mut db_path = store_path.clone();
    db_path.push("db");

    let info = format!("No witnesses are configured for {} identifier, so KEL won't be publicly available. To configure witnesses, provide their OOBIs with --witness option", &alias);
    match &kel_config.witness {
        Some(wits) if wits.is_empty() => println!("{}", info),
        None => println!("{}", info),
        Some(_) => (),
    };

    let id = handle_new_id(&keys, kel_config, &db_path).await;
    match id {
        Ok(id) => {
            let _ = remove_registry(&alias);
            // Save next keys seed
            save_next_seed(&keys.next, &store_path)?;

            // Save identifier
            save_identifier(id.id(), &store_path)?;
            // Save private key
            save_seed(&keys.current, &store_path)?;

            print!("\nIdentifier for alias {} initialized: {}", alias, id.id());
        }
        Err(e) => {
            println!("{}", e)
        }
    }

    Ok(())
}

pub fn kel_database_path(alias: &str) -> Result<PathBuf, LoadingError> {
    // Compute kel database path
    let mut store_path = working_directory()?;
    store_path.push(&alias);

    if !store_path.exists() {
        fs::create_dir_all(&store_path)?;
    }
    if store_path.is_dir() {
        match fs::read_dir(&store_path) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    if ask_for_confirmation(&format!(
                        "The alias '{}' already exists. Are you sure you want to overwrite it?",
                        alias
                    )) {
                        remove_dir_all(&store_path)?;
                    } else {
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => eprintln!("Error accessing directory: {}", e),
        }
    } else {
        println!(
            "Error: The path {:?} is not a directory",
            store_path.to_str().unwrap()
        );
        std::process::exit(1);
    }
    Ok(store_path)
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
    // Clear old identifier cache if exists
    let mut query_cache_path = db_path.clone();
    query_cache_path.push("query_cache");
    let _ = std::fs::remove_file(&query_cache_path);
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
    let mut file = std::fs::File::create(file_path.clone()).unwrap();
    writeln!(file, "{}", &keys_yaml).unwrap();

    let conf: Result<KeysConfig, _> = Figment::new().merge(Yaml::file(file_path)).extract();
    assert!(conf.is_ok());
}
