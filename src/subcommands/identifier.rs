use std::io::{self, IsTerminal, Read};
use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use clap::Subcommand;
use keri_controller::LocationScheme;
use tabled::{builder::Builder, settings::Style};
use url::Url;

use crate::{
    export::{handle_export, handle_import, ExportError},
    init::{handle_init, KeysConfig},
    keri::KeriError,
    resolve::{self, handle_resolve, OobiRoles},
    utils::{handle_info, working_directory, LoadingError},
};

#[derive(Subcommand)]
pub enum IdentifierCommand {
    /// Initialize a new identifier with an associated alias
    Init {
        /// Alias of the identifier used by the tool for internal purposes
        #[arg(short, long)]
        alias: Option<String>,
        /// File with seed of the keys: current and next
        #[arg(long)]
        from_seed_file: Option<PathBuf>,
        /// The URL of the witness
        #[arg(long)]
        witness_url: Vec<Url>,
        /// The URL of the watcher
        #[arg(long)]
        watcher_url: Vec<Url>,
        /// Natural number specifying the minimum witnesses needed to confirm a KEL event
        #[arg(long)]
        witness_threshold: Option<u64>,
        /// Generates json file with current and next keys seeds in provided path
        #[arg(long)]
        init_seed_file: Option<PathBuf>,
    },
    /// Show the identifier details of a specified alias
    Info { alias: String },
    /// List all aliases and their corresponding identifiers
    List,
    /// List identifier OOBIs
    Oobi {
        #[command(subcommand)]
        command: OobiCommands,
    },
    /// Export identifier data to JSON
    Export { alias: String },
    /// Import identifier data from JSON
    Import {
        /// Alias for imported identifier
        alias: String,
        /// JSON produced by export command
        data: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum OobiCommands {
    /// Returns saved OOBIs of provided alias
    Get {
        #[arg(short, long)]
        alias: String,
        #[command(subcommand)]
        role: Option<OobiRoles>,
    },
    // Resolves provided oobi and saves it
    Resolve {
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        file: PathBuf,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum IdentifierSubcommandError {
    #[error("{0}")]
    InitError(#[from] InitError),
    #[error("{0}")]
    ArgumentsError(String),
    #[error(transparent)]
    FileError(#[from] std::io::Error),
    #[error(transparent)]
    LoadingError(#[from] LoadingError),
    #[error(transparent)]
    KeriError(#[from] KeriError),
    #[error(transparent)]
    Export(#[from] ExportError),
}

#[derive(thiserror::Error, Debug)]
pub enum InitError {
    #[error("Make sure that provided urls are correct. \nDetails: \n{0}")]
    UrlError(#[from] url::ParseError),
    #[error("Can't connect with provided address. Make sure that provided urls are correct. Details:\n{0}")]
    ReqwestError(#[from] reqwest::Error),
}

async fn find_oobi(url: url::Url) -> Result<LocationScheme, InitError> {
    let introduce_url = url.clone().join("introduce")?;
    Ok(reqwest::get(introduce_url)
        .await?
        .json::<LocationScheme>()
        .await?)
}

async fn find_oobis_for_urls<I>(urls: I) -> Result<Vec<LocationScheme>, InitError>
where
    I: IntoIterator<Item = Url>,
{
    futures::future::try_join_all(urls.into_iter().map(find_oobi)).await
}

pub async fn process_identifier_command(
    command: IdentifierCommand,
) -> Result<(), IdentifierSubcommandError> {
    match command {
        IdentifierCommand::Init {
            alias,
            from_seed_file: init_seed_file,
            witness_url: witness,
            watcher_url: watcher,
            witness_threshold,
            init_seed_file: seed_file,
        } => {
            match (&init_seed_file, &seed_file) {
                (None, Some(path)) => {
                    let kc = KeysConfig::default();
                    let mut file = File::create(path)?;
                    file.write_all(&serde_json::to_vec(&kc).unwrap())?;
                    println!("Seed generated and saved in {}", &path.to_str().unwrap());
                    return Ok(());
                }
                (_, None) => (),
                (Some(_), Some(_)) => {
                    return Err(IdentifierSubcommandError::ArgumentsError(
                        "You can specify only one of 'init_seed_file' or 'seed_file', but not both"
                            .to_string(),
                    ))
                }
            };

            let alias = if let Some(alias) = alias {
                alias
            } else {
                return Err(IdentifierSubcommandError::ArgumentsError(
                    "The 'alias' argument needs to be provided".to_string(),
                ));
            };

            let witness_threshold = match witness_threshold {
                Some(n) => n,
                None => {
                    if witness.is_empty() {
                        0
                    } else {
                        1
                    }
                }
            };

            let witnesses_oobis = find_oobis_for_urls(witness).await?;

            let watchers_oobis = find_oobis_for_urls(watcher).await?;

            let seed_conf = init_seed_file.map(|seed_path| {
                let contents = fs::read_to_string(&seed_path)
                    .map_err(|_e| {
                        IdentifierSubcommandError::ArgumentsError(format!(
                            "File {} doesn't exist",
                            seed_path.to_str().unwrap()
                        ))
                    })
                    .unwrap();
                serde_json::from_str(&contents)
                    .map_err(|_e| {
                        IdentifierSubcommandError::ArgumentsError(
                            "Wrong format of file with seeds".to_string(),
                        )
                    })
                    .unwrap()
            });

            handle_init(
                alias,
                seed_conf,
                witnesses_oobis,
                watchers_oobis,
                witness_threshold,
            )
            .await
        }
        IdentifierCommand::Info { alias } => Ok(handle_info(&alias)?),
        IdentifierCommand::List => {
            let working_directory = working_directory()?;
            let mut builder = Builder::new();
            builder.push_record(["ALIAS", "IDENTIFIER"]);
            if let Ok(contents) = fs::read_dir(&working_directory) {
                for entry in contents {
                    let entry = entry?;
                    let metadata = entry.metadata()?;

                    // Check if the entry is a directory
                    if metadata.is_dir() {
                        if let Some(alias) = entry.file_name().to_str() {
                            let mut id_path = working_directory.clone();
                            id_path.push(alias);
                            id_path.push("id");
                            let identifier = fs::read_to_string(id_path)
                                .map_err(|_e| LoadingError::UnknownIdentifier(alias.to_string()))?;
                            builder.push_record([alias.to_string(), identifier.to_string()]);
                        }
                    }
                }
            };
            let table = builder.build().with(Style::blank()).to_string();
            println!("{}", table);
            Ok(())
        }
        IdentifierCommand::Oobi { command } => {
            match command {
                OobiCommands::Get { role, alias } => match resolve::handle_oobi(&alias, &role) {
                    Ok(lcs) => println!("{}", serde_json::to_string(&lcs).unwrap()),
                    Err(e) => println!("{}", e),
                },
                OobiCommands::Resolve { alias, file } => handle_resolve(&alias, file).await?,
            };
            Ok(())
        }
        IdentifierCommand::Export { alias } => {
            let exported = handle_export(&alias)?;
            println!("{}", serde_json::to_string_pretty(&exported).unwrap());
            Ok(())
        }
        IdentifierCommand::Import { data, alias } => match data {
            Some(data) => {
                handle_import(&alias, &data).await?;
                Ok(())
            }
            None => {
                if io::stdin().is_terminal() {
                    eprintln!(
                        "Error: No input provided. Provide an argument or pipe data via stdin."
                    );
                    std::process::exit(1);
                }

                let mut buffer = String::new();
                io::stdin().read_to_string(&mut buffer).map_err(|e| {
                    IdentifierSubcommandError::ArgumentsError(format!(
                        "Failed to read from stdin: {}",
                        e
                    ))
                })?;
                handle_import(&alias, &buffer).await?;
                Ok(())
            }
        },
    }
}
