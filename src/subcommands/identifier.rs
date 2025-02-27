use std::io::{self, IsTerminal, Read};
use std::{
    fs::{self},
    path::PathBuf,
};

use clap::Subcommand;
use keri_controller::LocationScheme;
use tabled::{builder::Builder, settings::Style};
use url::Url;

use crate::export::IdentifierExport;
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
        /// The URL of the witness
        #[arg(long)]
        witness_url: Vec<Url>,
        /// The URL of the watcher
        #[arg(long)]
        watcher_url: Vec<Url>,
        /// Natural number specifying the minimum witnesses needed to confirm a KEL event
        #[arg(long)]
        witness_threshold: Option<u64>,
    },
    /// Show the identifier details of a specified alias
    Info { 
        /// Alias of the identifier to retrieve details about
        alias: String 
    },
    /// List all aliases and their corresponding identifiers
    List,
    /// List identifier OOBIs
    Oobi {
        #[command(subcommand)]
        command: OobiCommands,
    },
    /// Export identifier data to JSON
    Export {   
        /// Alias ot the identifier to export
        alias: String 
    },
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
        /// Identifier whose OOBI is requested
        #[arg(short, long)]
        alias: String,
        /// Optional argument that specifies the role of the requested OOBI. Possible values are 'witness', 'watcher', 'messagebox'
        #[command(subcommand)]
        role: Option<OobiRoles>,
    },
    /// Resolves provided OOBI and saves it
    Resolve {
        /// Alias of the identifier that will be used to save resolved OOBI
        #[arg(short, long)]
        alias: String,
        /// Path to the file, which contains list of OOBIs to resolve in JSON format
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
            witness_url: witness,
            watcher_url: watcher,
            witness_threshold,
        } => {
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

            handle_init(
                alias,
                Some(KeysConfig::default()),
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
                let imported: IdentifierExport = serde_json::from_str(&data).map_err(|_e| {
                    IdentifierSubcommandError::ArgumentsError("Invalid JSON".to_string())
                })?;
                handle_import(&alias, imported).await?;
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
                let imported: IdentifierExport = serde_json::from_str(&buffer).map_err(|_e| {
                    IdentifierSubcommandError::ArgumentsError("Invalid JSON".to_string())
                })?;
                handle_import(&alias, imported).await?;
                Ok(())
            }
        },
    }
}
