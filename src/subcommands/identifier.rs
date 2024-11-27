use std::{fs, path::PathBuf};

use clap::Subcommand;
use tabled::{builder::Builder, settings::Style};

use crate::{
    init::handle_init,
    resolve::{self, handle_resolve, OobiRoles},
    utils::{handle_info, working_directory, LoadingError},
    CliError,
};

#[derive(Subcommand)]
pub enum IdentifierCommand {
    /// Init new signer
    Init {
        /// Alias of the identifier used by the tool for internal purposes
        #[arg(short, long)]
        alias: String,
        /// File with seed of the keys: current and next
        #[arg(short, long)]
        keys_file: Option<PathBuf>,
        /// OOBI of the witness (json format)
        #[arg(long)]
        witness: Vec<String>,
        /// OOBI of the watcher (json format)
        #[arg(long)]
        watcher: Vec<String>,
        /// Natural number specifying the minimum witnesses needed to confirm a KEL event
        #[arg(long)]
        witness_threshold: Option<u64>,
    },
    /// Shows information about identifier of given alias
    Whoami { alias: String },
    /// Lists all created aliases along with their identifiers
    List,
    /// Manage saved OOBIs
    Oobi {
        #[command(subcommand)]
        command: OobiCommands,
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

pub async fn process_identifier_command(command: IdentifierCommand) -> Result<(), CliError> {
    match command {
        IdentifierCommand::Init {
            alias,
            keys_file,
            witness,
            watcher,
            witness_threshold,
        } => {
            let witness_threshold = witness_threshold.unwrap_or(1);
            let witnesses_oobi = if witness.is_empty() {
                None
            } else {
                Some(witness)
            };
            let watchers_oobi = if watcher.is_empty() {
                None
            } else {
                Some(watcher)
            };
            handle_init(
                alias,
                keys_file,
                witnesses_oobi,
                watchers_oobi,
                witness_threshold,
            )
            .await
        }
        IdentifierCommand::Whoami { alias } => Ok(handle_info(&alias)?),
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
    }
}
