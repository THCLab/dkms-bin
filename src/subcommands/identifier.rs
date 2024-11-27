use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use clap::Subcommand;
use tabled::{builder::Builder, settings::Style};

use crate::{
    init::{handle_init, KeysConfig},
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
        alias: Option<String>,
        /// File with seed of the keys: current and next
        #[arg(long)]
        init_seed_file: Option<PathBuf>,
        /// OOBI of the witness (json format)
        #[arg(long)]
        witness: Vec<String>,
        /// OOBI of the watcher (json format)
        #[arg(long)]
        watcher: Vec<String>,
        /// Natural number specifying the minimum witnesses needed to confirm a KEL event
        #[arg(long)]
        witness_threshold: Option<u64>,
        /// Generates json file with current and next keys seeds in provided path
        #[arg(long)]
        seed_file: Option<PathBuf>,
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
            init_seed_file,
            witness,
            watcher,
            witness_threshold,
            seed_file,
        } => {
            match (&init_seed_file, &seed_file) {
                (None, Some(path)) => {
                    let kc = KeysConfig::default();
                    let mut file = File::create(&path)?;
                    file.write_all(&serde_json::to_vec(&kc).unwrap())?;
                    println!("Seed generated and saved in {}", &path.to_str().unwrap());
                    return Ok(());
                }
                (_, None) => (),
                (Some(_), Some(_)) => {
                    return Err(CliError::ArgumentsError(
                        "You can specify only one of 'init_seed_file' or 'seed_file', but not both"
                            .to_string(),
                    ))
                }
            };

            let alias = if let Some(alias) = alias {
                alias
            } else {
                return Err(CliError::ArgumentsError(
                    "The 'alias' argument needs to be provided".to_string(),
                ));
            };

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
                init_seed_file,
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
