use std::path::PathBuf;

use clap::Subcommand;
use keri_controller::IdentifierPrefix;

use crate::{
    kel::{handle_kel_query, handle_rotate},
    tel::{self, handle_issue, handle_query, handle_tel_oobi},
    CliError,
};

#[derive(Subcommand)]
pub enum LogCommand {
    /// Manage Key Event Logs (KEL)
    Kel {
        #[command(subcommand)]
        command: KelCommands,
    },
    /// Manage Transaction Event Logs (TEL)
    Tel {
        #[command(subcommand)]
        command: TelCommands,
    },
}

#[derive(Subcommand)]
pub enum KelCommands {
    /// Rotate identifiers keys
    Rotate {
        #[arg(short, long)]
        alias: String,
        #[arg(short = 'c', long)]
        rotation_config: Option<PathBuf>,
    },
    /// Find Key Event Log
    Find {
        /// Alias of the identifier making the request
        #[arg(short, long)]
        alias: String,
        /// The identifier to be searched
        #[arg(short, long)]
        identifier: String,
        /// Optional OOBI of the identifier to search for
        #[arg(short, long)]
        oobi: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum TelCommands {
    /// Init Transaction Event Log for given alias
    Incept {
        #[arg(short, long)]
        alias: String,
    },
    /// Issue credential
    Issue {
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        credential_json: String,
    },
    /// Search Transaction Event Log event
    Query {
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        issuer_id: String,
        #[arg(short, long)]
        registry_id: String,
        #[arg(short, long)]
        said: String,
    },
    /// Returns OOBI of TEL of given alias
    Oobi {
        #[arg(short, long)]
        alias: String,
    },
}

pub async fn process_log_command(command: LogCommand) -> Result<(), CliError> {
    match command {
        LogCommand::Kel { command } => {
            match command {
                KelCommands::Find {
                    alias,
                    identifier,
                    oobi,
                } => {
                    let identifier: IdentifierPrefix = identifier.parse().unwrap();
                    println!("{}", handle_kel_query(&alias, &identifier, oobi).await?);
                }
                KelCommands::Rotate {
                    alias,
                    rotation_config,
                } => {
                    handle_rotate(&alias, rotation_config).await.unwrap();
                }
            };
            Ok(())
        }
        LogCommand::Tel { command } => {
            match command {
                TelCommands::Incept { alias } => {
                    tel::handle_tel_incept(&alias).await?;
                }
                TelCommands::Issue {
                    alias,
                    credential_json,
                } => {
                    handle_issue(&alias, &credential_json).await?;
                }
                TelCommands::Query {
                    alias,
                    issuer_id,
                    registry_id,
                    said,
                } => {
                    handle_query(&alias, &said, &registry_id, &issuer_id).await?;
                }
                TelCommands::Oobi { alias } => {
                    handle_tel_oobi(&alias)?;
                }
            };
            Ok(())
        }
    }
}
