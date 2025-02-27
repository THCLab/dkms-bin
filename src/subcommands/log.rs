use std::path::PathBuf;

use clap::Subcommand;
use keri_controller::IdentifierPrefix;

use crate::{
    kel::{handle_kel_query, handle_rotate},
    tel::{handle_query, handle_tel_oobi},
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
        /// Alias of the identifier to rotate
        #[arg(short, long)]
        alias: String,
        /// Path to the rotation configuration file in YAML format
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
    /// Search Transaction Event Log event
    Query {
        /// Alias of the identifier making the request
        #[arg(short, long)]
        alias: String,
        /// Identifier whose TEL is requested 
        #[arg(short, long)]
        issuer_id: String,
		/// Identifier of the Management TEL
        #[arg(short, long)]
        registry_id: String,
		/// Identifier of the VC TEL
        #[arg(short, long)]
        said: String,
    },
    /// Returns OOBI of TEL of given alias
    Oobi {
        /// Alias of identifier whose TEL OOBI is requested
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
