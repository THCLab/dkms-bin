use clap::{CommandFactory, Parser, Subcommand};
use error::CliError;
use subcommands::{
    data::{process_data_command, DataCommand},
    identifier::{process_identifier_command, IdentifierCommand},
    key::{process_key_command, KeyCommands},
    log::{process_log_command, LogCommand},
    mesagkesto::{process_mesagkesto_command, MesagkestoCommands},
    said::{process_said_command, SaidCommands},
};
use utils::working_directory;

mod error;
mod expand;
mod init;
mod kel;
mod keri;
mod mesagkesto;
mod resolve;
mod said;
mod seed;
mod sign;
mod subcommands;
mod tel;
mod temporary_id;
mod utils;
mod verification_status;
mod verify;

#[derive(Parser)]
#[command(author, version, about, long_about = None,)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage identifiers
    Identifier {
        #[command(subcommand)]
        command: IdentifierCommand,
    },
    /// Manage logs
    Log {
        #[command(subcommand)]
        command: LogCommand,
    },
    /// Sign, verify
    Data {
        #[command(subcommand)]
        command: DataCommand,
    },

    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },

    /// Generates messages for communication with Mesagkesto
    Mesagkesto {
        #[command(subcommand)]
        command: MesagkestoCommands,
    },
    /// Computes Self Addressing Identifier (SAID)
    Said {
        #[command(subcommand)]
        command: SaidCommands,
    },

    /// Shows information about working environment
    Info,
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();
    if let Err(e) = process_command(cli.command).await {
        println!("{}", e);
        std::process::exit(1);
    };

    Ok(())
}

async fn process_command(command: Option<Commands>) -> Result<(), CliError> {
    match command {
        Some(Commands::Identifier { command }) => {
            process_identifier_command(command).await?;
        }
        Some(Commands::Log { command }) => {
            process_log_command(command).await?;
        }
        Some(Commands::Data { command }) => {
            process_data_command(command).await?;
        }
        Some(Commands::Key { command }) => {
            process_key_command(command).await?;
        }

        Some(Commands::Mesagkesto { command }) => process_mesagkesto_command(command).await?,
        Some(Commands::Said { command }) => process_said_command(command).await?,
        Some(Commands::Info) => {
            let working_directory = working_directory()?;
            println!("Working directory: {}", working_directory.to_str().unwrap());
        }
        None => {
            // If no subcommand is provided, display the help message
            Cli::command().print_help().unwrap();
        }
    };
    Ok(())
}
