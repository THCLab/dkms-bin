use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
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
mod export;
mod help;
mod init;
mod inspect;
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
mod debug;

#[derive(Parser)]
#[command(author, version, about, long_about = None, help_template = help::HELP_TEMPLATE)]
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
    let help_text = help::generate_help_text();

    let command = Cli::command()
        .help_template(help::HELP_TEMPLATE.replace("{commands}", help_text))
        .get_matches();

    let cli: Cli = FromArgMatches::from_arg_matches(&command).unwrap();
    match cli.command {
        Some(command) => {
            if let Err(e) = process_command(command).await {
                println!("{}", e);
                std::process::exit(1);
            };
        }
        None => {
            // If no subcommand is provided, display the help message
            Cli::command()
                .help_template(help::HELP_TEMPLATE.replace("{commands}", help_text))
                .print_help()
                .unwrap();
        }
    }

    Ok(())
}

async fn process_command(command: Commands) -> Result<(), CliError> {
    match command {
        Commands::Identifier { command } => {
            process_identifier_command(command).await?;
        }
        Commands::Log { command } => {
            process_log_command(command).await?;
        }
        Commands::Data { command } => {
            process_data_command(command).await?;
        }
        Commands::Key { command } => {
            process_key_command(command).await?;
        }

        Commands::Mesagkesto { command } => process_mesagkesto_command(command).await?,
        Commands::Said { command } => process_said_command(command).await?,
        Commands::Info => {
            let working_directory = working_directory()?;
            println!("Working directory: {}", working_directory.to_str().unwrap());
        }
    };
    Ok(())
}
