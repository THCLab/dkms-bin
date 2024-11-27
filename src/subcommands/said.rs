use clap::Subcommand;

use crate::{said::handle_sad, CliError};

#[derive(Subcommand)]
pub enum SaidCommands {
    /// Computes the SAID of the provided JSON file and replaces the d field with it
    SAD {
        #[arg(short, long)]
        json: String,
    },
}

pub async fn process_said_command(command: SaidCommands) -> Result<(), CliError> {
    match command {
        SaidCommands::SAD { json } => {
            let sad = handle_sad(&json)?;
            println!("{}", sad);
        }
    };
    Ok(())
}
