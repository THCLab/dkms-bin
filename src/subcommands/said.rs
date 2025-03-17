use std::io::{self, IsTerminal, Read};

use clap::Subcommand;
use said::derivation::{HashFunction, HashFunctionCode};

use crate::{said::handle_sad, CliError};

#[derive(Subcommand)]
pub enum SaidCommands {
    /// Computes the SAID of the provided JSON file and replaces the d field with it
    Sad {
        #[arg(short, long)]
        json: String,
    },
    /// Computes the SAID of the provided data
    Digesting {
        /// Input data
        #[arg(short, long)]
        data: Option<String>,
    },
}

pub async fn process_said_command(command: SaidCommands) -> Result<(), CliError> {
    match command {
        SaidCommands::Sad { json } => {
            let sad = handle_sad(&json)?;
            println!("{}", sad);
        }
        SaidCommands::Digesting { data } => {
            let input = match data {
                Some(text) => text.as_bytes().to_vec(), // Direct input
                None => {
                    if io::stdin().is_terminal() {
                        eprintln!(
                            "Error: No input provided. Provide an argument or pipe data via stdin."
                        );
                        std::process::exit(1);
                    }

                    let mut buffer = Vec::new();
                    match io::stdin().read_to_end(&mut buffer) {
                        Ok(0) => {
                            std::process::exit(1);
                        }
                        Ok(_) => buffer,
                        Err(_) => return Err(CliError::OptionOrStdinError("-d".to_string())),
                    }
                }
            };

            let code = HashFunctionCode::Blake3_256;
            let said = HashFunction::from(code).derive(&input);
            println!("{}", said.to_string())
        }
    };
    Ok(())
}
