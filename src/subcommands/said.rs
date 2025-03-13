use std::{
    fs,
    io::{self, IsTerminal, Read},
    path::Path,
};

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
        /// Input data: filepath or direct text
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
                Some(ref path_or_text) if Path::new(path_or_text).extension().is_some() => {
                    fs::read_to_string(path_or_text).map_err(CliError::FileError)?
                }
                Some(text) => text, // Direct input
                None => {
                    if io::stdin().is_terminal() {
                        eprintln!(
                            "Error: No input provided. Provide an argument or pipe data via stdin."
                        );
                        std::process::exit(1);
                    }

                    let mut buffer = String::new();
                    io::stdin()
                        .read_to_string(&mut buffer)
                        .map_err(|_e| CliError::OptionOrStdinError("-d".to_string()))?;
                    buffer
                }
            };

            let code = HashFunctionCode::Blake3_256;
            let said = HashFunction::from(code).derive(input.as_bytes());
            println!("{}", said.to_string())
        }
    };
    Ok(())
}
