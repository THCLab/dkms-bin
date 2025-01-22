use clap::Subcommand;
use said::SelfAddressingIdentifier;
use std::io::{self, IsTerminal, Read};

use crate::{
    inspect,
    sign::handle_sign,
    tel::{extract_said, handle_issue, handle_revoke},
    verification_status::VerificationStatus,
    verify::{handle_verify, VerifyHandleError},
    CliError,
};

#[derive(Subcommand)]
pub enum DataCommand {
    /// Sign provided data and returns it in CESR format
    Sign {
        #[arg(short, long)]
        alias: String,
        /// JSON-based data to be signed
        #[arg(short, long)]
        message: String,
    },
    /// Verifies provided CESR stream
    Verify {
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        oobi: Vec<String>,
        /// JSON-based data with CESR attachments to be verified
        #[arg(short, long)]
        message: Option<String>,
    },
    /// Presents CESR data in a human-readable format
    Inspect {
        /// JSON-based data with CESR attachments to be transformed into a readable format
        #[arg(short, long)]
        message: Option<String>,
    },
    /// Issue credential
    Issue {
        #[arg(short, long)]
        alias: String,
        /// ACDC credential payload in JSON format to be processed
        #[arg(short, long)]
        message: String,
    },
    /// Revoke credential
    Revoke {
        #[arg(short, long)]
        alias: String,
        /// ACDC credential payload in JSON format
        #[arg(short, long)]
        credential: Option<String>,
        /// ACDC SAID
        #[arg(short, long)]
        said: Option<SelfAddressingIdentifier>,
    },
}

pub async fn process_data_command(command: DataCommand) -> Result<(), CliError> {
    match command {
        DataCommand::Sign {
            alias,
            message: data,
        } => {
            println!("{}", handle_sign(alias, &data)?);
        }
        DataCommand::Verify {
            alias,
            oobi,
            message,
        } => {
            let status = match message {
                Some(message) => {
                    println!("{}", message);
                    match handle_verify(
                        &alias,
                        &oobi.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
                        message,
                    )
                    .await
                    {
                        Ok(result) => VerificationStatus::from(result),
                        Err(VerifyHandleError::NoWatchersConfigured(id)) => {
                            return Err(CliError::NoWatchers(id))
                        }
                        Err(e) => VerificationStatus::from(e),
                    }
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
                        CliError::Verification(VerificationStatus::Error {
                            description: format!("Failed to read from stdin: {}", e),
                        })
                    })?;

                    match handle_verify(
                        &alias,
                        &oobi.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
                        buffer,
                    )
                    .await
                    {
                        Ok(result) => VerificationStatus::from(result),
                        Err(VerifyHandleError::NoWatchersConfigured(id)) => {
                            return Err(CliError::NoWatchers(id))
                        }
                        Err(e) => VerificationStatus::from(e),
                    }
                }
            };
            match &status {
                VerificationStatus::Ok { description: _ } => println!("{}", &status),
                VerificationStatus::Error { description: _ }
                | VerificationStatus::Invalid { description: _ } => {
                    return Err(CliError::Verification(status))
                }
            }
        }
        DataCommand::Inspect { message } => match message {
            Some(message) => inspect::inspect(&message),
            None => {
                if io::stdin().is_terminal() {
                    return Err(CliError::OptionOrStdinError("-m".to_string()));
                }

                let mut buffer = String::new();
                io::stdin().read_to_string(&mut buffer).map_err(|e| {
                    CliError::Verification(VerificationStatus::Error {
                        description: format!("Failed to read from stdin: {}", e),
                    })
                })?;
                inspect::inspect(&buffer)
            }
        },
        DataCommand::Issue {
            alias,
            message: credential_json,
        } => handle_issue(&alias, &credential_json).await?,
        DataCommand::Revoke {
            alias,
            credential: credential_json,
            said,
        } => match (credential_json, said) {
            (None, None) => println!("Credential or its SAID in expected"),
            (None, Some(said)) => handle_revoke(&alias, &said).await?,
            (Some(cred), None) => {
                let said = extract_said(&cred)?;
                handle_revoke(&alias, &said).await?
            }
            (Some(_), Some(_)) => println!("Only one of credential or its SAID is expected"),
        },
    }
    Ok(())
}
