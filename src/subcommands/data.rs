use clap::Subcommand;

use crate::{
    expand, sign::handle_sign, verification_status::VerificationStatus, verify::handle_verify,
    CliError,
};

#[derive(Subcommand)]
pub enum DataCommand {
    /// Sign provided data and returns it in CESR format
    Sign {
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        data: String,
    },
    /// Verifies provided CESR stream
    Verify {
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        oobi: Vec<String>,
        #[arg(short, long)]
        message: String,
    },
    /// Presents CESR data in a human-readable format
    Expand {
        /// A CESR string, such as one produced by the issue or sign command
        cesr: String,
    },
}

pub async fn process_data_command(command: DataCommand) -> Result<(), CliError> {
    match command {
        DataCommand::Sign { alias, data } => {
            println!("{}", handle_sign(alias, &data)?);
        }
        DataCommand::Verify {
            alias,
            oobi,
            message,
        } => {
            let status = match handle_verify(
                &alias,
                &oobi.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
                message,
            )
            .await
            {
                Ok(result) => VerificationStatus::from(result),
                Err(e) => VerificationStatus::from(e),
            };
            match &status {
                VerificationStatus::Ok { description: _ } => println!("{}", &status),
                VerificationStatus::Error { description: _ }
                | VerificationStatus::Invalid { description: _ } => {
                    return Err(CliError::Verification(status))
                }
            }
        }
        DataCommand::Expand { cesr } => expand::expand(&cesr),
    }
    Ok(())
}
