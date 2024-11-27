use base64::{prelude::BASE64_STANDARD, Engine};
use cesrox::primitives::codes::seed::SeedCode;
use clap::Subcommand;

use crate::{
    seed::{convert_to_seed, generate_seed},
    CliError,
};

#[derive(Subcommand)]
pub enum KeyCommands {
    /// Generate Seed string from provided code and secret key encoded in base64.
    /// If no arguments it generates Ed25519 secret key.
    Seed {
        /// Code specify algorithm to use. Possible values are:
        ///     `A` for Ed25519 private key,
        ///     `J` for ECDSA secp256k1 private key,
        ///     'K' for Ed448 private key.
        #[arg(short, long, requires = "secret_key")]
        code: Option<String>,
        #[arg(short, long, requires = "code")]
        secret_key: Option<String>,
    },
}

pub async fn process_key_command(command: KeyCommands) -> Result<(), CliError> {
    match command {
        KeyCommands::Seed { code, secret_key } => {
            // seed is in b64
            let seed = match (code, secret_key) {
                (None, None) => Ok(generate_seed()),
                (None, Some(_sk)) => Ok("Code needs to be provided".to_string()),
                (Some(_code), None) => Ok("Key needs to be provided".to_string()),
                (Some(code), Some(sk_str)) => {
                    let code = code
                        .parse::<SeedCode>()
                        .map_err(|_e| CliError::SeedError(code.to_string()));
                    let sk = BASE64_STANDARD
                        .decode(&sk_str)
                        .map_err(|_| CliError::B64Error(sk_str.to_string()));
                    match (code, sk) {
                        (Ok(code), Ok(sk)) => convert_to_seed(code, sk)
                            .map_err(|e| CliError::SecretKeyError(sk_str, e)),
                        (Ok(_), Err(e)) | (Err(e), Ok(_)) | (Err(e), Err(_)) => Err(e),
                    }
                }
            };
            match seed {
                Ok(seed) => println!("{}", seed),
                Err(e) => println!("{}", e),
            }
        }
    };
    Ok(())
}
