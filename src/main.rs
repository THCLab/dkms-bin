use std::{fs, path::PathBuf};

use base64::{prelude::BASE64_STANDARD, Engine};
use cesrox::primitives::codes::seed::SeedCode;
use clap::{CommandFactory, Parser, Subcommand};
use config_file::ConfigFileError;
use init::handle_init;
use kel::{handle_kel_query, handle_rotate};
use keri::KeriError;
use keri_controller::{identifier::query::WatcherResponseError, IdentifierPrefix};
use mesagkesto::MesagkestoError;
use resolve::handle_resolve;
use said::SaidError;
use seed::{convert_to_seed, generate_seed};
use sign::handle_sign;
use tabled::{builder::Builder, settings::Style};
use tel::{handle_issue, handle_query, handle_tel_oobi};
use thiserror::Error;
use utils::{handle_info, working_directory, ExtractionError, LoadingError};
use verification_status::VerificationStatus;
use verify::handle_verify;

use crate::said::handle_sad;

mod expand;
mod init;
mod kel;
mod keri;
mod mesagkesto;
mod resolve;
mod said;
mod seed;
mod sign;
mod tel;
mod temporary_id;
mod utils;
mod verification_status;
mod verify;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Init new signer
    Init {
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        keys_file: Option<PathBuf>,
        #[arg(long)]
        witness: Vec<String>,
        #[arg(long)]
        watcher: Vec<String>,
        #[arg(long)]
        witness_threshold: Option<u64>,
    },
    /// Manage Key Event Log
    Kel {
        #[command(subcommand)]
        command: KelCommands,
    },
    /// Manage Transaction Event Log
    Tel {
        #[command(subcommand)]
        command: TelCommands,
    },
    /// Generates messages for communication with Mesagkesto
    Mesagkesto {
        #[command(subcommand)]
        command: MesagkestoCommands,
    },
    /// Manage saved OOBIs
    Oobi {
        #[command(subcommand)]
        command: OobiCommands,
    },
    /// Computes Self Addressing Identifier
    Said {
        #[command(subcommand)]
        command: SaidCommands,
    },
    /// Shows information about identifier of given alias
    Whoami {
        alias: String,
    },
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
    /// Generate Seed string from provided code and secret key encoded in base64.
    /// Code specify algorithm to use. Possible values are:
    ///     `A` for Ed25519 private key,
    ///     `J` for ECDSA secp256k1 private key,
    ///     'K' for Ed448 private key.
    /// If no arguments it generates Ed25519 secret key.
    #[clap(verbatim_doc_comment)]
    Seed {
        #[arg(short, long, requires = "secret_key")]
        code: Option<String>,
        #[arg(short, long, requires = "code")]
        secret_key: Option<String>,
    },
    /// Shows information about working environment
    Info,
    /// Lists all created aliases along with their identifiers
    List,
    /// Transforms CESR data into a human-readable format
    Expand {
        cesr: String,
    },
}

#[derive(Subcommand)]
pub enum MesagkestoCommands {
    Exchange {
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        content: String,
        #[arg(short, long)]
        receiver: String,
    },
    Query {
        #[arg(short, long)]
        alias: String,
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
#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
pub struct KelGettingGroup {
    #[clap(short, long)]
    alias: Option<String>,
    #[clap(short, long)]
    identifier: Option<String>,
}

#[derive(Subcommand)]
pub enum OobiCommands {
    /// Returns saved OOBIs of provided alias
    Get {
        #[arg(short, long)]
        alias: String,
        #[command(subcommand)]
        role: Option<OobiRoles>,
    },
    // Resolves provided oobi and saves it
    Resolve {
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum OobiRoles {
    Witness,
    Watcher,
    Messagebox,
}

#[derive(Subcommand)]
pub enum SaidCommands {
    // Computes the SAID of the provided JSON file and replaces the d field with it
    SAD {
        #[arg(short, long)]
        file: PathBuf,
    },
}

#[derive(Error, Debug)]
pub enum CliError {
    #[error(transparent)]
    ConfigUnparsable(#[from] ConfigFileError),
    #[error("Keys derivation error")]
    KeysDerivationError,
    #[error(transparent)]
    FileError(#[from] std::io::Error),
    #[error("Path error: {0}")]
    PathError(String),
    #[error("Missing 'd' field")]
    MissingDigest,
    #[error(transparent)]
    MesagkestoError(#[from] MesagkestoError),
    #[error("Wrong 'd' field value. {0}")]
    SaidError(#[from] SaidError),
    #[error("Error: {0}")]
    NotReady(String),
    #[error("Unknown identifier: {0}")]
    UnknownIdentifier(String),
    #[error(transparent)]
    KeriError(#[from] KeriError),
    #[error(transparent)]
    LoadingError(#[from] LoadingError),
    #[error("Unparsable identifier: {0}")]
    UnparsableIdentifier(String),
    #[error("The provided string {0} is not valid secret key. {1}. Please verify your input.")]
    SecretKeyError(String, keri_core::prefix::error::Error),
    #[error("Invalid base64: {0}")]
    B64Error(String),
    #[error("Invalid seed code: {0}")]
    SeedError(String),
    #[error("Can't parse provided oobi. {0}")]
    UnparsableOobi(#[from] ExtractionError),
    #[error("{0}")]
    Verification(VerificationStatus),
    #[error("Invalid input. Only valid json can be signed")]
    JsonExpected,
    #[error("{0:?}")]
    KelGetting(Vec<WatcherResponseError>),
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
        Some(Commands::Init {
            alias,
            keys_file,
            witness,
            watcher,
            witness_threshold,
        }) => {
            let witness_threshold = witness_threshold.unwrap_or(1);
            let witnesses_oobi = if witness.is_empty() {
                None
            } else {
                Some(witness)
            };
            let watchers_oobi = if watcher.is_empty() {
                None
            } else {
                Some(watcher)
            };
            handle_init(
                alias,
                keys_file,
                witnesses_oobi,
                watchers_oobi,
                witness_threshold,
            )
            .await?;
        }
        Some(Commands::Kel { command }) => match command {
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
        },
        Some(Commands::Mesagkesto { command }) => match command {
            MesagkestoCommands::Exchange {
                content,
                receiver,
                alias,
            } => {
                println!(
                    "{}",
                    mesagkesto::handle_exchange(&alias, &content, &receiver)?
                );
            }
            MesagkestoCommands::Query { alias } => {
                let qry = mesagkesto::handle_pull(&alias)?;
                println!("{}", qry);
            }
        },
        Some(Commands::Oobi { command }) => match command {
            OobiCommands::Get { role, alias } => match resolve::handle_oobi(&alias, &role) {
                Ok(lcs) => println!("{}", serde_json::to_string(&lcs).unwrap()),
                Err(e) => println!("{}", e),
            },
            OobiCommands::Resolve { alias, file } => handle_resolve(&alias, file).await?,
        },
        Some(Commands::Tel { command }) => match command {
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
        },
        Some(Commands::Said { command }) => match command {
            SaidCommands::SAD { file } => {
                let sad = handle_sad(file).await?;
                println!("{}", sad);
            }
        },
        Some(Commands::Whoami { alias }) => {
            handle_info(&alias)?;
        }
        Some(Commands::Sign { alias, data }) => {
            println!("{}", handle_sign(alias, &data)?);
        }
        Some(Commands::Seed { code, secret_key }) => {
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
        Some(Commands::Verify {
            alias,
            oobi,
            message,
        }) => {
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
        Some(Commands::Info) => {
            let working_directory = working_directory()?;
            println!("Working directory: {}", working_directory.to_str().unwrap());
        }
        Some(Commands::List) => {
            let working_directory = working_directory()?;
            let mut builder = Builder::new();
            builder.push_record(["ALIAS", "IDENTIFIER"]);
            if let Ok(contents) = fs::read_dir(&working_directory) {
                for entry in contents {
                    let entry = entry?;
                    let metadata = entry.metadata()?;

                    // Check if the entry is a directory
                    if metadata.is_dir() {
                        if let Some(alias) = entry.file_name().to_str() {
                            let mut id_path = working_directory.clone();
                            id_path.push(alias);
                            id_path.push("id");
                            let identifier = fs::read_to_string(id_path)
                                .map_err(|_e| LoadingError::UnknownIdentifier(alias.to_string()))?;
                            builder.push_record([alias.to_string(), identifier.to_string()]);
                        }
                    }
                }
            };
            let table = builder.build().with(Style::blank()).to_string();
            println!("{}", table);
        }
        Some(Commands::Expand { cesr }) => expand::expand(&cesr),
        None => {
            // If no subcommand is provided, display the help message
            Cli::command().print_help().unwrap();
        }
    };
    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use std::{path::PathBuf, sync::Arc};

//     use acdc::attributes::InlineAttributes;
//     use anyhow::Result;
//     use controller::{
//         config::ControllerConfig, BasicPrefix, Controller, CryptoBox, EndRole, IdentifierPrefix,
//         KeyManager, LocationScheme, SelfSigningPrefix,
//     };
//     use keri::actor::prelude::SelfAddressingIdentifier;
//     use tempfile::Builder;

//     use crate::keri::{query_mailbox, setup_identifier};

//     #[tokio::test]
//     pub async fn test_generating() -> Result<()> {
//         // Create temporary db file.
//         let signing_id_path = Builder::new()
//             .prefix("test-db")
//             .tempdir()
//             .unwrap()
//             .path()
//             .to_path_buf();

//         // Create temporary db file.
//         let verifying_id_path = Builder::new()
//             .prefix("test-db")
//             .tempdir()
//             .unwrap()
//             .path()
//             .to_path_buf();

//         let signing_controller = Arc::new(Controller::new(ControllerConfig {
//             db_path: signing_id_path,
//             ..Default::default()
//         })?);
//         let verifying_controller = Arc::new(Controller::new(ControllerConfig {
//             db_path: verifying_id_path,
//             ..Default::default()
//         })?);
//         let witness_oobi: LocationScheme = serde_json::from_str(r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}"#).unwrap();
//         let witness_oobi: LocationScheme = serde_json::from_str(r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}"#).unwrap();
//         let witness_id: BasicPrefix = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC".parse()?;

//         let messagebox_oobi: LocationScheme = serde_json::from_str(r#"{"eid":"BFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-","scheme":"http","url":"http://messagebox.sandbox.argo.colossi.network/"}"#).unwrap();
//         let messagebox_oobi: LocationScheme = serde_json::from_str(r#"{"eid":"BFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-","scheme":"http","url":"http://localhost:8080/"}"#).unwrap();
//         let messagebox_id = "BFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-";

//         let watcher_oobi: LocationScheme = serde_json::from_str(r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}"#).unwrap();
//         let watcher_oobi: LocationScheme = serde_json::from_str(r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3235/"}"#).unwrap();

//         let signing_key_manager = Arc::new(CryptoBox::new().unwrap());
//         let dir_path_str = "./generated/identifier1";
//         let out_path = PathBuf::from(dir_path_str);
//         let signing_identifier = setup_identifier(
//             signing_controller.clone(),
//             signing_key_manager.clone(),
//             witness_oobi.clone(),
//             Some(messagebox_oobi),
//             None,
//         )
//         .await?;

//         let verifying_key_manager = Arc::new(CryptoBox::new().unwrap());
//         let out_path2 = PathBuf::from("./generated/identifier2");
//         let verifying_identifier = setup_identifier(
//             verifying_controller,
//             verifying_key_manager.clone(),
//             witness_oobi.clone(),
//             None,
//             Some(watcher_oobi),
//         )
//         .await?;

//         // Issuing ACDC
//         let attr: InlineAttributes = r#"{"number":"123456789"}"#.parse()?;
//         let registry_id = signing_identifier.registry_id.clone().unwrap().to_string();
//         let acdc = acdc::Attestation::new_public_untargeted(
//             &signing_identifier.id.to_string(),
//             registry_id,
//             "schema".to_string(),
//             attr,
//         );

//         // let path = "./generated/acdc";
//         // let mut file = File::create(path)?;
//         // file.write_all(&said::version::Encode::encode(&acdc)?)?;

//         let cred_said: SelfAddressingIdentifier =
//             acdc.clone().digest.unwrap().to_string().parse().unwrap();

//         let (vc_id, ixn) = signing_identifier.issue(cred_said.clone())?;
//         let signature = SelfSigningPrefix::new(
//             cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
//             signing_key_manager.sign(&ixn)?,
//         );
//         assert_eq!(vc_id.to_string(), cred_said.to_string());
//         signing_identifier.finalize_event(&ixn, signature).await?;

//         let said = match vc_id {
//             IdentifierPrefix::SelfAddressing(said) => said,
//             _ => {
//                 unreachable!()
//             }
//         };
//         signing_identifier.notify_witnesses().await?;

//         let qry = query_mailbox(
//             &signing_identifier,
//             signing_key_manager.clone(),
//             &witness_id,
//         )
//         .await?;

//         let mut path = out_path;
//         // path.push("kel");
//         // let mut file = File::create(path)?;
//         // file.write_all(signing_identifier.get_kel()?.as_bytes())?;
//         signing_identifier.notify_backers().await?;

//         println!("\nkel: {:?}", signing_identifier.get_kel());

//         // Save tel to file
//         let tel = signing_controller.tel.get_tel(&said)?;
//         let encoded = tel
//             .iter()
//             .map(|tel| tel.serialize().unwrap())
//             .flatten()
//             .collect::<Vec<_>>();
//         // let path = "./generated/tel";
//         // let mut file = File::create(path)?;
//         // file.write_all(&encoded)?;

//         // fs::create_dir_all("./generated/messagebox").unwrap();
//         // Signer's oobi
//         let end_role_oobi = EndRole {
//             eid: IdentifierPrefix::Basic(witness_id.clone()),
//             cid: signing_identifier.id.clone(),
//             role: keri::oobi::Role::Witness,
//         };
//         let oobi0 = serde_json::to_string(&witness_oobi).unwrap();
//         let oobi1 = serde_json::to_string(&end_role_oobi).unwrap();
//         // let path = "./generated/identifier1/oobi0";
//         // let mut file = File::create(path)?;
//         // file.write_all(&oobi0.as_bytes())?;

//         // let path = "./generated/identifier1/oobi1";
//         // let mut file = File::create(path)?;
//         // file.write_all(&oobi1.as_bytes())?;

//         let exn = messagebox::forward_message(
//             verifying_identifier.id.to_string(),
//             String::from_utf8(said::version::Encode::encode(&acdc)?).unwrap(),
//         );
//         let signature = SelfSigningPrefix::new(
//             cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
//             signing_key_manager.sign(&exn.to_string().as_bytes())?,
//         );

//         let signed_exn = signing_identifier.sign_to_cesr(&exn.to_string(), signature, 0)?;

//         println!("\nExchange: {}", signed_exn);

//         // let path = "./generated/messagebox/exn";
//         // let mut file = File::create(path)?;
//         // file.write_all(&signed_exn.as_bytes())?;

//         // Verifier's oobi
//         let end_role_oobi = EndRole {
//             eid: IdentifierPrefix::Basic(witness_id),
//             cid: verifying_identifier.id.clone(),
//             role: keri::oobi::Role::Witness,
//         };
//         let oobi00 = serde_json::to_string(&witness_oobi).unwrap();
//         let oobi11 = serde_json::to_string(&end_role_oobi).unwrap();
//         // let path = "./generated/identifier2/oobi0";
//         // let mut file = File::create(path)?;
//         // file.write_all(&oobi00.as_bytes())?;

//         // let path = "./generated/identifier2/oobi1";
//         // let mut file = File::create(path)?;
//         // file.write_all(&oobi11.as_bytes())?;

//         let qry = messagebox::query_by_sn(verifying_identifier.id.to_string(), 0);
//         let signature = SelfSigningPrefix::new(
//             cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
//             verifying_key_manager.sign(&qry.to_string().as_bytes())?,
//         );
//         let signed_qry = verifying_identifier.sign_to_cesr(&qry.to_string(), signature, 0)?;

//         println!("\nQuery: {}", signed_qry);

//         // let path = "./generated/messagebox/qry";
//         // let mut file = File::create(path)?;
//         // file.write_all(&signed_qry.as_bytes())?;

//         let acdc_d = acdc.digest.clone().unwrap().to_string().parse().unwrap();
//         let acdc_sai: SelfAddressingIdentifier = acdc.digest.unwrap().to_string().parse().unwrap();
//         let acdc_ri: IdentifierPrefix = acdc.registry_identifier.parse().unwrap();
//         let qry = verifying_identifier.query_tel(acdc_ri, acdc_d)?;
//         let signature = SelfSigningPrefix::new(
//             cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
//             verifying_key_manager.sign(&qry.encode().unwrap())?,
//         );
//         let signed_qry = verifying_identifier.sign_to_cesr(
//             &String::from_utf8(qry.encode().unwrap()).unwrap(),
//             signature.clone(),
//             0,
//         )?;
//         let path = "./generated/messagebox/tel_qry";
//         // let mut file = File::create(path)?;
//         // file.write_all(&signed_qry.as_bytes())?;

//         // verifying_identifier.source.resolve_oobi(serde_json::from_str(&oobi0).unwrap()).await?;
//         verifying_identifier
//             .source
//             .resolve_oobi(serde_json::from_str(&oobi1).unwrap())
//             .await?;
//         verifying_identifier
//             .finalize_tel_query(&signing_identifier.id, qry, signature)
//             .await?;

//         let tel = verifying_identifier.source.tel.get_tel(&cred_said);
//         let state = verifying_identifier.source.tel.get_vc_state(&cred_said);
//         println!("state: {:?}", state);

//         Ok(())
//     }
// }
