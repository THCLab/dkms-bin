use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use dauthz_core::challenge::CeremonyPurpose;
use dauthz_core::sp_auth::{parse_deep_link, PresentedCredential};

use crate::{
    auth::{
        describe, handle_link, handle_verify_introduction, prepare_response, send_response,
        AuthError, LinkOptions, RespondOptions,
    },
    CliError,
};

#[derive(Clone, Copy, ValueEnum)]
pub enum Purpose {
    Identification,
    Registration,
}

impl From<Purpose> for CeremonyPurpose {
    fn from(p: Purpose) -> Self {
        match p {
            Purpose::Identification => CeremonyPurpose::Identification,
            Purpose::Registration => CeremonyPurpose::Registration,
        }
    }
}

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Answer a cyfron://auth sign-in link with a dkms identifier
    Respond {
        /// Alias of the identifier that signs in
        #[arg(short, long)]
        alias: String,
        /// The cyfron://auth?... link (copied from the service's login page)
        link: String,
        /// Attribute to disclose, as name=value; only names the service requested
        #[arg(long = "attr", value_parser = parse_attr)]
        attrs: Vec<(String, String)>,
        /// Credential proof file ({acdc, issuer_cesr, disclosed}) to present
        #[arg(long)]
        present: Option<PathBuf>,
        /// Decline the request instead of signing
        #[arg(long)]
        deny: bool,
        /// Reason sent with --deny
        #[arg(long, requires = "deny")]
        reason: Option<String>,
        /// Do not ask for confirmation
        #[arg(short, long)]
        yes: bool,
        /// Print the callback body instead of sending it
        #[arg(long)]
        dry_run: bool,
    },
    /// Build a cyfron://auth sign-in link naming an identifier as the service
    Link {
        /// Alias of the service identifier
        #[arg(short, long)]
        alias: String,
        /// URL the wallet POSTs its answer to
        #[arg(long)]
        callback_url: String,
        /// Service name shown to the user
        #[arg(long)]
        sp_name: String,
        /// Service origin shown to the user
        #[arg(long)]
        sp_origin: Option<String>,
        /// Service logo URL
        #[arg(long)]
        sp_logo: Option<String>,
        #[arg(long, value_enum, default_value = "identification")]
        purpose: Purpose,
        /// Comma-separated attribute names to request (registration only)
        #[arg(long)]
        requested_attrs: Option<String>,
        /// Invite token
        #[arg(long)]
        invite: Option<String>,
        /// Terms of service URI (sent only together with --tos-hash)
        #[arg(long)]
        tos_uri: Option<String>,
        /// Digest of the terms of service
        #[arg(long)]
        tos_hash: Option<String>,
        /// Required credentials, as <schema_said>[@<issuer_aid>][,...]
        #[arg(long)]
        requested_credentials: Option<String>,
        /// Nonce to embed; random when omitted
        #[arg(long)]
        nonce: Option<String>,
        /// Deep-link scheme
        #[arg(long, default_value = "cyfron")]
        scheme: String,
    },
    /// Verify a signed cyfron-sp-auth envelope and print a JSON verdict
    Verify {
        /// Alias of the verifying (service) identifier
        #[arg(short, long)]
        alias: String,
        /// AID the response claims to come from
        #[arg(long)]
        aid: String,
        /// OOBI of the signing identifier (the callback's entity_oobi)
        #[arg(short, long)]
        oobi: Vec<String>,
        /// Nonce of the issued challenge; also checks the envelope answers it
        #[arg(long)]
        nonce: Option<String>,
        /// Signed envelope (the callback's signed_challenge); read from stdin when omitted
        #[arg(short, long)]
        message: Option<String>,
    },
}

fn parse_attr(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.trim().to_string(), v.to_string()))
        .filter(|(k, _)| !k.is_empty())
        .ok_or_else(|| format!("expected name=value, got '{s}'"))
}

fn confirm(question: &str) -> Result<bool, CliError> {
    if !io::stdin().is_terminal() {
        return Err(AuthError::Refused(
            "no terminal to confirm on; pass --yes to answer without asking".into(),
        )
        .into());
    }
    eprint!("{question} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

pub async fn process_auth_command(command: AuthCommand) -> Result<(), CliError> {
    match command {
        AuthCommand::Respond {
            alias,
            link,
            attrs,
            present,
            deny,
            reason,
            yes,
            dry_run,
        } => {
            let link = parse_deep_link(&link).map_err(|e| AuthError::Link(e.to_string()))?;
            eprint!("{}", describe(&link));
            let presented = match present {
                Some(path) => Some(
                    PresentedCredential::parse_proof(&fs::read_to_string(path)?)
                        .map_err(|e| AuthError::Refused(e.to_string()))?,
                ),
                None => None,
            };
            let deny = if deny {
                Some(reason)
            } else if yes || dry_run || confirm("Sign in?")? {
                None
            } else {
                Some(Some("declined by user".to_string()))
            };
            let opts = RespondOptions {
                attrs: attrs.into_iter().collect::<BTreeMap<_, _>>(),
                presented,
                deny,
                dry_run,
            };
            let body = prepare_response(&alias, &link, &opts).await?;
            if opts.dry_run {
                println!("{}", serde_json::to_string_pretty(&body).unwrap());
            } else {
                println!("{}", send_response(&link, &body).await?);
            }
        }
        AuthCommand::Link {
            alias,
            callback_url,
            sp_name,
            sp_origin,
            sp_logo,
            purpose,
            requested_attrs,
            invite,
            tos_uri,
            tos_hash,
            requested_credentials,
            nonce,
            scheme,
        } => {
            let minted = handle_link(
                &alias,
                LinkOptions {
                    scheme,
                    nonce,
                    sp_name,
                    sp_origin,
                    sp_logo,
                    purpose: purpose.into(),
                    requested_attrs,
                    callback_url,
                    invite,
                    tos_uri,
                    tos_hash,
                    requested_credentials,
                },
            )?;
            println!("{}", serde_json::to_string(&minted).unwrap());
        }
        AuthCommand::Verify {
            alias,
            aid,
            oobi,
            nonce,
            message,
        } => {
            let signed = match message {
                Some(m) => m,
                None => {
                    if io::stdin().is_terminal() {
                        return Err(CliError::OptionOrStdinError("-m".to_string()));
                    }
                    let mut buffer = String::new();
                    io::stdin().read_to_string(&mut buffer)?;
                    buffer
                }
            };
            let verdict =
                handle_verify_introduction(&alias, &aid, &oobi, &signed, nonce.as_deref()).await?;
            println!("{}", serde_json::to_string(&verdict).unwrap());
        }
    }
    Ok(())
}
