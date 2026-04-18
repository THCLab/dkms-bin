use clap::Subcommand;
use std::sync::Arc;
use url::Url;

use keri_sdk::{Identifier, IdentifierPrefix, Signer};

use crate::{
    init::kel_database_path,
    multisig::pull_mailbox,
    resolve::find_locations,
    subcommands::identifier::find_oobis_for_urls,
    utils::{
        load, load_identifier, load_signer, save_identifier, save_next_seed, save_seed,
        working_directory, Requests,
    },
};

#[derive(Subcommand)]
pub enum DelegationCommand {
    /// Request delegation from a delegator (delegatee side, step 1)
    Request {
        /// Alias for the new delegated identifier
        #[arg(short, long)]
        alias: String,
        /// Delegator's identifier prefix
        #[arg(short, long)]
        delegator: IdentifierPrefix,
        /// Witness URL(s) for the delegated identifier
        #[arg(long)]
        witness_url: Vec<Url>,
        /// Witness signing threshold
        #[arg(long, default_value = "1")]
        witness_threshold: u64,
        /// Watcher URL(s) to configure after delegation completes
        #[arg(long)]
        watcher_url: Vec<Url>,
    },
    /// List pending delegation requests (delegator side)
    Pending {
        /// Alias of the delegator identifier
        #[arg(short, long)]
        alias: String,
        /// Poll the mailbox for new requests
        #[arg(long)]
        pull: bool,
        /// Seconds to poll (omit for indefinite)
        #[arg(long, requires = "pull")]
        time: Option<u32>,
    },
    /// Approve a pending delegation request (delegator side)
    Approve {
        /// Alias of the delegator identifier
        #[arg(short, long)]
        alias: String,
        /// Index of the request in the pending list
        #[arg(short, long)]
        index: usize,
    },
    /// Complete delegation after delegator approval (delegatee side, step 2)
    Complete {
        /// Alias of the delegated identifier
        #[arg(short, long)]
        alias: String,
    },
    /// Show delegation info for an identifier
    Info {
        /// Alias of the delegated identifier
        #[arg(short, long)]
        alias: String,
    },
}

pub async fn process_delegation_command(cmd: DelegationCommand) {
    let result = match cmd {
        DelegationCommand::Request {
            alias,
            delegator,
            witness_url,
            witness_threshold,
            watcher_url,
        } => {
            handle_request(alias, delegator, witness_url, witness_threshold, watcher_url).await
        }
        DelegationCommand::Pending { alias, pull, time } => {
            handle_pending(&alias, pull, time).await;
            Ok(())
        }
        DelegationCommand::Approve { alias, index } => handle_approve(&alias, index).await,
        DelegationCommand::Complete { alias } => handle_complete(&alias).await,
        DelegationCommand::Info { alias } => {
            handle_info(&alias);
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn handle_request(
    alias: String,
    delegator: IdentifierPrefix,
    witness_urls: Vec<Url>,
    witness_threshold: u64,
    watcher_urls: Vec<Url>,
) -> anyhow::Result<()> {
    use crate::seed::generate_ed25519_seeds;
    use keri_sdk::types::DelegationConfig;

    let witnesses_oobis = find_oobis_for_urls(witness_urls).await?;
    let watchers_oobis = find_oobis_for_urls(watcher_urls).await?;

    let config = DelegationConfig {
        delegator: delegator.clone(),
        witnesses: witnesses_oobis,
        witness_threshold,
        watchers: watchers_oobis,
    };

    let (current_seed, next_seed) = generate_ed25519_seeds();
    let db_path = kel_database_path(&alias)?;

    let signer = Arc::new(Signer::new_with_seed(&current_seed)?);

    let (next_pub_key, _) = next_seed.derive_key_pair()?;
    let next_pk = keri_sdk::BasicPrefix::Ed25519NT(next_pub_key);

    let (temp_id, delegated_prefix) =
        keri_sdk::operations::request_delegation(db_path, signer, next_pk, config).await?;

    // Persist everything.
    let mut dir = working_directory()?;
    dir.push(&alias);
    std::fs::create_dir_all(&dir)?;

    save_seed(&current_seed, &dir.join("priv_key"))?;
    save_next_seed(&next_seed, &dir.join("next_priv_key"))?;
    save_identifier(temp_id.id(), &dir.join("id"))?;
    save_identifier(&delegated_prefix, &dir.join("delegated_id"))?;
    save_identifier(&delegator, &dir.join("delegator_id"))?;

    println!("Delegation request sent to delegator {}", delegator);
    println!("Delegated identifier prefix: {}", delegated_prefix);
    println!(
        "Alias '{}' created. Run `dkms delegation complete -a {}` after the delegator approves.",
        alias, alias
    );

    Ok(())
}

async fn handle_pending(alias: &str, pull: bool, time: Option<u32>) {
    let req = Requests::new(alias).unwrap();

    let all_req = req.show().unwrap();
    if !all_req.is_empty() {
        println!("Pending delegation requests:\n  {}", all_req.join("\n  "));
    } else if !pull {
        println!("No pending requests. Use --pull to check the mailbox.");
    }

    if pull {
        let mut id = load(alias).unwrap();
        let signer = Arc::new(load_signer(alias).unwrap());
        let mut requests = Requests::new(alias).unwrap();

        if let Some(secs) = time {
            for _ in 0..secs {
                poll_delegation_mailbox(&mut id, signer.clone(), &mut requests).await;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        } else {
            loop {
                poll_delegation_mailbox(&mut id, signer.clone(), &mut requests).await;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

async fn poll_delegation_mailbox(id: &mut Identifier, signer: Arc<Signer>, requests: &mut Requests) {
    let pending = pull_mailbox(id, signer).await.unwrap();
    for request in pending {
        if request.is_delegation() {
            let action = request.into_action_required();
            match requests.add(action) {
                Ok(Some(_)) => {
                    println!("New delegation request received:");
                    let all = requests.show().unwrap();
                    if let Some(line) = all.last() {
                        println!("  {}", line);
                    }
                }
                Ok(None) => {}
                Err(e) => eprintln!("Failed to store request: {}", e),
            }
        }
    }
}

async fn handle_approve(alias: &str, index: usize) -> anyhow::Result<()> {
    use keri_sdk::types::DelegationRequest;

    let mut id = load(alias)?;
    let signer = Arc::new(load_signer(alias)?);
    let req = Requests::new(alias)?;

    let stored = req.accept(index);
    let (event, mut exchanges) = match stored {
        Ok(Some(data)) => data,
        Ok(None) => anyhow::bail!("No request at index {}", index),
        Err(e) => anyhow::bail!("Failed to retrieve request: {}", e),
    };

    let exchange = exchanges.pop()
        .ok_or_else(|| anyhow::anyhow!("Delegation request has no exchange message"))?;

    let action = keri_sdk::ActionRequired::DelegationRequest(event, exchange);
    let delegation_req = DelegationRequest::try_from(action)
        .map_err(|_| anyhow::anyhow!("Request at index {} is not a delegation request", index))?;

    let delegatee = delegation_req.identifier();
    println!("Approving delegation for {}", delegatee);

    keri_sdk::operations::approve_delegation(&mut id, &signer, delegation_req).await?;

    println!("Delegation approved. The delegatee can now run `dkms delegation complete`.");
    Ok(())
}

async fn handle_complete(alias: &str) -> anyhow::Result<()> {
    let mut temp_id = load(alias)?;
    let signer = Arc::new(load_signer(alias)?);

    let mut dir = working_directory()?;
    dir.push(alias);

    let delegated_prefix: IdentifierPrefix = std::fs::read_to_string(dir.join("delegated_id"))
        .map_err(|e| {
            anyhow::anyhow!(
                "Missing delegated_id — was `delegation request` run for this alias? ({})",
                e
            )
        })?
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid delegated_id"))?;

    let delegator_id: IdentifierPrefix = std::fs::read_to_string(dir.join("delegator_id"))
        .map_err(|e| anyhow::anyhow!("Missing delegator_id ({})", e))?
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid delegator_id"))?;

    // Resolve delegator OOBI so we have their KEL locally.
    let delegator_locs = find_locations(&temp_id, std::iter::once(delegator_id.clone()));
    if delegator_locs.is_empty() {
        eprintln!(
            "Warning: Could not find delegator's OOBI. Make sure you've resolved it:\n  \
             dkms identifier oobi resolve -a {} -f <delegator-oobi.json>",
            alias
        );
    }

    keri_sdk::operations::complete_delegation(
        &mut temp_id,
        &signer,
        &delegated_prefix,
        &delegator_id,
    )
    .await?;

    // Update persisted identifier to the delegated one.
    save_identifier(&delegated_prefix, &dir.join("id"))?;

    println!("Delegation complete!");
    println!("Identifier: {}", delegated_prefix);
    Ok(())
}

fn handle_info(alias: &str) {
    let mut dir = working_directory().unwrap();
    dir.push(alias);

    let id = load_identifier(alias);
    let delegated = std::fs::read_to_string(dir.join("delegated_id")).ok();
    let delegator = std::fs::read_to_string(dir.join("delegator_id")).ok();

    match id {
        Ok(id) => println!("Identifier:  {}", id),
        Err(_) => println!("Identifier:  (not found)"),
    }

    match delegated {
        Some(d) => println!("Delegated:   {}", d.trim()),
        None => println!("Delegated:   (not a delegated identifier)"),
    }

    match delegator {
        Some(d) => println!("Delegator:   {}", d.trim()),
        None => println!("Delegator:   (none)"),
    }
}
