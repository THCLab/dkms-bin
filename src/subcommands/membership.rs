use clap::Subcommand;
use said::SelfAddressingIdentifier;
use std::{str::FromStr, sync::Arc, thread::sleep, time::Duration};

#[derive(Subcommand)]
pub enum MembershipCommand {
    /// Add participant to a group
    Add {
        /// Alias of identifier who creates the group
        #[arg(short, long)]
        alias: String,
        /// Alias of group to add participant to
        #[arg(short, long)]
        group_alias: String,
        /// Participant's identifier
        #[arg(short, long)]
        participant: IdentifierPrefix,
        /// Participants OOBIs
        #[arg(short, long)]
        oobi: Option<String>,
    },
    /// Remove participant from a group
    Remove {
        /// Alias of identifier who creates the group
        #[arg(short, long)]
        alias: String,
        /// Alias of group to remove participant from
        #[arg(short, long)]
        group_alias: String,
        /// Participant's identifier
        #[arg(short, long)]
        participant: IdentifierPrefix,
    },
    /// Finalize group creation and send requests to group members
    Finalize {
        /// Alias of identifier who creates the group
        #[arg(short, long)]
        alias: String,
        /// Alias of group to finalize
        #[arg(short, long)]
        group_alias: String,
        /// Group signing threshold
        #[arg(long)]
        group_threshold: u64,
        /// The URL of the witness
        #[arg(long)]
        witness_url: Vec<Url>,
        /// Natural number specifying the minimum witnesses needed to confirm a KEL event
        #[arg(long)]
        witness_threshold: Option<u64>,
    },
    /// List pending memberships and requests from other identifiers of the given alias
    Pending {
        /// Alias of identifier to show pending memberships and requests
        #[arg(short, long)]
        alias: String,
        /// Optional argument that specifies whether to pull the mailbox
        #[arg(long)]
        pull: bool,
        /// Optional argument that specifies the time in seconds to pull the mailbox. If not provided, the mailbox will be pulled indefinitely.
        #[arg(long, requires = "pull")]
        time: Option<u32>,
    },
    /// Accept a pending request
    Accept {
        /// Alias of identifier accepting the request
        #[arg(short, long)]
        alias: String,
        /// Index of the request in the pending request list
        #[arg(short, long)]
        index: usize,
        /// Alias under which the confirmed group identifier will be saved
        #[arg(short, long)]
        group_alias: Option<String>,
    },
    /// Show groups associated with the given alias
    Info {
        /// Alias of identifier to show groups of
        #[arg(short, long)]
        alias: String,
        /// Optional argument that specifies the group alias to show details about
        #[arg(short, long)]
        group_alias: Option<String>,
    },
    /// Sign a message with the group's identifier
    Sign {
        /// Alias of group member that will sign the message
        #[arg(short, long)]
        alias: String,
        /// Alias of group to sign the message with
        #[arg(short, long)]
        group_alias: String,
        /// Message to sign
        #[arg(short, long)]
        message: String,
    },
    /// Returns the group's identifier OOBI
    Oobi {
        /// Alias of group member
        #[arg(short, long)]
        alias: String,
        /// Alias of group
        #[arg(short, long)]
        group_alias: String,
    },
    /// Issue credential
    Issue {
        /// Alias of issuing identifier
        #[arg(short, long)]
        alias: String,
        /// Alias of group
        #[arg(short, long)]
        group_alias: String,
        /// Attributes in JSON format used to construct an ACDC
        #[arg(short, long)]
        message: String,
        /// OCA Bundle identifier
        #[arg(short = 'b', long, value_parser = parse_said)]
        oca_bundle_said: SelfAddressingIdentifier,
    },
    /// Incept registry
    Registry {
        /// Alias of issuing identifier
        #[arg(short, long)]
        alias: String,
        /// Alias of group
        #[arg(short, long)]
        group_alias: String,
    },
}

pub async fn process_membership_command(cmd: MembershipCommand) {
    match cmd {
        MembershipCommand::Add {
            alias,
            group_alias,
            participant,
            oobi,
        } => {
            if let Some(oobi) = oobi {
                let id = load(&alias).unwrap();
                let oobi: Vec<Oobi> = serde_json::from_str(&oobi).unwrap();
                for oobi in oobi {
                    id.resolve_oobi(&oobi).await.unwrap();
                }
            }
            let membership = Membership::new(&alias);
            membership.add_member(&group_alias, &participant).unwrap();
            println!("Added {} to {}", participant.to_string(), group_alias);
        }
        MembershipCommand::Remove {
            alias,
            group_alias,
            participant,
        } => {
            let membership = Membership::new(&alias);
            membership
                .remove_member(&group_alias, &participant)
                .unwrap();
            println!("Removed {} from {}", participant, group_alias);
        }
        MembershipCommand::Pending { alias, pull, time } => {
            let mut id = load(&alias).unwrap();
            let signer = Arc::new(load_signer(&alias).unwrap());
            let mem = Arc::new(Membership::new(&alias));
            let req = Requests::new(&alias).unwrap();
            handle_pending(&mut id, req, signer, mem, pull, time).await;
        }
        MembershipCommand::Finalize {
            alias,
            group_alias,
            group_threshold,
            witness_url,
            witness_threshold,
        } => {
            let mut initiator_id = load(&alias).unwrap();
            let signer = Arc::new(load_signer(&alias).unwrap());
            let membership = Membership::new(&alias);
            let members = membership.get_members(group_alias.as_str());

            let witnesses_oobis = find_oobis_for_urls(witness_url).await.unwrap();
            let group_id = group_incept(
                &mut initiator_id,
                signer,
                members,
                group_threshold,
                None,
                witnesses_oobis,
                witness_threshold.unwrap(),
            )
            .await
            .unwrap();
            membership.save_group(&group_alias, &group_id.to_string());
            println!(
                "Group {} finalized. Requests sent to participants. Group id: {}",
                group_alias,
                group_id.to_string()
            );
        }
        MembershipCommand::Accept {
            alias,
            index,
            group_alias,
        } => {
            let mut id = load(&alias).unwrap();
            let signer = Arc::new(load_signer(&alias).unwrap());
            let req = Requests::new(&alias).unwrap();
            let group_id = accept(&mut id, req, signer, index).await;
            match (group_alias, group_id) {
                (Some(group_alias), Some(id)) => {
                    let membership = Membership::new(&alias);
                    membership.save_group(&group_alias, &id.to_string());
                }
                _ => (),
            };
        }
        MembershipCommand::Info { alias, group_alias } => {
            let membership = Membership::new(&alias);

            if let Some(group_alias) = group_alias {
                let id = membership.get_identifier(group_alias.as_str());
                println!("Identifier: {:?}", id.to_string());
                let cont = load_controller(alias.as_str()).unwrap();
                let state = cont.find_state(&id);
                match state {
						                    Ok(state) => println!("State: {}", serde_json::to_string_pretty(&state).unwrap()),
						                    Err(MechanicsError::UnknownIdentifierError(_id)) => println!("Not all participants have accepted the group. Try `membership pending` to check for confirmation."),
						                    Err(e) => println!("Error: {:?}", e),
					                    }
            } else {
                membership
                    .list_groups()
                    .iter()
                    .for_each(|v| println!("{}", v));
            }
        }
        MembershipCommand::Sign {
            alias,
            group_alias,
            message,
        } => {
            let resp = handle_group_sign(alias, &group_alias, &message).unwrap();
            println!("{}", resp);
        }
        MembershipCommand::Oobi { alias, group_alias } => {
            match handle_group_oobi(&alias, &group_alias) {
                Ok(lcs) => println!("{}", serde_json::to_string(&lcs).unwrap()),
                Err(e) => println!("{}", e),
            }
        }
        MembershipCommand::Issue {
            alias,
            group_alias,
            message,
            oca_bundle_said,
        } => {
            let ewa_id = load_identifier(&alias).unwrap();
            let group_id = load_group_id(&alias, &group_alias).unwrap();
            let ewa_signer = Arc::new(load_signer(&alias).unwrap());
            handle_group_issue(
                group_id,
                &ewa_id,
                ewa_signer,
                &message,
                oca_bundle_said.to_string(),
            )
            .await
            .unwrap();
        }
        MembershipCommand::Registry { alias, group_alias } => {
            let mut group_id = load_group_id(&alias, &group_alias).unwrap();
            let participant_id = load_identifier(&alias).unwrap();
            let signer = Arc::new(load_signer(&alias).unwrap());
            let membership = Arc::new(Membership::new(&alias));
            handle_group_registry_incept(
                &mut group_id,
                &participant_id,
                signer,
                membership,
                &group_alias,
            )
            .await
            .unwrap();
        }
    }
}

pub async fn handle_pending(
    id: &mut Identifier,
    req: Requests,
    signer: Arc<Signer>,
    mem: Arc<Membership>,
    pull: bool,
    time: Option<u32>,
) {
    let not_finalized = mem.list_groups_members();
    if !not_finalized.is_empty() {
        println!("Not finalized groups. You can finalize them with `membership finalize` command:  \n\talias | members\n\t{}\n\t", not_finalized.join("\n\t"));
    }

    let all_req = req.show().unwrap();
    if !all_req.is_empty() {
        println!(
            "Requests from others. You can accept them with `membership accept` command: \n{}",
            all_req.join("\n\t")
        );
    }
    if pull {
        watch_mailbox(id, signer, &mem, req, time).await
    }
}

async fn watch_mailbox(
    mut identifier: &mut Identifier,
    signer: Arc<Signer>,
    mem: &Membership,
    mut requests: Requests,
    time: Option<u32>,
) {
    let all_req = requests.show().unwrap();
    if !all_req.is_empty() {
        println!(
            "Requests from others. You can accept them with `membership accept` command: \n{}",
            all_req.join("\n\t")
        );
    }
    if let Some(time) = time {
        for _ in 0..time {
            pull_mailbox_helper(&mut identifier, signer.clone(), mem, &mut requests).await;
            sleep(Duration::from_secs(1));
        }
    } else {
        loop {
            pull_mailbox_helper(&mut identifier, signer.clone(), mem, &mut requests).await;
            sleep(Duration::from_secs(1));
        }
    }
}

async fn pull_mailbox_helper(
    mut identifier: &mut Identifier,
    signer: Arc<Signer>,
    mem: &Membership,
    requests: &mut Requests,
) {
    let bob_mailbox = pull_mailbox(&mut identifier, signer.clone()).await.unwrap();
    for request in bob_mailbox {
        let requested_event = match &request {
            ActionRequired::MultisigRequest(ev, exn) => ev,
            ActionRequired::DelegationRequest(ev, exn) => todo!(),
        };
        let req_info = Requests::show_one(&requested_event);
        let index = requests.add(request).unwrap();
        println!("New request: {}: {}", index, req_info);
    }
    for group in mem.group_ids() {
        let bob_group_mailbox = pull_group_mailbox(&mut identifier, &group, signer.clone())
            .await
            .unwrap();
        for request in bob_group_mailbox {
            let requested_event = match &request {
                ActionRequired::MultisigRequest(ev, exn) => ev,
                ActionRequired::DelegationRequest(_ev, exn) => todo!(),
            };
            let req_info = Requests::show_one(&requested_event);
            let index = requests.add(request).unwrap();
            println!("New group request: {}: {}", index, req_info);
        }
    }
}

use keri_controller::{
    identifier::{mechanics::MechanicsError, Identifier},
    mailbox_updating::ActionRequired,
    IdentifierPrefix, Oobi,
};
use keri_core::signer::Signer;
use redb::{
    Database, MultimapTableDefinition, ReadableMultimapTable, ReadableTable, TableDefinition,
};
use url::Url;

use crate::{
    multisig::{accept, group_incept, pull_group_mailbox, pull_mailbox},
    resolve::handle_group_oobi,
    sign::handle_group_sign,
    subcommands::identifier::find_oobis_for_urls,
    tel::{handle_group_issue, handle_group_registry_incept},
    utils::{
        load, load_controller, load_group_id, load_identifier, load_signer, working_directory,
        LoadingError, Requests,
    },
};

use super::data::parse_said;

/// Group alias -> Group participants mapping. Stores the list of participants until group is finalized.
const INITIALIZED: MultimapTableDefinition<&str, &str> =
    MultimapTableDefinition::new("initialized");

/// Group alias -> Group identifier mapping
const FINISHED: TableDefinition<&str, &str> = TableDefinition::new("finished");

/// Alias -> Registry ID mapping
const REGISTRIES: TableDefinition<&str, &str> = TableDefinition::new("registries");

pub struct Membership(Database);

impl Membership {
    pub fn new(alias: &str) -> Self {
        let mut dir = working_directory().unwrap();
        dir.push(alias);
        dir.push("membership");
        let db = Database::create(dir).unwrap();
        let write_txn = db.begin_write().unwrap(); // Start a write transaction
        {
            // Open the table (this ensures it exists)
            let _table = write_txn.open_multimap_table(INITIALIZED).unwrap();
            let _table = write_txn.open_table(FINISHED).unwrap();
            let _table = write_txn.open_table(REGISTRIES).unwrap();
        }
        write_txn.commit().unwrap();
        Self(db)
    }

    fn get_members(&self, group_alias: &str) -> Vec<IdentifierPrefix> {
        let read_txn = self.0.begin_read().unwrap();
        let table = read_txn.open_multimap_table(INITIALIZED).unwrap();
        let current = table.get(group_alias).unwrap();
        current
            .map(|v| IdentifierPrefix::from_str(v.unwrap().value()).unwrap())
            .collect()
    }

    pub fn add_member(&self, group_alias: &str, id: &IdentifierPrefix) -> Result<(), LoadingError> {
        let write_txn = self.0.begin_write().unwrap();
        {
            let mut table = write_txn.open_multimap_table(INITIALIZED).unwrap();
            table.insert(group_alias, id.to_string().as_str()).unwrap();
        }
        write_txn.commit().unwrap();
        Ok(())
    }

    fn remove_member(&self, group_alias: &str, id: &IdentifierPrefix) -> Result<(), LoadingError> {
        let write_txn = self.0.begin_write().unwrap();
        {
            let mut table = write_txn.open_multimap_table(INITIALIZED).unwrap();
            table.remove(group_alias, id.to_string().as_str()).unwrap();
        }
        write_txn.commit().unwrap();
        Ok(())
    }

    pub fn list_groups_members(&self) -> Vec<String> {
        let read_txn = self.0.begin_read().unwrap();
        let table = read_txn.open_multimap_table(INITIALIZED).unwrap();
        let mut out = vec![];
        for r in table.iter().unwrap() {
            let (key, value) = r.unwrap();
            let participants = value
                .map(|v| v.unwrap().value().to_string())
                .collect::<Vec<_>>();
            out.push(format!("{}: {}", key.value(), participants.join(", ")));
        }
        out
    }

    pub fn save_group(&self, group_alias: &str, group_id: &str) {
        let write_txn = self.0.begin_write().unwrap();
        {
            let mut table = write_txn.open_multimap_table(INITIALIZED).unwrap();
            table.remove_all(group_alias).unwrap();
            let mut table = write_txn.open_table(FINISHED).unwrap();
            table.insert(group_alias, group_id).unwrap();
        }
        write_txn.commit().unwrap();
    }

    pub fn save_group_registry(&self, group_alias: &str, registry_id: &str) {
        let write_txn = self.0.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(REGISTRIES).unwrap();
            table.insert(group_alias, registry_id).unwrap();
        }
        write_txn.commit().unwrap();
        println!("Registry {} saved for {}", registry_id, group_alias);
    }

    pub fn get_group_registry(&self, group_alias: &str) -> Option<IdentifierPrefix> {
        let read_txn = self.0.begin_read().unwrap();
        {
            let table = read_txn.open_table(REGISTRIES).unwrap();
            table
                .get(group_alias)
                .unwrap()
                .map(|reg| reg.value().parse::<IdentifierPrefix>().unwrap())
        }
    }

    pub fn get_identifier(&self, group_alias: &str) -> IdentifierPrefix {
        let read_txn = self.0.begin_read().unwrap();
        {
            let table = read_txn.open_table(FINISHED).unwrap();
            table
                .get(group_alias)
                .unwrap()
                .unwrap()
                .value()
                .parse()
                .unwrap()
        }
    }

    pub fn list_groups(&self) -> Vec<String> {
        let read_txn = self.0.begin_read().unwrap();
        let table = read_txn.open_table(FINISHED).unwrap();
        let mut out = vec![];
        for r in table.iter().unwrap() {
            let (key, value) = r.unwrap();
            out.push(format!("{}: {}", key.value(), value.value()));
        }
        out
    }

    pub fn group_ids(&self) -> Vec<IdentifierPrefix> {
        let read_txn = self.0.begin_read().unwrap();
        let table = read_txn.open_table(FINISHED).unwrap();
        let mut out = vec![];
        for r in table.iter().unwrap() {
            let (_key, value) = r.unwrap();
            let id: IdentifierPrefix = value.value().parse().unwrap();
            out.push(id);
        }
        out
    }
}
