use clap::Subcommand;
use std::{str::FromStr, sync::Arc, thread::sleep, time::Duration};
use tokio::sync::Mutex;

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
        #[arg(short, long)]
        alias: String,
        #[arg(long)]
        pull: bool,
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
        group_alias: String,
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
        MembershipCommand::Pending { alias, pull } => {
            let id = load(&alias).unwrap();
            let signer = Arc::new(load_signer(&alias).unwrap());
            let mem = Membership::new(alias.as_str());
            let not_finalized = mem.list_groups_members();
            if !not_finalized.is_empty() {
                println!("Not finalized groups. You can finalize them with `membership finalize` command:  \n\talias | members\n\t{}\n\t", not_finalized.join("\n\t"));
            }

            let req = Requests::new();
            let all_req = req.show(id.id());
            if !all_req.is_empty() {
                println!("Requests from others. You can accept them with `membership accept` command: \n{}", all_req.join("\n\t"));
            }
            if pull {
                watch_mailbox(id, signer, &mem, req).await
            }
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
            let group_id = accept(&mut id, signer, index).await;
            let membership = Membership::new(&alias);
            membership.save_group(&group_alias, &group_id.to_string());
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
    }
}

async fn watch_mailbox(
    mut identifier: Identifier,
    signer: Arc<Signer>,
    mem: &Membership,
    mut requests: Requests,
) {
    let all_req = requests.show(identifier.id());
    if !all_req.is_empty() {
        println!(
            "Requests from others. You can accept them with `membership accept` command: \n{}",
            all_req.join("\n\t")
        );
    }
    loop {
        let bob_mailbox = pull_mailbox(&mut identifier, signer.clone()).await.unwrap();
        for request in bob_mailbox {
            let req_info = Requests::show_one(&request);
            let index = requests.add(identifier.id(), request);
            println!("New request: {}: {}", index, req_info);
        }
        for group in mem.group_ids() {
            let bob_group_mailbox = pull_group_mailbox(&mut identifier, &group, signer.clone())
                .await
                .unwrap();
            for request in bob_group_mailbox {
                let req_info = Requests::show_one(&request);
                let index = requests.add(identifier.id(), request);
                println!("New request: {}: {}", index, req_info);
            }
        }

        sleep(Duration::from_secs(3));
    }
}

use keri_controller::{
    identifier::{mechanics::MechanicsError, Identifier},
    IdentifierPrefix, Oobi,
};
use keri_core::signer::Signer;
use redb::{
    Database, MultimapTableDefinition, ReadableMultimapTable, ReadableTable, TableDefinition,
};
use url::Url;

use crate::{
    multisig::{accept, group_incept, pull_group_mailbox, pull_mailbox},
    subcommands::{identifier::find_oobis_for_urls, membership},
    utils::{load, load_controller, load_signer, working_directory, LoadingError, Requests},
};

const INITIALIZED: MultimapTableDefinition<&str, &str> =
    MultimapTableDefinition::new("initialized");
const FINISHED: TableDefinition<&str, &str> = TableDefinition::new("finished");

pub struct Membership(Database);

impl Membership {
    pub fn new(alias: &str) -> Self {
        let mut dir = working_directory().unwrap();
        dir.push(alias);
        dir.push("membership");
        let db = Database::create(dir).unwrap();
        let write_txn = db.begin_write().unwrap(); // Start a write transaction
        {
            let _table = write_txn.open_multimap_table(INITIALIZED).unwrap(); // Open the table (this ensures it exists)
            let _table = write_txn.open_table(FINISHED).unwrap(); // Open the table (this ensures it exists)
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
            let (key, value) = r.unwrap();
            let id: IdentifierPrefix = value.value().parse().unwrap();
            out.push(id);
        }
        out
    }
}
