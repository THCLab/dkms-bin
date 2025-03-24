use std::{str::FromStr, sync::Arc};

use clap::Subcommand;


#[derive(Subcommand)]
pub enum MembershipCommand {
    Create {
        #[arg(short, long)]
        alias: String,
		#[arg(short, long)]
        group_alias: String,
    },
	/// Add participant to group
	Add {
		#[arg(short, long)]
        alias: String,
		#[arg(short, long)]
        group_alias: String,
		#[arg(short, long)]
        participant: IdentifierPrefix,
		#[arg(short, long)]
		oobi: Option<String>,
	},
	/// Remove participant from group
	Remove {
		#[arg(short, long)]
        alias: String,
		#[arg(short, long)]
        group_alias: String,
		#[arg(short, long)]
        participant: IdentifierPrefix,
	},
	/// List of not finalized memberships of given alias. Show group alias and list of members
	List {
		#[arg(short, long)]
        alias: String,
	},
	/// Finalize group creation and sends requests to group members
	Finalize {
		#[arg(short, long)]
        alias: String,
		#[arg(short, long)]
        group_alias: String,
		#[arg(long)]
        group_threshold: u64,
		/// The URL of the witness
        #[arg(long)]
        witness_url: Vec<Url>,
        /// Natural number specifying the minimum witnesses needed to confirm a KEL event
        #[arg(long)]
        witness_threshold: Option<u64>,
	},
	/// List of requests from other identifiers
	Pending {
		#[arg(short, long)]
        alias: String,
	},
	/// Accepts pending request. Index is the index of the request in the
	/// pending request list
	Accept {
		#[arg(short, long)]
		alias: String,
		#[arg(short, long)]
		index: usize,
	}
}

pub async fn process_membership_command(cmd: MembershipCommand) {
	match cmd {
	MembershipCommand::Create { alias, group_alias } => {
			let membership = Membership::new(&alias);
			println!("Created membership database for {}", alias);
		}
    MembershipCommand::Add { alias, group_alias, participant, oobi } => {
			if let Some(oobi) = oobi {
				let id = load(&alias).unwrap();
				let oobi: Vec<Oobi> = serde_json::from_str(&oobi).unwrap();
				for oobi in oobi {
					id.resolve_oobi(&oobi).await.unwrap();
				}
			}
			let membership = Membership::new(&alias);
			membership.add(&group_alias, &participant).unwrap();
			println!("Added {} to {}", alias, group_alias);
		}
    MembershipCommand::Remove { alias, group_alias, participant } => {
			let membership = Membership::new(&alias);
			membership.remove(&group_alias, &participant).unwrap();
			println!("Removed {} from {}", alias, group_alias);
		}
    MembershipCommand::List {alias } => {
			let membership = Membership::new(&alias);
			membership.list().iter().for_each(|v| println!("{}", v));

		}
    MembershipCommand::Pending {alias} => {
			let mut id = load(&alias).unwrap();
			let signer = Arc::new(load_signer(&alias).unwrap());
			let req = requests(&mut id, signer).await;
			let all_req = req.show(id.id());
			println!("{}", all_req);

		}
    MembershipCommand::Finalize { alias, group_alias, group_threshold, witness_url, witness_threshold } => {
			let mut initiator_id = load(&alias).unwrap();
			let signer = Arc::new(load_signer(&alias).unwrap());
			let membership = Membership::new(&alias);
			let members = membership.get(group_alias.as_str());
			dbg!(&members);
			
            let witnesses_oobis = find_oobis_for_urls(witness_url).await.unwrap();
			let group_id = group_incept(&mut initiator_id, signer, members, group_threshold, None, witnesses_oobis, witness_threshold.unwrap()).await.unwrap();
			println!("Accepted pending memberships. Group id: {}", group_id.to_string());
		}
    MembershipCommand::Accept { alias, index } => {
		let mut id = load(&alias).unwrap();
		let signer = Arc::new(load_signer(&alias).unwrap());
		accept(&mut id, signer, index).await;
	},
		}

}


use keri_controller::{IdentifierPrefix, LocationScheme, Oobi};
use redb::{Database, MultimapTableDefinition, ReadableMultimapTable};
use url::Url;

use crate::{multisig::{accept, group_incept, requests}, subcommands::{identifier::find_oobis_for_urls, membership}, utils::{load, load_signer, working_directory, LoadingError}};

const INITIALIZED: MultimapTableDefinition<&str, &str> = MultimapTableDefinition::new("initialized");

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
        }
        write_txn.commit().unwrap();
        Self(db)
    }

    fn get(&self, group_alias: &str) -> Vec<IdentifierPrefix> {
        let read_txn = self.0.begin_read().unwrap();
        let table = read_txn.open_multimap_table(INITIALIZED).unwrap();
        let current = table.get(group_alias)
            .unwrap();
		current.map(|v| IdentifierPrefix::from_str(v.unwrap().value()).unwrap()).collect()
    }

   pub fn add(&self, group_alias: &str, id: &IdentifierPrefix) -> Result<(), LoadingError> {
       let write_txn = self.0.begin_write().unwrap();
        {
            let mut table = write_txn.open_multimap_table(INITIALIZED).unwrap();
            table.insert(group_alias, id.to_string().as_str()).unwrap();
        }
        write_txn.commit().unwrap();
        Ok(())
    }

	fn remove(&self, group_alias: &str, id: &IdentifierPrefix) -> Result<(), LoadingError> {
       let write_txn = self.0.begin_write().unwrap();
        {
            let mut table = write_txn.open_multimap_table(INITIALIZED).unwrap();
            table.remove(group_alias, id.to_string().as_str()).unwrap();
        }
        write_txn.commit().unwrap();
        Ok(())
    }

	pub fn list(&self) -> Vec<String> {
		let read_txn = self.0.begin_read().unwrap();
		let table = read_txn.open_multimap_table(INITIALIZED).unwrap();
		let mut out = vec![];
		for r in table.iter().unwrap() {
			let (key, value) = r.unwrap();
			let participants = value.map(|v| v.unwrap().value().to_string()).collect::<Vec<_>>();
			out.push(format!("{}: {}", key.value(), participants.join(", ")));
		};
		out
	}
}
