use std::str::FromStr;

use clap::Subcommand;


#[derive(Subcommand)]
pub enum MembershipCommand {
    Create {
        #[arg(short, long)]
        alias: String,
		#[arg(short, long)]
        group_alias: String,
    },
	Add {
		#[arg(short, long)]
        alias: String,
		#[arg(short, long)]
        group_alias: String,
		#[arg(short, long)]
        participant: IdentifierPrefix,
	},
	Remove {
		#[arg(short, long)]
        alias: String,
		#[arg(short, long)]
        group_alias: String,
		#[arg(short, long)]
        participant: IdentifierPrefix,
	},
	List {#[arg(short, long)]
        alias: String,},
	Pending {},
	Accept {},
}

pub fn process_membership_command(cmd: MembershipCommand) {
	match cmd {
		MembershipCommand::Create { alias, group_alias } => {
			let membership = Membership::new(&alias);
			println!("Created membership database for {}", alias);
		}
		MembershipCommand::Add { alias, group_alias, participant } => {
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
			println!("Listed memberships");
			membership.list().iter().for_each(|v| println!("{}", v));

		}
		MembershipCommand::Pending {} => {
			println!("Listed pending memberships");
		}
		MembershipCommand::Accept {} => {
			println!("Accepted pending memberships");
		}
	}

}


use keri_controller::IdentifierPrefix;
use redb::{Database, MultimapTableDefinition, ReadableMultimapTable};

use crate::utils::{working_directory, LoadingError};

const TABLE: MultimapTableDefinition<&str, &str> = MultimapTableDefinition::new("membership");

pub struct Membership(Database);

impl Membership {
    pub fn new(alias: &str) -> Self {
        let mut dir = working_directory().unwrap();
        dir.push(alias);
		dir.push("membership");
        let db = Database::create(dir).unwrap();
        let write_txn = db.begin_write().unwrap(); // Start a write transaction
        {
            let _table = write_txn.open_multimap_table(TABLE).unwrap(); // Open the table (this ensures it exists)
        }
        write_txn.commit().unwrap();
        Self(db)
    }

    fn get(&self, group_alias: &str) -> Vec<IdentifierPrefix> {
        let read_txn = self.0.begin_read().unwrap();
        let table = read_txn.open_multimap_table(TABLE).unwrap();
        let current = table.get(group_alias)
            .unwrap();
		current.map(|v| IdentifierPrefix::from_str(v.unwrap().value()).unwrap()).collect()
    }

   pub fn add(&self, group_alias: &str, id: &IdentifierPrefix) -> Result<(), LoadingError> {
       let write_txn = self.0.begin_write().unwrap();
        {
            let mut table = write_txn.open_multimap_table(TABLE).unwrap();
            table.insert(group_alias, id.to_string().as_str()).unwrap();
        }
        write_txn.commit().unwrap();
        Ok(())
    }

	fn remove(&self, group_alias: &str, id: &IdentifierPrefix) -> Result<(), LoadingError> {
       let write_txn = self.0.begin_write().unwrap();
        {
            let mut table = write_txn.open_multimap_table(TABLE).unwrap();
            table.remove(group_alias, id.to_string().as_str()).unwrap();
        }
        write_txn.commit().unwrap();
        Ok(())
    }

	pub fn list(&self) -> Vec<String> {
		let read_txn = self.0.begin_read().unwrap();
		let table = read_txn.open_multimap_table(TABLE).unwrap();
		let mut out = vec![];
		for r in table.iter().unwrap() {
			let (key, value) = r.unwrap();
			let participants = value.map(|v| v.unwrap().value().to_string()).collect::<Vec<_>>();
			out.push(format!("{}: {}", key.value(), participants.join(", ")));
		};
		out
	}
}
