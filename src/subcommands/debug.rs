use clap::Subcommand;
use keri_controller::{IdentifierPrefix, LocationScheme};

use crate::temporary_identifier::generate_temporary_identifier;

#[derive(Subcommand)]
pub enum DebugCommand {
	Ksn {
		/// Source OOBI in json
        #[arg(short, long)]
		source: String, 
        #[arg(short, long)]
		id: IdentifierPrefix,
	},
	Tel {
		/// Source OOBI in json
        #[arg(short, long)]
		source: String, 
        #[arg(short, long)]
		registry_id: IdentifierPrefix,
		#[arg(short, long)]
		vc_id: Option<IdentifierPrefix>,
	},
	Kel {
		/// Source OOBI in json
        #[arg(short, long)]
		source: String, 
        #[arg(short, long)]
		identifier: IdentifierPrefix,
        #[arg(long)]
		sn: u64,
        #[arg(short, long)]
		limit: Option<u64>,
	}
}

pub async fn process_debug_command(cmd: DebugCommand) {
	match cmd {
		DebugCommand::Ksn { source, id } => {
    		let tmp_id = generate_temporary_identifier().unwrap();
			let source: LocationScheme = serde_json::from_str(&source).unwrap();

        	let ksn = tmp_id.pull_ksn(id, source).await.unwrap();

			println!("{}", &ksn);
			
		},
		DebugCommand::Tel { source, vc_id, registry_id: id } => {
			let tmp_id = generate_temporary_identifier().unwrap();
			let source: LocationScheme = serde_json::from_str(&source).unwrap();

        	let tel = tmp_id.pull_tel(&id, vc_id, source).await;

			println!("{}", &tel);
		},
		DebugCommand::Kel { source, identifier, sn, limit } => {
			let tmp_id = generate_temporary_identifier().unwrap();
			let source: LocationScheme = serde_json::from_str(&source).unwrap();

			let limit = limit.unwrap_or(1);
        	let kel = tmp_id.pull_kel(identifier.clone(), sn, limit, source).await.unwrap();
			match kel {
				Some(kel) => {
					let kel_str = kel.into_iter().map(|event| String::from_utf8(event.to_cesr().unwrap()).unwrap()).collect::<Vec<_>>().join("\n");
					println!("{}", kel_str);

				},
				None => println!("Identifier {} not found", identifier.to_string()),
			}
			
		},
	}
}
