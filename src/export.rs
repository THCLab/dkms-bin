use std::fs::create_dir_all;

use keri_controller::config::ControllerConfig;
use keri_controller::controller::Controller;
use keri_controller::{identifier::Identifier, IdentifierPrefix, LocationScheme, SeedPrefix};
use keri_controller::{CesrPrimitive, EndRole, Oobi};
use keri_core::event::sections::seal::EventSeal;
use keri_core::oobi::Role;
use serde::{Deserialize, Serialize};

use crate::tel::save_registry;
use crate::temporary_identifier::generate_temporary_identifier;
use crate::utils::{save_identifier, save_next_seed, save_seed};
use crate::{
    init::{kel_database_path, KeysConfig},
    utils::{
        collect_watchers_data, collect_witness_data, load, load_next_seed, load_seed, LoadingError,
    },
};

#[derive(thiserror::Error, Debug)]
pub enum ExportError {
    #[error(transparent)]
    Loading(#[from] LoadingError),
    #[error("Temporary identifier error: {0}")]
    TemporaryId(String),
    #[error("File creation error: {0}")]
    FileCreation(std::io::Error),
    #[error("Writting to file error: {0}")]
    FileWritting(std::io::Error),
}

#[derive(Serialize, Deserialize)]
pub struct IdentifierExport {
    identifier: IdentifierPrefix,
    last_event_seal: EventSeal,
    registry_id: Option<IdentifierPrefix>,
    current_seed: SeedPrefix,
    next_seed: SeedPrefix,
    witnesses: Vec<LocationScheme>,
    watchers: Vec<LocationScheme>,
    witness_threshold: u64,
}
pub fn handle_export(alias: &str) -> Result<IdentifierExport, ExportError> {
    let identifier = load(alias)?;
    let current = load_seed(alias)?;
    let next = load_next_seed(alias)?;

    let (witness_locations, witness_threshold) = collect_witness_data(&identifier)?;
    let watchers = collect_watchers_data(&identifier)?;
    let id = identifier.id();
    let last_event_seal = identifier.get_last_event_seal().unwrap();
    let registry_id = identifier.registry_id().cloned();

    Ok(IdentifierExport {
        identifier: id.clone(),
        last_event_seal,
        registry_id,
        current_seed: current,
        next_seed: next,
        witnesses: witness_locations,
        watchers,
        witness_threshold,
    })
}

pub async fn handle_import(alias: &str, imported: IdentifierExport) -> Result<(), ExportError> {
    let kc = KeysConfig {
        current: imported.current_seed,
        next: imported.next_seed,
    };

    let tmp_id = generate_temporary_identifier()?;

    let store_path = kel_database_path(alias)?;
    let mut db_path = store_path.clone();
    db_path.push("db");
    create_dir_all(&db_path).map_err(ExportError::FileCreation)?;

    let controller = Controller::new(ControllerConfig {
        db_path,
        ..Default::default()
    })
    .unwrap();
    let identifier = Identifier::new(
        imported.identifier.clone(),
        imported.registry_id.clone(),
        controller.known_events.clone(),
        controller.communication.clone(),
        controller.query_cache.clone(),
    );

    // Pull KEL from witnesses
    for witness in imported.witnesses {
        // Save witness OOBI
        identifier
            .resolve_oobi(&Oobi::Location(witness.clone()))
            .await
            .unwrap();
        // Find KEL
        let id = imported.last_event_seal.prefix.clone();
        let sn = imported.last_event_seal.sn;
        let kel = tmp_id
            .pull_kel(id.clone(), 0, sn, witness.clone())
            .await
            .unwrap();
        if let Some(kel) = kel {
            for msg in kel {
                controller.known_events.process(&msg).unwrap();
            }
        } else {
            println!("Identifier {} KEL not found", &id);
        };

        // Find TEL
        if let Some(registry_id) = &imported.registry_id {
            let tel_resp = tmp_id.pull_tel(registry_id, None, witness).await;
            controller
                .known_events
                .tel
                .parse_and_process_tel_stream(tel_resp.as_bytes())
                .unwrap();
        }
    }
    save_next_seed(&kc.next, &store_path).map_err(ExportError::FileWritting)?;

    save_identifier(&imported.identifier, &store_path).map_err(ExportError::FileWritting)?;

    save_seed(&kc.current, &store_path).map_err(ExportError::FileWritting)?;

    if let Some(registry_id) = &imported.registry_id {
        save_registry(alias, &registry_id.to_str()).unwrap();
    }

    // reconfigure watcher
    let watchers = imported.watchers;
    for watcher in watchers {
        identifier
            .resolve_oobi(&Oobi::Location(watcher.clone()))
            .await
            .unwrap();
        let end_role = EndRole {
            cid: identifier.id().clone(),
            role: Role::Watcher,
            eid: watcher.eid.clone(),
        };
        identifier
            .resolve_oobi(&Oobi::EndRole(end_role))
            .await
            .unwrap();
    }

    print!(
        "\nIdentifier for alias {} imported: {}",
        alias, imported.identifier
    );
    Ok(())
}
