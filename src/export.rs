use keri_controller::{IdentifierPrefix, LocationScheme, Oobi, SeedPrefix};
use serde::{Deserialize, Serialize};

use crate::utils::{load, load_next_seed, load_seed};

#[derive(Serialize, Deserialize)]
pub struct IdentifierExport {
    current: SeedPrefix,
    next: SeedPrefix,
    witnesses: Vec<LocationScheme>,
    watchers: Vec<LocationScheme>,
    witness_threshold: u64,
}
pub fn handle_export(alias: &str) -> IdentifierExport {
    let identifier = load(&alias).unwrap();
    let current = load_seed(&alias).unwrap();
    let next = load_next_seed(&alias).unwrap();

    let witnesses = identifier
        .witnesses()
        .map(|id| {
            identifier
                .get_location(&IdentifierPrefix::Basic(id))
                .unwrap()
        })
        .flatten()
        .collect::<Vec<_>>();
    let state = identifier.find_state(identifier.id()).unwrap();
    let witness_threshold = state.witness_config.tally;
    let witness_threshold = match witness_threshold {
        keri_core::event::sections::threshold::SignatureThreshold::Simple(i) => i,
        keri_core::event::sections::threshold::SignatureThreshold::Weighted(weighted_threshold) => {
            todo!()
        }
    };
    let watchers = identifier
        .get_role_location(identifier.id(), keri_core::oobi::Role::Watcher)
        .unwrap();

    IdentifierExport {
        current,
        next,
        witnesses,
        watchers,
        witness_threshold,
    }
}
