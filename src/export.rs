use keri_controller::{LocationScheme, SeedPrefix};
use serde::{Deserialize, Serialize};

use crate::utils::{
    collect_watchers_data, collect_witness_data, load, load_next_seed, load_seed, LoadingError,
};

#[derive(thiserror::Error, Debug)]
pub enum ExportError {
    #[error(transparent)]
    Loading(#[from] LoadingError),
}

#[derive(Serialize, Deserialize)]
pub struct IdentifierExport {
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

    Ok(IdentifierExport {
        current_seed: current,
        next_seed: next,
        witnesses: witness_locations,
        watchers,
        witness_threshold,
    })
}
