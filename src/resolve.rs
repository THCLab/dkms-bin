use std::fs;
use std::path::PathBuf;

use clap::Subcommand;
use keri_controller::{identifier::Identifier, EndRole, IdentifierPrefix, LocationScheme, Oobi};

use crate::{
    keri::KeriError, subcommands::identifier::IdentifierSubcommandError, utils::load, CliError,
};

#[derive(Subcommand)]
pub enum OobiRoles {
    Witness,
    Watcher,
    Messagebox,
}

pub async fn handle_resolve(alias: &str, path: PathBuf) -> Result<(), IdentifierSubcommandError> {
    let id_cont = load(alias)?;
    let file = fs::read_to_string(path).expect("Should have been able to read the file");
    for oobi in serde_json::from_str::<Vec<Oobi>>(&file).unwrap() {
        let _ = id_cont
            .resolve_oobi(&oobi)
            .await
            .map_err(KeriError::MechanicsError);
        id_cont
            .send_oobi_to_watcher(id_cont.id(), &oobi)
            .await
            .map_err(KeriError::ControllerError)?;
    }
    Ok(())
}

/// Returns witnesses' identifiers of alias
pub fn witnesses(identifier: &Identifier) -> Result<Vec<IdentifierPrefix>, CliError> {
    Ok(identifier
        .find_state(identifier.id())
        .map_err(KeriError::MechanicsError)?
        .witness_config
        .witnesses
        .into_iter()
        .map(IdentifierPrefix::Basic)
        .collect())
}

/// Returns watchers' identifiers of alias
pub fn watcher(identifier: &Identifier) -> Result<Vec<IdentifierPrefix>, CliError> {
    let watchers = identifier.watchers().map_err(KeriError::ControllerError)?;
    Ok(watchers)
}

/// Returns mesagebox' identifiers of alias
pub fn mesagkesto(identifeir: &Identifier) -> Result<Vec<IdentifierPrefix>, CliError> {
    let msgbox = identifeir
        // .source
        .get_end_role(identifeir.id(), keri_core::oobi::Role::Messagebox)
        .map_err(KeriError::ControllerError)?
        .into_iter()
        .map(|b| b.eid)
        .collect();
    Ok(msgbox)
}

pub fn handle_oobi(alias: &str, oobi_command: &Option<OobiRoles>) -> Result<Vec<Oobi>, CliError> {
    let identifier = load(alias)?;

    match oobi_command {
        Some(OobiRoles::Witness) => Ok(find_locations(&identifier, witnesses(&identifier)?)
            .into_iter()
            .map(Oobi::Location)
            .collect()),
        Some(OobiRoles::Watcher) => Ok(find_locations(&identifier, watcher(&identifier)?)
            .into_iter()
            .map(Oobi::Location)
            .collect()),
        Some(OobiRoles::Messagebox) => Ok(find_locations(&identifier, mesagkesto(&identifier)?)
            .into_iter()
            .map(Oobi::Location)
            .collect()),
        None => {
            let witnesses = witnesses(&identifier)?;
            let locations = find_locations(&identifier, witnesses.clone())
                .into_iter()
                .map(Oobi::Location);
            let witnesses_oobi: Vec<Oobi> = witnesses
                .iter()
                .flat_map(|cid| {
                    let mut oobis = vec![Oobi::EndRole(EndRole {
                        eid: cid.clone(),
                        role: keri_core::oobi::Role::Witness,
                        cid: identifier.id().clone(),
                    })];

                    if let Some(reg) = identifier.registry_id() {
                        oobis.push(Oobi::EndRole(EndRole {
                            cid: reg.clone(),
                            role: keri_core::oobi::Role::Witness,
                            eid: cid.clone(),
                        }));
                    }

                    oobis
                })
                .collect();
            Ok(locations.into_iter().chain(witnesses_oobi).collect())
        }
    }
}

pub fn find_locations<I: IntoIterator<Item = IdentifierPrefix>>(
    identifier: &Identifier,
    identifiers: I,
) -> Vec<LocationScheme> {
    identifiers
        .into_iter()
        .flat_map(|id| identifier.get_location(&id).unwrap())
        .collect()
}
