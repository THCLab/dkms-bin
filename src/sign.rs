use crate::{
    keri::KeriError,
    utils::{ed25519_sig, load, load_group_id, load_signer},
    CliError,
};

pub fn handle_sign(alias: String, data: &str) -> Result<String, CliError> {
    // check if provided string is valid json
    if let Err(_err) = serde_json::from_str::<serde_json::Value>(data) {
        return Err(CliError::JsonExpected);
    };
    let cont = load(&alias)?;
    let sk = load_signer(&alias)?;

    let signature = ed25519_sig(&sk, data.as_bytes()).map_err(KeriError::SigningError)?;
    Ok(cont.sign_to_cesr(data, &[signature]).map_err(KeriError::Sdk)?)
}

pub fn handle_group_sign(alias: String, group_alias: &str, data: &str) -> Result<String, CliError> {
    // check if provided string is valid json
    if let Err(_err) = serde_json::from_str::<serde_json::Value>(data) {
        return Err(CliError::JsonExpected);
    };
    let cont = load_group_id(&alias, group_alias)?;

    let sk = load_signer(&alias)?;

    let signature = ed25519_sig(&sk, data.as_bytes()).map_err(KeriError::SigningError)?;
    Ok(cont.sign_to_cesr(data, &[signature]).map_err(KeriError::Sdk)?)
}
