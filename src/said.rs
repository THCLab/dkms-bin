use std::{fs, path::PathBuf};

use indexmap::IndexMap;
use said::{
    derivation::{HashFunction, HashFunctionCode},
    sad::DerivationCode,
};
use thiserror::Error;

use crate::CliError;

#[derive(Error, Debug)]
pub enum SaidError {
    #[error("Missing `d` field in provided json")]
    MissingSaidField,
    #[error("Invalid SAID. {0}")]
    InvalidSaid(said::error::Error),
    #[error("Serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub fn handle_sad(input: &str) -> Result<String, SaidError> {
    let mut map: IndexMap<String, serde_json::Value> = serde_json::from_str(input)?;
    if let Some(_dig) = map.get("d") {
        let code = HashFunctionCode::Blake3_256;
        map["d"] = serde_json::Value::String("#".repeat(code.full_size()));
        let said = HashFunction::from(code).derive(&serde_json::to_vec(&map)?);
        map["d"] = serde_json::Value::String(said.to_string());
        Ok(serde_json::to_string(&map)?)
    } else {
        Err(SaidError::MissingSaidField)
    }
}

#[test]
fn test_json_to_sad() {
    let data = r#"{"hello":"world","d":""}"#;
    let said_inserted = handle_sad(data);

    let to_compute = format!(r#"{{"hello":"world","d":"{}"}}"#, "#".repeat(44));
    let expected_said =
        HashFunction::from(HashFunctionCode::Blake3_256).derive(to_compute.as_bytes());

    let json: serde_json::Value = serde_json::from_str(&said_inserted.unwrap()).unwrap();
    if let Some(serde_json::Value::String(dig)) = json.get("d") {
        assert_eq!(dig, &expected_said.to_string());
    };
}
