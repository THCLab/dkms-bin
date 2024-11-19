use std::fmt::Display;

use serde::Serialize;

use crate::verify::{ACDCState, VerifyHandleError};

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum VerificationStatus {
    Ok { description: String },
    Error { description: String },
    Invalid { description: String },
}

impl From<ACDCState> for VerificationStatus {
    fn from(value: ACDCState) -> Self {
        match value {
            ACDCState::VerificationSuccess => VerificationStatus::Ok {
                description: "Verification success".to_string(),
            },
            ACDCState::Issued => VerificationStatus::Ok {
                description: "ACDC issued".to_string(),
            },
            ACDCState::Revoked => VerificationStatus::Ok {
                description: "ACDC revoked".to_string(),
            },
            ACDCState::NotFound => VerificationStatus::Error {
                description: "ACDC state not found".to_string(),
            },
        }
    }
}

impl From<VerifyHandleError> for VerificationStatus {
    fn from(value: VerifyHandleError) -> Self {
        VerificationStatus::Error {
            description: value.to_string(),
        }
    }
}

impl Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}
