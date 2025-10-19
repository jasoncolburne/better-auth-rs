use crate::messages::{ClientRequest, ServerResponse};
use serde::{Deserialize, Serialize};

// Change Recovery Key

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecoveryKeyAuthentication {
    pub device: String,
    pub identity: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "recoveryHash")]
    pub recovery_hash: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecoveryKeyRequestData {
    pub authentication: ChangeRecoveryKeyAuthentication,
}

pub type ChangeRecoveryKeyRequest = ClientRequest<ChangeRecoveryKeyRequestData>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecoveryKeyResponseData {}

pub type ChangeRecoveryKeyResponse = ServerResponse<ChangeRecoveryKeyResponseData>;
