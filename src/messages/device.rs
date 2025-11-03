use crate::error::BetterAuthError;
use crate::invalid_message_error;
use crate::messages::{ClientRequest, Serializable, ServerResponse, Signable};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// Link Container

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkContainerAuthentication {
    pub device: String,
    pub identity: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkContainerPayload {
    pub authentication: LinkContainerAuthentication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkContainer {
    pub payload: LinkContainerPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl LinkContainer {
    pub fn new(payload: LinkContainerPayload) -> Self {
        Self {
            payload,
            signature: None,
        }
    }

    pub fn parse(message: &str) -> Result<Self, BetterAuthError> {
        serde_json::from_str(message)
            .map_err(|e| invalid_message_error(Some("message"), Some(&e.to_string())))
    }
}

#[async_trait]
impl Serializable for LinkContainer {
    type Error = BetterAuthError;

    async fn to_json(&self) -> Result<String, Self::Error> {
        if self.signature.is_none() {
            return Err(invalid_message_error(
                Some("signature"),
                Some("null signature"),
            ));
        }
        serde_json::to_string(self)
            .map_err(|e| invalid_message_error(Some("serialization"), Some(&e.to_string())))
    }
}

#[async_trait]
impl Signable for LinkContainer {
    fn get_payload(&self) -> Option<&serde_json::Value> {
        None
    }

    fn get_signature(&self) -> Option<&String> {
        self.signature.as_ref()
    }

    fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }

    fn compose_payload(&self) -> Result<String, Self::Error> {
        serde_json::to_string(&self.payload)
            .map_err(|e| invalid_message_error(Some("payload_serialization"), Some(&e.to_string())))
    }
}

// Link Device

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkDeviceAuthentication {
    pub device: String,
    pub identity: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkDeviceRequestData {
    pub authentication: LinkDeviceAuthentication,
    pub link: LinkContainer,
}

pub type LinkDeviceRequest = ClientRequest<LinkDeviceRequestData>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkDeviceResponseData {}

pub type LinkDeviceResponse = ServerResponse<LinkDeviceResponseData>;

// Unlink Device

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlinkDeviceAuthentication {
    pub device: String,
    pub identity: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlinkDeviceLink {
    pub device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlinkDeviceRequestData {
    pub authentication: UnlinkDeviceAuthentication,
    pub link: UnlinkDeviceLink,
}

pub type UnlinkDeviceRequest = ClientRequest<UnlinkDeviceRequestData>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlinkDeviceResponseData {}

pub type UnlinkDeviceResponse = ServerResponse<UnlinkDeviceResponseData>;

// Rotate Device

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateDeviceAuthentication {
    pub device: String,
    pub identity: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateDeviceRequestData {
    pub authentication: RotateDeviceAuthentication,
}

pub type RotateDeviceRequest = ClientRequest<RotateDeviceRequestData>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateDeviceResponseData {}

pub type RotateDeviceResponse = ServerResponse<RotateDeviceResponseData>;
