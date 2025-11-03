use crate::error::BetterAuthError;
use crate::invalid_message_error;
use crate::messages::{Serializable, Signable};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAccess {
    pub nonce: String,
    #[serde(rename = "serverIdentity")]
    pub server_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPayload<T> {
    pub access: ServerAccess,
    pub response: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse<T> {
    pub payload: ServerPayload<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl<T: Serialize + Send + Sync> ServerResponse<T> {
    pub fn new(response: T, server_identity: String, nonce: String) -> Self {
        Self {
            payload: ServerPayload {
                access: ServerAccess {
                    nonce,
                    server_identity,
                },
                response,
            },
            signature: None,
        }
    }

    pub fn parse(message: &str) -> Result<Self, BetterAuthError>
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_str(message)
            .map_err(|e| invalid_message_error(Some("message"), Some(&e.to_string())))
    }
}

#[async_trait]
impl<T: Serialize + Send + Sync> Serializable for ServerResponse<T> {
    async fn to_json(&self) -> Result<String, BetterAuthError> {
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
impl<T: Serialize + Send + Sync> Signable for ServerResponse<T> {
    fn get_payload(&self) -> Option<&serde_json::Value> {
        None
    }

    fn get_signature(&self) -> Option<&String> {
        self.signature.as_ref()
    }

    fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }

    fn compose_payload(&self) -> Result<String, BetterAuthError> {
        serde_json::to_string(&self.payload)
            .map_err(|e| invalid_message_error(Some("payload_serialization"), Some(&e.to_string())))
    }
}

// Scannable response for generic responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannableResponseData {}

pub type ScannableResponse = ServerResponse<ScannableResponseData>;
