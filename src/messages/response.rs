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

    pub fn parse(message: &str) -> Result<Self, String>
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_str(message).map_err(|e| e.to_string())
    }
}

#[async_trait]
impl<T: Serialize + Send + Sync> Serializable for ServerResponse<T> {
    async fn to_json(&self) -> Result<String, String> {
        if self.signature.is_none() {
            return Err("null signature".to_string());
        }
        serde_json::to_string(self).map_err(|e| e.to_string())
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

    fn compose_payload(&self) -> Result<String, String> {
        serde_json::to_string(&self.payload).map_err(|e| e.to_string())
    }
}

// Scannable response for generic responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannableResponseData {}

pub type ScannableResponse = ServerResponse<ScannableResponseData>;
