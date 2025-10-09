use crate::messages::{Serializable, Signable};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAccess {
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPayload<T> {
    pub access: ClientAccess,
    pub request: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRequest<T> {
    pub payload: ClientPayload<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl<T: Serialize + Send + Sync> ClientRequest<T> {
    pub fn new(request: T, nonce: String) -> Self {
        Self {
            payload: ClientPayload {
                access: ClientAccess { nonce },
                request,
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
impl<T: Serialize + Send + Sync> Serializable for ClientRequest<T> {
    async fn to_json(&self) -> Result<String, String> {
        if self.signature.is_none() {
            return Err("null signature".to_string());
        }
        serde_json::to_string(self).map_err(|e| e.to_string())
    }
}

#[async_trait]
impl<T: Serialize + Send + Sync> Signable for ClientRequest<T> {
    fn get_payload(&self) -> Option<&serde_json::Value> {
        None // We'll use compose_payload instead
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
