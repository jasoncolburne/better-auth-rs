use crate::interfaces::{SigningKey, Verifier};
use crate::invalid_message_error;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait Serializable: Send + Sync {
    async fn to_json(&self) -> Result<String, String>;
}

#[async_trait]
pub trait Signable: Serializable {
    fn get_payload(&self) -> Option<&serde_json::Value>;
    fn get_signature(&self) -> Option<&String>;
    fn set_signature(&mut self, signature: String);

    fn compose_payload(&self) -> Result<String, String>;

    async fn sign(&mut self, signer: &dyn SigningKey) -> Result<(), String> {
        let payload = self.compose_payload()?;
        let signature = signer.sign(&payload).await?;
        self.set_signature(signature);
        Ok(())
    }

    async fn verify(&self, verifier: &dyn Verifier, public_key: &str) -> Result<(), String> {
        let signature = self
            .get_signature()
            .ok_or(invalid_message_error(Some("signature"), Some("null signature")).to_string())?;

        let payload = self.compose_payload()?;

        verifier.verify(&payload, signature, public_key).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignableMessageBase {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl SignableMessageBase {
    pub fn new(payload: Option<serde_json::Value>) -> Self {
        Self {
            payload,
            signature: None,
        }
    }
}
