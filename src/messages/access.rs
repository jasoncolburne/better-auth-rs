use crate::interfaces::{
    ServerTimeLockStore, Timestamper, TokenEncoder, VerificationKeyStore, Verifier,
};
use crate::messages::{Serializable, Signable};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

// Access Token

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken<T> {
    #[serde(rename = "serverIdentity")]
    pub server_identity: String,
    pub device: String,
    pub identity: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "rotationHash")]
    pub rotation_hash: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    pub expiry: String,
    #[serde(rename = "refreshExpiry")]
    pub refresh_expiry: String,
    pub attributes: T,
    #[serde(skip)]
    pub signature: Option<String>,
}

impl<T: Serialize + Send + Sync> AccessToken<T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_identity: String,
        device: String,
        identity: String,
        public_key: String,
        rotation_hash: String,
        issued_at: String,
        expiry: String,
        refresh_expiry: String,
        attributes: T,
    ) -> Self {
        Self {
            server_identity,
            device,
            identity,
            public_key,
            rotation_hash,
            issued_at,
            expiry,
            refresh_expiry,
            attributes,
            signature: None,
        }
    }

    pub async fn parse(message: &str, token_encoder: &dyn TokenEncoder) -> Result<Self, String>
    where
        T: for<'de> Deserialize<'de>,
    {
        let public_key_length = token_encoder.signature_length(message).await?;

        if message.len() < public_key_length {
            return Err("message too short".to_string());
        }

        let signature = message[..public_key_length].to_string();
        let rest = &message[public_key_length..];

        let token_string = token_encoder.decode(rest).await?;
        let mut token: AccessToken<T> =
            serde_json::from_str(&token_string).map_err(|e| e.to_string())?;
        token.signature = Some(signature);

        Ok(token)
    }

    pub async fn serialize_token(
        &self,
        token_encoder: &dyn TokenEncoder,
    ) -> Result<String, String> {
        let signature = self.signature.as_ref().ok_or("missing signature")?;
        let payload = self.compose_payload()?;
        let token = token_encoder.encode(&payload).await?;
        Ok(format!("{}{}", signature, token))
    }

    pub async fn verify_token(
        &self,
        verifier: &dyn Verifier,
        public_key: &str,
        timestamper: &dyn Timestamper,
    ) -> Result<(), String> {
        self.verify(verifier, public_key).await?;

        let now = timestamper.now();
        let issued_at = timestamper.parse(&self.issued_at)?;
        let expiry = timestamper.parse(&self.expiry)?;

        if timestamper.compare(now, issued_at) == Ordering::Less {
            return Err("token from future".to_string());
        }

        if timestamper.compare(now, expiry) == Ordering::Greater {
            return Err("token expired".to_string());
        }

        Ok(())
    }
}

#[async_trait]
impl<T: Serialize + Send + Sync> Serializable for AccessToken<T> {
    async fn to_json(&self) -> Result<String, String> {
        if self.signature.is_none() {
            return Err("null signature".to_string());
        }
        serde_json::to_string(self).map_err(|e| e.to_string())
    }
}

#[async_trait]
impl<T: Serialize + Send + Sync> Signable for AccessToken<T> {
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
        #[derive(Serialize)]
        struct Payload<'a, T> {
            #[serde(rename = "serverIdentity")]
            server_identity: &'a str,
            device: &'a str,
            identity: &'a str,
            #[serde(rename = "publicKey")]
            public_key: &'a str,
            #[serde(rename = "rotationHash")]
            rotation_hash: &'a str,
            #[serde(rename = "issuedAt")]
            issued_at: &'a str,
            expiry: &'a str,
            #[serde(rename = "refreshExpiry")]
            refresh_expiry: &'a str,
            attributes: &'a T,
        }

        let payload = Payload {
            server_identity: &self.server_identity,
            device: &self.device,
            identity: &self.identity,
            public_key: &self.public_key,
            rotation_hash: &self.rotation_hash,
            issued_at: &self.issued_at,
            expiry: &self.expiry,
            refresh_expiry: &self.refresh_expiry,
            attributes: &self.attributes,
        };

        serde_json::to_string(&payload).map_err(|e| e.to_string())
    }
}

// Access Request

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequestAccess {
    pub nonce: String,
    pub timestamp: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequestPayload<T> {
    pub access: AccessRequestAccess,
    pub request: T,
}

// Helper struct for parsing that keeps request as raw JSON
#[derive(Deserialize)]
struct AccessRequestRaw {
    payload: AccessRequestPayloadRaw,
    signature: Option<String>,
}

#[derive(Deserialize)]
struct AccessRequestPayloadRaw {
    access: AccessRequestAccess,
    request: Box<serde_json::value::RawValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest<T> {
    pub payload: AccessRequestPayload<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip)]
    original_request_string: Option<String>,
}

impl<T: Serialize + Send + Sync> AccessRequest<T> {
    pub fn new(payload: AccessRequestPayload<T>) -> Self {
        Self {
            payload,
            signature: None,
            original_request_string: None,
        }
    }

    pub fn parse(message: &str) -> Result<Self, String>
    where
        T: for<'de> Deserialize<'de>,
    {
        // First parse with RawValue to capture the original request string
        let raw: AccessRequestRaw = serde_json::from_str(message).map_err(|e| e.to_string())?;
        let original_request_string = raw.payload.request.get().to_string();

        // Now parse normally
        let mut request: Self = serde_json::from_str(message).map_err(|e| e.to_string())?;
        request.original_request_string = Some(original_request_string);

        Ok(request)
    }

    pub async fn verify_access<U>(
        &self,
        nonce_store: &dyn ServerTimeLockStore,
        verifier: &dyn Verifier,
        access_key_store: &dyn VerificationKeyStore,
        token_encoder: &dyn TokenEncoder,
        timestamper: &dyn Timestamper,
    ) -> Result<AccessToken<U>, String>
    where
        U: for<'de> Deserialize<'de> + Serialize + Send + Sync,
    {
        let access_token: AccessToken<U> =
            AccessToken::parse(&self.payload.access.token, token_encoder).await?;

        let access_key = access_key_store.get(&access_token.server_identity).await?;
        let public_key = access_key.public().await?;

        access_token
            .verify_token(access_key.verifier(), &public_key, timestamper)
            .await?;
        self.verify(verifier, &access_token.public_key).await?;

        let now = timestamper.now();
        let access_time = timestamper.parse(&self.payload.access.timestamp)?;
        let expiry = timestamper.add_seconds(access_time, nonce_store.lifetime_in_seconds());

        if timestamper.compare(now, expiry) == Ordering::Greater {
            return Err("stale request".to_string());
        }

        if timestamper.compare(now, access_time) == Ordering::Less {
            return Err("request from future".to_string());
        }

        nonce_store
            .reserve(self.payload.access.nonce.clone())
            .await?;

        Ok(access_token)
    }
}

#[async_trait]
impl<T: Serialize + Send + Sync> Serializable for AccessRequest<T> {
    async fn to_json(&self) -> Result<String, String> {
        if self.signature.is_none() {
            return Err("null signature".to_string());
        }
        serde_json::to_string(self).map_err(|e| e.to_string())
    }
}

#[async_trait]
impl<T: Serialize + Send + Sync> Signable for AccessRequest<T> {
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
        // Use the original request string if we have it, otherwise re-serialize
        let request_str = if let Some(ref original) = self.original_request_string {
            original.clone()
        } else {
            serde_json::to_string(&self.payload.request).map_err(|e| e.to_string())?
        };

        // Build the payload with the original request string preserved
        let payload_string = format!(
            r#"{{"access":{{"nonce":"{}","timestamp":"{}","token":"{}"}},"request":{}}}"#,
            self.payload.access.nonce,
            self.payload.access.timestamp,
            self.payload.access.token,
            request_str
        );

        Ok(payload_string)
    }
}
