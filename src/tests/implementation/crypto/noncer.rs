use crate::interfaces::Noncer as NoncerTrait;
use async_trait::async_trait;
use base64::Engine;
use rand::Rng;

#[derive(Clone)]
pub struct Noncer;

impl Default for Noncer {
    fn default() -> Self {
        Self::new()
    }
}

impl Noncer {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl NoncerTrait for Noncer {
    async fn generate_128(&self) -> Result<String, String> {
        let mut entropy = [0u8; 16];
        rand::thread_rng().fill(&mut entropy);

        // Prepend with 2 zero bytes
        let mut padded = vec![0u8, 0u8];
        padded.extend_from_slice(&entropy);

        // Encode to URL-safe base64
        let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&padded);

        // Return with '0A' prefix (skip first 2 characters of base64)
        Ok(format!("0A{}", &base64[2..]))
    }
}
