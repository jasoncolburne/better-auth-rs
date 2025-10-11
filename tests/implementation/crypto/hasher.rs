use async_trait::async_trait;
use better_auth::interfaces::Hasher as HasherTrait;

#[derive(Clone)]
pub struct Hasher;

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl HasherTrait for Hasher {
    async fn sum(&self, message: &str) -> Result<String, String> {
        use base64::Engine;
        use blake3::Hasher as Blake3Hasher;

        let hash = Blake3Hasher::new().update(message.as_bytes()).finalize();
        let hash_bytes = hash.as_bytes();

        // Prepend with a 0 byte
        let mut padded = vec![0u8];
        padded.extend_from_slice(hash_bytes);

        // Encode to URL-safe base64
        let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&padded);

        // Return with 'E' prefix (skip first character of base64)
        Ok(format!("E{}", &base64[1..]))
    }
}
