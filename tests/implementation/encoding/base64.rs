pub struct Base64;

impl Base64 {
    pub fn encode(data: &[u8]) -> String {
        use base64::Engine;
        let base64 = base64::engine::general_purpose::STANDARD.encode(data);
        // Replace / with _ and + with -
        base64.replace('/', "_").replace('+', "-")
    }

    pub fn decode(base64: &str) -> Result<Vec<u8>, String> {
        use base64::Engine;
        // First try standard base64 decoding
        base64::engine::general_purpose::STANDARD
            .decode(base64)
            .or_else(|_| {
                // If that fails, try URL-safe decoding
                base64::engine::general_purpose::URL_SAFE.decode(base64)
            })
            .map_err(|e| format!("Failed to decode base64: {}", e))
    }
}
