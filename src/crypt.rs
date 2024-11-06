use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::{rngs::OsRng, RngCore};

#[derive(Clone)]
pub(crate) struct EncryptionService {
    cipher: Aes256Gcm,
    pub jwt_secret: String,
}

impl EncryptionService {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("Valid key length");
        Self {
            cipher,
            jwt_secret: "your-secret-key".to_string(),
        }
    }

    pub fn encrypt(&self, data: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Aes256Gcm::generate_nonce(OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, data.as_bytes().as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;
        Ok((BASE64.encode(ciphertext), BASE64.encode(nonce)))
    }

    pub fn decrypt(
        &self,
        encrypted_data: &str,
        nonce_str: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let encrypted_bytes = BASE64.decode(encrypted_data)?;
        let nonce_bytes = BASE64.decode(nonce_str)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(&nonce, &*encrypted_bytes)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        String::from_utf8(plaintext).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use log::debug;

    use super::*;
    fn init() {
        std::env::set_var("RUST_LOG", "debug");
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn en_decryption() {
        init();
        let key = &[42; 32];
        let service = EncryptionService::new(key);

        let test_data = String::from("test_data_string");
        let (encrypted, nonce) = service.encrypt(&test_data).unwrap();

        let decrypted = service.decrypt(&encrypted, &nonce);

        debug!("{:?}", encrypted);
        debug!("{:?}", decrypted);
    }
}
