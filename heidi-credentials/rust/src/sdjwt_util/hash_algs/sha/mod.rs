use base64::Engine;
use next_gen_signatures::BASE64_URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::sdjwt_util::hash_algs::SdJwtHashAlgorithm;

impl SdJwtHashAlgorithm for Sha256 {
    fn sd_hash(&self, data: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(data))
    }

    fn disclosure_hash(&self, d: &crate::sdjwt_util::Disclosure) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(d.enc.as_bytes()))
    }

    fn update_params(&mut self, _params: &serde_json::Value) {
        // No parameters to update for SHA-256
    }
    fn sd_alg_params(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
    fn sd_alg(&self) -> serde_json::Value {
        serde_json::json!("sha-256")
    }
}
impl SdJwtHashAlgorithm for Sha384 {
    fn sd_hash(&self, data: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha384::digest(data))
    }

    fn disclosure_hash(&self, d: &crate::sdjwt_util::Disclosure) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha384::digest(d.enc.as_bytes()))
    }
    fn update_params(&mut self, _params: &serde_json::Value) {
        // No parameters to update for SHA-384
    }
    fn sd_alg_params(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
    fn sd_alg(&self) -> serde_json::Value {
        serde_json::json!("sha-384")
    }
}
impl SdJwtHashAlgorithm for Sha512 {
    fn sd_hash(&self, data: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha512::digest(data))
    }

    fn disclosure_hash(&self, d: &crate::sdjwt_util::Disclosure) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha512::digest(d.enc.as_bytes()))
    }
    fn update_params(&mut self, _params: &serde_json::Value) {
        // No parameters to update for SHA-512
    }
    fn sd_alg_params(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
    fn sd_alg(&self) -> serde_json::Value {
        serde_json::json!("sha-512")
    }
}
