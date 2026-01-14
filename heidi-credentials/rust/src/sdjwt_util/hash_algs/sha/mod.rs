use base64::Engine;
use next_gen_signatures::BASE64_URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::sdjwt_util::hash_algs::SdJwtHashAlgorithm;

impl SdJwtHashAlgorithm for Sha256 {
    fn sd_hash(&self, data: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(data))
    }

    fn disclosure_hash(&self, d: (&crate::sdjwt_util::Disclosure, &str)) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(d.1.as_bytes()))
    }

    fn update_params(&mut self, _params: &serde_json::Value) {
        // No parameters to update for SHA-256
    }
}
impl SdJwtHashAlgorithm for Sha384 {
    fn sd_hash(&self, data: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha384::digest(data))
    }

    fn disclosure_hash(&self, d: (&crate::sdjwt_util::Disclosure, &str)) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha384::digest(d.1.as_bytes()))
    }
    fn update_params(&mut self, _params: &serde_json::Value) {
        // No parameters to update for SHA-384
    }
}
impl SdJwtHashAlgorithm for Sha512 {
    fn sd_hash(&self, data: &[u8]) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha512::digest(data))
    }

    fn disclosure_hash(&self, d: (&crate::sdjwt_util::Disclosure, &str)) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(Sha512::digest(d.1.as_bytes()))
    }
    fn update_params(&mut self, _params: &serde_json::Value) {
        // No parameters to update for SHA-512
    }
}
