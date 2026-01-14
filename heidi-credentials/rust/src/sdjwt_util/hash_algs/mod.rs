use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::sdjwt_util::Disclosure;

pub mod ec_pedersen;
pub mod sha;

pub trait SdJwtHashAlgorithm: Send + Sync {
    fn sd_hash(&self, data: &[u8]) -> String;
    fn disclosure_hash(&self, d: &Disclosure) -> String;
    fn update_params(&mut self, params: &serde_json::Value);
    fn sd_alg_params(&self) -> serde_json::Value;
    fn sd_alg(&self) -> serde_json::Value;
}

#[derive(uniffi::Object)]
pub struct SdJwtHasher(pub Arc<Mutex<dyn SdJwtHashAlgorithm>>);
#[uniffi::export]
impl SdJwtHasher {
    #[uniffi::constructor]
    //TODO UBAM: make fallible
    pub fn from_str(s: &str) -> Self {
        s.try_into().unwrap()
    }
    pub fn sd_alg_params(&self) -> heidi_util_rust::value::Value {
        let hasher = self.0.lock().unwrap();
        hasher.sd_alg_params().into()
    }
    pub fn sd_alg(&self) -> heidi_util_rust::value::Value {
        let hasher = self.0.lock().unwrap();
        hasher.sd_alg().into()
    }
    pub fn hash(
        &self,
        enc: String,
        salt: String,
        attr_name: Option<String>,
        value: heidi_util_rust::value::Value,
    ) -> String {
        let hasher = self.0.lock().unwrap();
        hasher.disclosure_hash(&Disclosure {
            salt,
            key: attr_name,
            value,
            enc,
        })
    }
    pub fn generated_blinding(&self, seed: String) -> String {
        let hasher = self.0.lock().unwrap();
        hasher.sd_hash(seed.as_bytes())
    }
}

impl FromStr for SdJwtHasher {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl TryFrom<&str> for SdJwtHasher {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "sha-256" | "SHA-256" => Ok(SdJwtHasher(Arc::new(Mutex::new(Sha256::new())))),
            "sha-384" | "SHA-384" => Ok(SdJwtHasher(Arc::new(Mutex::new(Sha384::new())))),
            "sha-512" | "SHA-512" => Ok(SdJwtHasher(Arc::new(Mutex::new(Sha512::new())))),
            "ec_pedersen" | "EC_PEDERSEN" => Ok(SdJwtHasher(Arc::new(Mutex::new(
                ec_pedersen::EcPedersenX25519::default(),
            )))),
            _ => Err(format!("Unsupported hash algorithm: {}", value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
    use next_gen_signatures::BASE64_URL_SAFE_NO_PAD;

    #[test]
    fn test_scalar() {
        let s_orig = "8fxy-AuCVCGHUJOBjCdtUi63eiqwEF1KTn-rQVJxFAE";
        let s = BASE64_URL_SAFE_NO_PAD.decode(s_orig).unwrap();
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&s);
        let s = Scalar::from_bytes_mod_order(s_bytes);
        let s_new = s.to_bytes();
        let s_new = BASE64_URL_SAFE_NO_PAD.encode(s_new);
        assert_eq!(s_orig, s_new);
    }
    #[test]
    fn test_c() {
        let g = "0MxP_Q-JG1weVun9iHZnx8-iGOKelJfi_b738p2NvCQ";
        let h = "fJGj5gmh0YV_CwVmk4XMwz_lso8kfE9u2j-pQCdVbnA";
        let g = BASE64_URL_SAFE_NO_PAD.decode(&g).unwrap();
        let h = BASE64_URL_SAFE_NO_PAD.decode(&h).unwrap();
        let g = CompressedRistretto::from_slice(&g)
            .unwrap()
            .decompress()
            .unwrap();
        let h = CompressedRistretto::from_slice(&h)
            .unwrap()
            .decompress()
            .unwrap();
        let s_orig = "8fxy-AuCVCGHUJOBjCdtUi63eiqwEF1KTn-rQVJxFAE";
        let s = BASE64_URL_SAFE_NO_PAD.decode(s_orig).unwrap();
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&s);
        let blinding = Scalar::from_bytes_mod_order(s_bytes);
        let hash = "zASHotSMSziIPhGqHR3gEh2xC74qRzt5mknHUhz8T3o";
        let value: Scalar = (1958u16).into();
        let commitment = value * g + blinding * h;
        let b = commitment.compress().to_bytes();
        println!("C: {}", hash);
        assert_eq!(hash, BASE64_URL_SAFE_NO_PAD.encode(b));
    }
}
