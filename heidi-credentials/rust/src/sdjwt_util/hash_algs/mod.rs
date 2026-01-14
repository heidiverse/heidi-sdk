use std::str::FromStr;

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::sdjwt_util::Disclosure;

pub mod ec_pedersen;
pub mod sha;

pub trait SdJwtHashAlgorithm {
    fn sd_hash(&self, data: &[u8]) -> String;
    fn disclosure_hash(&self, d: (&Disclosure, &str)) -> String;
    fn update_params(&mut self, params: &serde_json::Value);
}

pub struct SdJwtHasher(pub Box<dyn SdJwtHashAlgorithm>);

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
            "sha-256" | "SHA-256" => Ok(SdJwtHasher(Box::new(Sha256::new()))),
            "sha-384" | "SHA-384" => Ok(SdJwtHasher(Box::new(Sha384::new()))),
            "sha-512" | "SHA-512" => Ok(SdJwtHasher(Box::new(Sha512::new()))),
            "ec_pedersen" | "EC_PEDERSEN" => Ok(SdJwtHasher(Box::new(
                ec_pedersen::EcPedersenX25519::default(),
            ))),
            _ => Err(format!("Unsupported hash algorithm: {}", value)),
        }
    }
}
