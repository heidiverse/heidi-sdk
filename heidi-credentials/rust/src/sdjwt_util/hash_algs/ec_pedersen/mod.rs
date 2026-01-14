use base64::Engine;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use next_gen_signatures::BASE64_URL_SAFE_NO_PAD;
use sha2::Sha512;

use crate::sdjwt_util::hash_algs::SdJwtHashAlgorithm;

pub struct EcPedersenX25519 {
    g: RistrettoPoint,
    h: RistrettoPoint,
}

impl Default for EcPedersenX25519 {
    fn default() -> Self {
        Self {
            g: RistrettoPoint::default(),
            h: RistrettoPoint::default(),
        }
    }
}

impl SdJwtHashAlgorithm for EcPedersenX25519 {
    /// The EC Pedersen hash algorithm uses scalars for the sd_hash
    fn sd_hash(&self, data: &[u8]) -> String {
        let scalar = Scalar::hash_from_bytes::<Sha512>(data);
        let scalar_bytes = scalar.to_bytes();
        BASE64_URL_SAFE_NO_PAD.encode(&scalar_bytes)
    }
    /// For the disclosures, we use (blinded) Ristretto points.
    fn disclosure_hash(&self, d: (&crate::sdjwt_util::Disclosure, &str)) -> String {
        let blinding = BASE64_URL_SAFE_NO_PAD.decode(&d.0.salt).unwrap();
        let mut blinding_bytes = [0u8; 32];
        blinding_bytes.copy_from_slice(&blinding);
        let blinding = Scalar::from_bytes_mod_order(blinding_bytes);
        let v: serde_json::Value = (&d.0.value).into();
        match v {
            serde_json::Value::Number(number) => {
                let scalar_number = number.as_i64().unwrap();
                let s = if scalar_number >= 0 {
                    Scalar::from(scalar_number.abs() as u64)
                } else {
                    Scalar::from(scalar_number.abs() as u64).invert()
                };

                let commitment = s * self.g + blinding * self.h;
                BASE64_URL_SAFE_NO_PAD.encode(commitment.compress().as_bytes())
            }
            _ => {
                let serialized_value = serde_json::to_string(&v).unwrap();
                let scalar_hash = Scalar::hash_from_bytes::<Sha512>(serialized_value.as_bytes());
                let commitment = scalar_hash * self.g + blinding * self.h;
                BASE64_URL_SAFE_NO_PAD.encode(commitment.compress().as_bytes())
            }
        }
    }

    fn update_params(&mut self, params: &serde_json::Value) {
        let Some(commitment_scheme) = params.get("commitment_scheme") else {
            return;
        };
        let Some(public_params) = commitment_scheme.get("public_params") else {
            return;
        };
        let Some(g) = public_params
            .get("g")
            .and_then(|a| a.as_str())
            .and_then(|a| BASE64_URL_SAFE_NO_PAD.decode(a).ok())
        else {
            return;
        };
        let Some(h) = public_params
            .get("h")
            .and_then(|a| a.as_str())
            .and_then(|a| BASE64_URL_SAFE_NO_PAD.decode(a).ok())
        else {
            return;
        };
        let Some(g) = CompressedRistretto::from_slice(&g)
            .ok()
            .and_then(|g| g.decompress())
        else {
            return;
        };
        self.g = g;
        let Some(h) = CompressedRistretto::from_slice(&h)
            .ok()
            .and_then(|h| h.decompress())
        else {
            return;
        };
        self.h = h;
    }
}
