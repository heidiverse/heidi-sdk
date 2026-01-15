use base64::Engine;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use next_gen_signatures::BASE64_URL_SAFE_NO_PAD;
use sha2::Sha512;
pub mod canonicalize;

use crate::sdjwt_util::hash_algs::{
    ec_pedersen::canonicalize::{canonicalize_object, stringify_value},
    SdJwtHashAlgorithm,
};

pub struct EcPedersenX25519 {
    g: RistrettoPoint,
    h: RistrettoPoint,
}

impl Default for EcPedersenX25519 {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            g: RistrettoPoint::random(&mut rng),
            h: RistrettoPoint::random(&mut rng),
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
    fn disclosure_hash(&self, d: &crate::sdjwt_util::Disclosure) -> String {
        let blinding = BASE64_URL_SAFE_NO_PAD.decode(&d.salt).unwrap();
        let mut blinding_bytes = [0u8; 32];
        blinding_bytes.copy_from_slice(&blinding);
        let blinding = Scalar::from_bytes_mod_order(blinding_bytes);
        let v: serde_json::Value = (&d.value).into();
        match v {
            //TODO: UBAM how can we handle floats?
            serde_json::Value::Number(number) if !number.is_f64() => {
                let scalar_number = number.as_i128().unwrap();
                let s = if scalar_number >= 0 {
                    Scalar::from(scalar_number.abs() as u64)
                } else {
                    Scalar::from(scalar_number.abs() as u64).invert()
                };

                let commitment = s * self.g + blinding * self.h;
                BASE64_URL_SAFE_NO_PAD.encode(commitment.compress().as_bytes())
            }
            _ => {
                let serialized_value = stringify_value(&d.value);
                let scalar_hash = Scalar::hash_from_bytes::<Sha512>(serialized_value.as_bytes());
                let commitment = scalar_hash * self.g + blinding * self.h;
                BASE64_URL_SAFE_NO_PAD.encode(commitment.compress().as_bytes())
            }
        }
    }

    fn update_params(&mut self, params: &serde_json::Value) {
        println!("{:?}", params);
        let Some(commitment_scheme) = params.get("commitment_scheme") else {
            return;
        };
        let Some(public_params) = commitment_scheme.get("public_params") else {
            return;
        };
        println!("set g to: {:?}", public_params.get("g"));
        println!("set h to: {:?}", public_params.get("h"));
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
    fn sd_alg_params(&self) -> serde_json::Value {
        serde_json::json!({
            "commitment_scheme": {
                "public_params": {
                    "g": BASE64_URL_SAFE_NO_PAD.encode(self.g.compress().as_bytes()),
                    "h": BASE64_URL_SAFE_NO_PAD.encode(self.h.compress().as_bytes())
                },
                "crv" : "ed25519"
            }
        })
    }

    fn sd_alg(&self) -> serde_json::Value {
        serde_json::json!("ec_pedersen")
    }
}
