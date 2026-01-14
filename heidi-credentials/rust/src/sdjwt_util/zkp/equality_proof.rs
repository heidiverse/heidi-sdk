use base64::Engine;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use next_gen_signatures::BASE64_URL_SAFE_NO_PAD;
use sha2::Sha512;

use crate::sdjwt::SdJwtRust;

pub struct EqualityProof {
    s1: Scalar,
    r1: Scalar,
    s2: Scalar,
    r2: Scalar,
    com1: RistrettoPoint,
    com2: RistrettoPoint,
}

impl EqualityProof {
    pub fn from_sdjwts(
        attr: &str,
        sd_jwt1: &SdJwtRust,
        sd_jwt2: &SdJwtRust,
        nonce: Vec<u8>,
    ) -> Option<Self> {
        let mut rng = rand::thread_rng();

        let Some((_, dis1)) = sd_jwt1
            .disclosures_map
            .iter()
            .find(|a| a.1.key.as_deref().map(|key| key == attr).unwrap_or(false))
        else {
            return None;
        };
        let Some((_, dis2)) = sd_jwt2
            .disclosures_map
            .iter()
            .find(|a| a.1.key.as_deref().map(|key| key == attr).unwrap_or(false))
        else {
            return None;
        };
        let disclosure1_value = (&dis1.value).into();
        let disclosure2_value = (&dis2.value).into();

        let mut blinding1_bytes: [u8; 32] = [0; 32];
        blinding1_bytes.copy_from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&dis1.salt).unwrap());
        let blinding1 = Scalar::from_bytes_mod_order(blinding1_bytes);
        let mut blinding2_bytes: [u8; 32] = [0; 32];
        blinding2_bytes.copy_from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&dis2.salt).unwrap());
        let blinding2 = Scalar::from_bytes_mod_order(blinding2_bytes);

        let value1 = match disclosure1_value {
            serde_json::Value::Number(number) => {
                let scalar_number = number.as_i64().unwrap();
                if scalar_number >= 0 {
                    Scalar::from(scalar_number.abs() as u64)
                } else {
                    Scalar::from(scalar_number.abs() as u64).invert()
                }
            }
            _ => {
                let serialized_value = serde_json::to_string(&dis1.value).unwrap();
                Scalar::hash_from_bytes::<Sha512>(serialized_value.as_bytes())
            }
        };

        let value2 = match disclosure2_value {
            serde_json::Value::Number(number) => {
                let scalar_number = number.as_i64().unwrap();
                if scalar_number >= 0 {
                    Scalar::from(scalar_number.abs() as u64)
                } else {
                    Scalar::from(scalar_number.abs() as u64).invert()
                }
            }
            _ => {
                let serialized_value = serde_json::to_string(&dis2.value).unwrap();
                Scalar::hash_from_bytes::<Sha512>(serialized_value.as_bytes())
            }
        };

        let g1 = sd_jwt1
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("g")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let h1 = sd_jwt1
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("h")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        let g1 = BASE64_URL_SAFE_NO_PAD.decode(g1).unwrap();
        let h1 = BASE64_URL_SAFE_NO_PAD.decode(h1).unwrap();

        let g2 = sd_jwt2
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("g")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let h2 = sd_jwt2
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("h")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();

        let g2 = BASE64_URL_SAFE_NO_PAD.decode(g2).unwrap();
        let h2 = BASE64_URL_SAFE_NO_PAD.decode(h2).unwrap();
        let mut challenge_bytes = vec![];
        challenge_bytes.extend_from_slice(attr.as_bytes());
        challenge_bytes.extend_from_slice(&g1);
        challenge_bytes.extend_from_slice(&h1);
        challenge_bytes.extend_from_slice(&g2);
        challenge_bytes.extend_from_slice(&h2);
        challenge_bytes.extend_from_slice(&nonce);

        let g1 = CompressedRistretto::from_slice(&g1)
            .unwrap()
            .decompress()
            .unwrap();
        let h1 = CompressedRistretto::from_slice(&h1)
            .unwrap()
            .decompress()
            .unwrap();
        let g2 = CompressedRistretto::from_slice(&g2)
            .unwrap()
            .decompress()
            .unwrap();
        let h2 = CompressedRistretto::from_slice(&h2)
            .unwrap()
            .decompress()
            .unwrap();
        let rand_x1 = Scalar::random(&mut rng);
        let rand_y1 = Scalar::random(&mut rng);
        let random_com1 = rand_x1 * g1 + rand_y1 * h1;

        let rand_y2 = Scalar::random(&mut rng);
        let random_com2 = rand_x1 * g2 + rand_y2 * h2;
        let challenge = Scalar::hash_from_bytes::<Sha512>(&challenge_bytes);

        let s1 = rand_x1 - challenge * value1;
        let r1 = rand_y1 - challenge * blinding1;
        let s2 = rand_x1 - challenge * value2;
        let r2 = rand_y2 - challenge * blinding2;

        Some(EqualityProof {
            s1,
            r1,
            s2,
            r2,
            com1: random_com1,
            com2: random_com2,
        })
    }
    pub fn verify(
        &self,
        context: Vec<u8>,
        attr: &str,
        sd_jwt1: &SdJwtRust,
        sd_jwt2: &SdJwtRust,
    ) -> bool {
        let relevant_commitment = sd_jwt1
            .claims
            .get("com_link")
            .unwrap()
            .get(attr)
            .unwrap()
            .as_i64()
            .cloned()
            .unwrap();
        let c1 = sd_jwt1
            .claims
            .get("_sd")
            .unwrap()
            .get(relevant_commitment as usize)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let c2 = sd_jwt2
            .claims
            .get("_sd")
            .unwrap()
            .get(relevant_commitment as usize)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let c1 = CompressedRistretto::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(c1).unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        let c2 = CompressedRistretto::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(c2).unwrap())
            .unwrap()
            .decompress()
            .unwrap();

        let g1 = sd_jwt1
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("g")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let h1 = sd_jwt1
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("h")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let g1 = CompressedRistretto::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&g1).unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        let h1 = CompressedRistretto::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&h1).unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        let g2 = sd_jwt2
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("g")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let h2 = sd_jwt2
            .claims
            .get("_sd_alg_param")
            .unwrap()
            .get("commitment_scheme")
            .unwrap()
            .get("public_params")
            .unwrap()
            .get("h")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let g2 = CompressedRistretto::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&g2).unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        let h2 = CompressedRistretto::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&h2).unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        let challenge = Scalar::hash_from_bytes::<Sha512>(&context);

        let verify1 = self.s1 * g1 + self.r1 * h1 + challenge * c1;
        let verify2 = self.s2 * g2 + self.r2 * h2 + challenge * c2;
        println!("{}", verify1 == self.com1);
        println!("{}", verify2 == self.com2);
        println!("{}", self.s1 == self.s2);
        verify1 == self.com1 && verify2 == self.com2 && self.s1 == self.s2
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.s1.to_bytes());
        bytes.extend_from_slice(&self.r1.to_bytes());
        bytes.extend_from_slice(&self.s2.to_bytes());
        bytes.extend_from_slice(&self.r2.to_bytes());
        bytes.extend_from_slice(self.com1.compress().as_bytes());
        bytes.extend_from_slice(self.com2.compress().as_bytes());
        bytes
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let s1 = Scalar::from_bytes_mod_order(bytes[0..32].try_into().unwrap());
        let r1 = Scalar::from_bytes_mod_order(bytes[32..64].try_into().unwrap());
        let s2 = Scalar::from_bytes_mod_order(bytes[64..96].try_into().unwrap());
        let r2 = Scalar::from_bytes_mod_order(bytes[96..128].try_into().unwrap());
        let com1 = CompressedRistretto::from_slice(bytes[128..160].try_into().unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        let com2 = CompressedRistretto::from_slice(bytes[160..192].try_into().unwrap())
            .unwrap()
            .decompress()
            .unwrap();

        EqualityProof {
            s1,
            r1,
            s2,
            r2,
            com1,
            com2,
        }
    }
}
