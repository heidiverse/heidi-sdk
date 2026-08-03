/* Copyright 2024 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use crate::error::SigningError;
use crate::get_reqwest_client;
use crate::hsm::{build_wallet_attestation_pop, format_wallet_attestation_pop};
use crate::signing::NativeSigner;
use crate::util::generate_uuid_v4;
use crate::ApiError;
use anyhow::anyhow;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct WalletBackend {
    client: ClientWithMiddleware,
    base_url: String,
    cached_wallet_attestations: Mutex<HashMap<Vec<u8>, String>>,
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl WalletBackend {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    /// Construct a new Wallet Backend API Client
    ///
    /// SAFETY:
    /// It is ok to unwrap, since our builders never panic
    pub fn new(base_url: String) -> Self {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(1);
        let client = ClientBuilder::new(get_reqwest_client().build().unwrap())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        return Self {
            client,
            base_url,
            cached_wallet_attestations: Mutex::new(HashMap::new()),
        };
    }

    pub async fn get_wallet_attestation(
        self: &Arc<Self>,
        key: Arc<dyn NativeSigner>,
    ) -> Result<String, ApiError> {
        {
            let cache = self.cached_wallet_attestations.lock()?;
            if let Some(cached_attestation) = cache.get(&key.public_key()) {
                return Ok(cached_attestation.clone());
            }
        }

        let wallet_attestation = self.get_new_wallet_attestation(&key).await?;

        {
            let mut cache = self.cached_wallet_attestations.lock()?;
            cache.insert(key.public_key(), wallet_attestation.clone());
        }

        Ok(wallet_attestation)
    }

    async fn get_new_wallet_attestation(
        self: &Arc<Self>,
        key: &Arc<dyn NativeSigner>,
    ) -> Result<String, ApiError> {
        if key.alg() != "ES256" {
            return Err(anyhow::anyhow!(
                "invalid signer for wallet attestion, expecting ES256 (SHA256 with P256 ECDSA)"
            )
            .into());
        }
        if key.public_key().len() != 1 + 2 * 32 {
            return Err(anyhow::anyhow!("invalid signer for wallet attestion, wallet backend does not support key compression").into());
        }

        // Note: UUID is expected for the attestation/start endpoint, but it's not really used for the
        // flow with a device bound key -- it would only be used for the HSM bound key flow.
        let uuid = generate_uuid_v4();

        let nonce_response: Value = self
            .client
            .post(format!("{}/attestation/start", self.base_url))
            .json(&json!({"uuid": uuid}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let Some(Value::String(nonce)) = nonce_response.get("pinNonce") else {
            return Err(anyhow!("pinNonce not found").into());
        };

        // sign nonce as proof of posession
        let decoded_nonce = BASE64_URL_SAFE_NO_PAD.decode(nonce)?;
        let signed_nonce = key.sign_bytes(decoded_nonce)?;

        let response: Value = self
            .client
            .post(format!(
                "{}/attestation/finalize-device-bound",
                self.base_url
            ))
            .json(&json!({
                "walletSignedNonce": BASE64_URL_SAFE_NO_PAD.encode(signed_nonce),
                "pinNonce": nonce,
                "devicePub": BASE64_URL_SAFE_NO_PAD.encode(key.public_key()),
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let Some(Value::String(wallet_attestation)) = response.get("walletAttestation") else {
            return Err(anyhow!("walletAttestation not found").into());
        };

        Ok(wallet_attestation.clone())
    }

    pub fn generate_wallet_attestation_pop(
        self: &Arc<Self>,
        key: Arc<dyn NativeSigner>,
        client_id: String,
        credential_issuer_url: String,
        nonce: Option<String>,
    ) -> Result<String, ApiError> {
        let encoded_pop = build_wallet_attestation_pop(client_id, credential_issuer_url, nonce)?;
        let pop_signature_bytes = key.sign_bytes(encoded_pop.as_bytes().to_vec())?;

        Ok(format_wallet_attestation_pop(
            encoded_pop,
            &pop_signature_bytes,
        ))
    }

    pub async fn get_key_attestation(
        self: &Arc<Self>,
        client_nonce: Option<String>,
        audience: Option<String>,
        key_storage: Vec<String>,
        user_authentication: Vec<String>,
        keys: Vec<Arc<dyn NativeSigner>>,
    ) -> Result<String, ApiError> {
        for key in keys.iter() {
            if key.alg() != "ES256" {
                return Err(anyhow::anyhow!(
                    "invalid signer for wallet attestion, expecting ES256 (SHA256 with P256 ECDSA)"
                )
                .into());
            }
            if key.public_key().len() != 1 + 2 * 32 {
                return Err(anyhow::anyhow!("invalid signer for wallet attestion, wallet backend does not support key compression").into());
            }
        }

        // Note: UUID is expected for the attestation/start endpoint, but it's not really used for the
        // flow with a device bound key -- it would only be used for the HSM bound key flow.
        let uuid = generate_uuid_v4();

        let nonce_response: Value = self
            .client
            .post(format!("{}/attestation/start", self.base_url))
            .json(&json!({"uuid": uuid}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let Some(Value::String(nonce)) = nonce_response.get("pinNonce") else {
            return Err(anyhow!("pinNonce not found").into());
        };

        // sign nonce as proof of posession
        let decoded_nonce = BASE64_URL_SAFE_NO_PAD.decode(nonce)?;

        let keys: Result<Vec<AttestedKey>, _> = keys
            .iter()
            .map(|key| -> Result<AttestedKey, crate::error::SigningError> {
                AttestedKey::new(decoded_nonce.as_slice(), key)
            })
            .collect();
        let keys = keys?;

        let response: Value = self
            .client
            .post(format!(
                "{}/attestation/finalize-key-attestation",
                self.base_url
            ))
            .json(&KeyAttestationRequestBody {
                nonce: nonce.to_string(),
                client_nonce: client_nonce,
                audience,
                key_storage,
                user_authentication,
                keys,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let Some(Value::String(key_attestation)) = response.get("keyAttestation") else {
            return Err(anyhow!("walletAttestation not found").into());
        };

        Ok(key_attestation.clone())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAttestationRequestBody {
    pub audience: Option<String>,
    pub key_storage: Vec<String>,
    pub user_authentication: Vec<String>,
    pub keys: Vec<AttestedKey>,
    pub nonce: String,
    pub client_nonce: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestedKey {
    r#pub: String,
    signed_nonce: String,
    supporting_attestation: Option<String>,
}
impl AttestedKey {
    pub fn new(decoded_nonce: &[u8], key: &Arc<dyn NativeSigner>) -> Result<Self, SigningError> {
        let signed_nonce = key.sign_bytes(decoded_nonce.to_vec())?;
        Ok(Self {
            r#pub: BASE64_URL_SAFE_NO_PAD.encode(key.public_key()),
            signed_nonce: BASE64_URL_SAFE_NO_PAD.encode(signed_nonce),
            supporting_attestation: key.key_attestation(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod test_backend {

    use super::*;
    use crate::testing::new_native_signer;
    use std::sync::{Arc, Once};

    fn setup_proxy() {
        static SET_PROXY: Once = Once::new();
        SET_PROXY.call_once(|| {
            // crate::uniffi_reqwest::set_proxy("127.0.0.1".to_string(), 8080);
        });
    }

    #[tokio::test]
    async fn test_wallet_attestation() {
        setup_proxy();

        let backend = Arc::new(WalletBackend::new(
            "https://sprind-eudi-hsm-connector-ws-dev.ubique.ch/v1".to_string(),
        ));

        let key = new_native_signer();

        let attestation = backend.get_wallet_attestation(key.clone()).await.unwrap();
        dbg!(&attestation);

        // do it again to test the caching
        let attestation2 = backend.get_wallet_attestation(key.clone()).await.unwrap();
        assert!(
            attestation == attestation2,
            "wallet attestation changed unexpectedly"
        );

        let pop = backend
            .generate_wallet_attestation_pop(
                key.clone(),
                "a-client-id".to_string(),
                "an-issuer-url".to_string(),
                None,
            )
            .unwrap();
        dbg!(&pop);
        validate_jwt_es256(pop, key.public_key_jwk());

        let pop_nonce = backend
            .generate_wallet_attestation_pop(
                key.clone(),
                "a-client-id".to_string(),
                "an-issuer-url".to_string(),
                Some("a-nonce".to_string()),
            )
            .unwrap();
        dbg!(&pop_nonce);
        validate_jwt_es256(pop_nonce, key.public_key_jwk());
    }

    fn validate_jwt_es256(jwt: String, pub_key_jwk: String) {
        use josekit::jwk::Jwk;
        use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm;
        use josekit::jwt;
        let jwk = Jwk::from_bytes(pub_key_jwk.as_bytes()).unwrap();
        let verifier = EcdsaJwsAlgorithm::Es256.verifier_from_jwk(&jwk).unwrap();
        let _ = jwt::decode_with_verifier(jwt, &verifier).unwrap();
    }

    #[tokio::test]
    async fn test_key_attestation() {
        setup_proxy();

        let backend = Arc::new(WalletBackend::new(
            "https://sprind-eudi-hsm-connector-ws-dev.ubique.ch/v1".to_string(),
        ));

        let issuer_c_nonce = "fnord".to_string();
        let audience = "https://example.com/issuer/c".to_string();
        let keys = vec![new_native_signer(), new_native_signer()];

        let attestation = backend
            .get_key_attestation(
                Some(issuer_c_nonce.clone()),
                Some(audience.clone()),
                vec!["iso_18045_basic".to_string()],
                vec!["iso_18045_high".to_string()],
                keys.clone(),
            )
            .await
            .unwrap();

        // poor Jose's JOSE decoding
        let parts: Vec<&str> = attestation.split(".").collect();
        assert_eq!(parts.len(), 3);
        let jwthdr: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        dbg!(jwthdr);
        let jwtbody: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        dbg!(&jwtbody);
        if let Some(Value::Array(attested_keys)) = jwtbody.get("attested_keys") {
            assert_eq!(attested_keys.len(), keys.len());
        } else {
            panic!("no attested_keys in key attestation jwt");
        }
        if let Some(Value::String(jwt_nonce)) = jwtbody.get("nonce") {
            assert_eq!(jwt_nonce, &issuer_c_nonce);
        } else {
            panic!("no nonce in key attestation jwt");
        }
        if let Some(Value::String(jwt_aud)) = jwtbody.get("aud") {
            assert_eq!(jwt_aud, &audience);
        } else {
            panic!("no aud in key attestation jwt");
        }
    }
}
