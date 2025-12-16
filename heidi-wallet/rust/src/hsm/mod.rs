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

//! Implemenet HSM specific operations, such as key derivation and REST-API calls.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd};
use hkdf::Hkdf;
use reqwest::StatusCode;

use crate::error::HsmError;
#[cfg(feature = "reqwest")]
use crate::get_reqwest_client;
use crate::signing::NativeSigner;
use crate::uniffi_reqwest::HsmSupport;
use crate::util::{encode_jwt, generate_uuid_v4};
use crate::{lock, ApiError};
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::{FieldElement, SecretKey};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex};
use uniffi::Object;
use uniffi::Record;
use zeroize::Zeroizing;

/// Field encoding Domain Separation TAG for Pin derived ephemeral keys
/// c.f. https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3
/// for more information
const DST: &[u8] = b"HEIDI-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

/// Derive an ephemeral key pair from
/// - *pin*: User defined input (handle with care)
/// - *aes_key*: An AES-GCM 256 key, used for HMAC key derivation
/// - *nonce*: A AES-GCM 256 nonce (needs to be the same for the key derivation,
///  therefore make sure to keep it as private as the key itself)
pub(crate) fn derive_pin_key(
    pin: &[u8],
    aes_key: &[u8],
    nonce: &[u8],
) -> anyhow::Result<SecretKey> {
    let cipher =
        <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(aes_key).context("KeryInit failed")?;

    let encrypted_pin = cipher
        .encrypt(
            GenericArray::from_slice(nonce),
            b"plaintext message".as_ref(),
        )
        .map_err(|e| anyhow!(e))?;
    let hk = Hkdf::<Sha256>::new(Some(&encrypted_pin[..]), pin);
    let mut okm = [0u8; 42];
    let Ok(_) = hk.expand(&[], &mut okm) else {
        bail!("42 should be valid length for Sha256 to output")
    };

    let mut u = [FieldElement::default()];
    let Ok(_) =
        hash_to_field::<ExpandMsgXmd<Sha256>, FieldElement>(&[okm.as_slice()], &[DST], &mut u)
    else {
        bail!("hash_to_field failed");
    };
    let Ok(secret_key) = SecretKey::from_bytes(&u[0].to_bytes()) else {
        bail!("could not get secret key from field element");
    };
    Ok(secret_key)
}

#[derive(Object)]
/// HSM Obkect holding relevant parts for seed credential issuance and batch credential issuance
pub struct Hsm {
    pin_callback: Arc<dyn EnterPin>,
    native_signer: Arc<dyn NativeSigner>,
    key_material: Arc<dyn AesKeyMaterial>,
    pin_nonce: Mutex<Option<String>>,
    client: ClientWithMiddleware,
    base_url: String,
    wallet_attestation: Mutex<Option<String>>,
    uuid: Mutex<Option<String>>,
}

#[async_trait]
impl HsmSupport for Hsm {
    fn get_wallet_attestation(&self) -> Option<String> {
        Hsm::get_wallet_attestation(self)
    }
    async fn generate_pop(
        &self,
        client_id: String,
        credential_issuer_url: String,
    ) -> Option<String> {
        Hsm::generate_pop(self, client_id, credential_issuer_url, None).await
    }
}

impl Hsm {
    /// Generate the two signatures needed for authentication with the HSM API
    pub fn generate_signatures(&self, pin_nonce_str: String) -> Result<HsmPayload, ApiError> {
        let Ok(pin_nonce) = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(&pin_nonce_str) else {
            return Err(HsmError::NoNonce.into());
        };
        let pin = Zeroizing::new(self.pin_callback.pin());
        let aes_nonce = Zeroizing::new(self.key_material.get_nonce());
        let aes_key = Zeroizing::new(self.key_material.get_key());
        let ephemeral_key =
            derive_pin_key(&pin, &aes_key, &aes_nonce).map_err(|_| HsmError::ExpandFailure)?;
        let ephemeral_publickey = ephemeral_key.public_key().to_sec1_bytes().to_vec();
        let device_publickey = self.native_signer.public_key();
        let pin_signature_message = [pin_nonce.clone(), device_publickey.clone()].concat();
        let device_signature_message = [pin_nonce, ephemeral_publickey.clone()].concat();
        let device_signature = self
            .native_signer
            .sign_bytes(device_signature_message)
            .map_err(|_| HsmError::ExpandFailure)?;
        let ephemeral_key: SigningKey = ephemeral_key.into();
        let ephemeral_signature: Signature = ephemeral_key.sign(&pin_signature_message);
        Ok(HsmPayload {
            device_pub_key: device_publickey,
            device_signature,
            pin_pub_key: ephemeral_publickey,
            pin_signature: ephemeral_signature.to_bytes().to_vec(),
            pin_nonce: pin_nonce_str,
        })
    }
    /// Get nonce for registratino process
    pub async fn get_register_pin_nonce(self: &Arc<Self>) -> Result<(), ApiError> {
        let response: serde_json::Value = self
            .client
            .get(format!("{}/register/start", self.base_url))
            .send()
            .await?
            .json()
            .await?;
        let Some(Value::String(the_nonce)) = response.get("pinNonce") else {
            return Err(anyhow!("pinNonce not found").into());
        };
        let mut pin_nonce =
            lock!(self.pin_nonce => |_e| { Err(anyhow!("Could not aqcuire lock").into()) });
        pin_nonce.replace(the_nonce.to_string());
        Ok(())
    }
    /// Get nonce for signing procedures
    pub async fn get_sign_pin_nonce(&self, sign_start: SignStart) -> Result<(), ApiError> {
        let response: serde_json::Value = self
            .client
            .post(format!("{}/sign/start", self.base_url))
            .json(&sign_start)
            .send()
            .await?
            .json()
            .await?;
        let Some(Value::String(the_nonce)) = response.get("pinNonce") else {
            return Err(anyhow!("pinNonce not found").into());
        };
        let mut pin_nonce =
            lock!(self.pin_nonce => |_e| { Err(anyhow!("Could not aqcuire lock").into()) });
        pin_nonce.replace(the_nonce.to_string());
        Ok(())
    }
    /// Get nonce for batch operations
    pub async fn get_batch_pin_nonce(self: &Arc<Self>) -> Result<String, ApiError> {
        let response: serde_json::Value = self
            .client
            .get(format!("{}/batch/pin-nonce", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let Some(Value::String(the_nonce)) = response.get("pinNonce") else {
            return Err(anyhow!("pinNonce not found").into());
        };
        Ok(the_nonce.to_string())
    }
    /// Get nonce for wallet attestation
    pub async fn get_wallet_attestation_pin_nonce(
        &self,
        sign_start: SignStart,
    ) -> Result<(), ApiError> {
        let response: serde_json::Value = self
            .client
            .post(format!("{}/attestation/start", self.base_url))
            .json(&sign_start)
            .send()
            .await?
            .json()
            .await?;
        let Some(Value::String(the_nonce)) = response.get("pinNonce") else {
            return Err(anyhow!("pinNonce not found").into());
        };
        let mut pin_nonce =
            lock!(self.pin_nonce => |_e| { Err(anyhow!("Could not aqcuire lock").into()) });
        pin_nonce.replace(the_nonce.to_string());
        Ok(())
    }
}

/// Various models used in requests with the cloud HSM
#[derive(Record, Deserialize)]
pub struct WalletAttestationResult {
    #[serde(rename = "walletAttestation")]
    pub wallet_attestation: String,
}

#[derive(Record, Deserialize)]
pub struct HsmRegistrationResult {
    pub uuid: String,
    #[serde(
        deserialize_with = "deserialize_from_base64_no_padding",
        rename = "devPub"
    )]
    pub pub_key: Vec<u8>,
    #[serde(rename = "walletAttestation")]
    pub wallet_attestation: String,
}
#[derive(Serialize)]
pub struct SignStart {
    uuid: String,
}

#[uniffi::export(async_runtime = "tokio")]
impl Hsm {
    #[uniffi::constructor]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    /// Construct a new HSM API Client
    ///
    /// SAFETY:
    /// It is ok to unwrap, since our builders never panic
    pub fn new(
        pin_callback: Arc<dyn EnterPin>,
        native_signer: Arc<dyn NativeSigner>,
        key_material: Arc<dyn AesKeyMaterial>,
        base_url: String,
    ) -> Self {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(1);
        let client = ClientBuilder::new(get_reqwest_client().build().unwrap())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Self {
            pin_callback,
            native_signer,
            key_material,
            client,
            pin_nonce: Mutex::new(None),
            base_url,
            wallet_attestation: Mutex::new(None),
            uuid: Mutex::new(None),
        }
    }
    #[uniffi::constructor]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    /// Get a HSM Client from a UUID registered earlier.
    ///
    /// SAFETY:
    /// Client builder does not panic
    pub fn from_uuid(
        pin_callback: Arc<dyn EnterPin>,
        native_signer: Arc<dyn NativeSigner>,
        key_material: Arc<dyn AesKeyMaterial>,
        base_url: String,
        wallet_attestation: String,
        uuid: String,
    ) -> Self {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(1);
        let client = ClientBuilder::new(get_reqwest_client().build().unwrap())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Self {
            pin_callback,
            native_signer,
            key_material,
            pin_nonce: Mutex::new(None),
            client,
            base_url,
            wallet_attestation: Mutex::new(Some(wallet_attestation)),
            uuid: Mutex::new(Some(uuid)),
        }
    }
    /// Generate Proof of possession for wallet attestation
    pub async fn generate_pop(
        &self,
        client_id: String,
        credential_issuer_url: String,
        nonce: Option<String>,
    ) -> Option<String> {
        let encoded_pop =
            build_wallet_attestation_pop(client_id, credential_issuer_url, nonce).ok()?;
        let pop_signature_bytes = self.sign(encoded_pop.as_bytes().to_vec()).await.ok()?;

        Some(format_wallet_attestation_pop(
            encoded_pop,
            &pop_signature_bytes,
        ))
    }
    /// Get a cached wallet attestation. If that fails try using [refresh_wallet_attestation()]
    pub fn get_wallet_attestation(&self) -> Option<String> {
        self.wallet_attestation.lock().ok()?.clone()
    }
    /// Referesh the cached wallet attestation
    pub async fn refresh_wallet_attestation(
        self: &Arc<Self>,
    ) -> Result<WalletAttestationResult, ApiError> {
        let uuid = {
            let Ok(lock) = self.uuid.lock() else {
                return Err(HsmError::LockError.into());
            };
            let Some(uuid) = lock.as_ref() else {
                return Err(HsmError::LockError.into());
            };
            uuid.clone()
        };
        self.get_wallet_attestation_pin_nonce(SignStart { uuid: uuid.clone() })
            .await?;
        let pin_nonce = {
            let mut pin_nonce = lock!(self.pin_nonce => |_e| { Err(HsmError::NoNonce.into()) });
            let Some(pin_nonce) = pin_nonce.take() else {
                return Err(HsmError::NoNonce.into());
            };
            pin_nonce
        };

        let payload = self.generate_signatures(pin_nonce)?;

        let payload = HsmRefreshWalletAttestation {
            device_signature: payload.device_signature,
            pin_signature: payload.pin_signature,
            pin_nonce: payload.pin_nonce,
            uuid,
        };

        let result = self
            .client
            .post(format!("{}/attestation/finalize", self.base_url))
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;
        let result: WalletAttestationResult = result.json().await?;
        // let public_key = result.pub_key.clone();
        let Ok(mut lock) = self.wallet_attestation.lock() else {
            return Err(HsmError::LockError.into());
        };
        *lock = Some(result.wallet_attestation.clone());

        Ok(result)
    }

    /// Register a new client with the HSM backend, using PIN authentication
    pub async fn register(self: &Arc<Self>) -> Result<HsmRegistrationResult, ApiError> {
        self.get_register_pin_nonce().await?;
        let pin_nonce = {
            let mut pin_nonce = lock!(self.pin_nonce => |_e| { Err(HsmError::NoNonce.into()) });
            let Some(pin_nonce) = pin_nonce.take() else {
                return Err(HsmError::NoNonce.into());
            };
            pin_nonce
        };

        let payload = self.generate_signatures(pin_nonce)?;
        println!("{}", json!(&payload));
        let result = self
            .client
            .post(format!("{}/register/finalize", self.base_url))
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;

        let result: HsmRegistrationResult = result.json().await?;
        // let public_key = result.pub_key.clone();
        let Ok(mut lock) = self.wallet_attestation.lock() else {
            return Err(HsmError::LockError.into());
        };
        *lock = Some(result.wallet_attestation.clone());

        let Ok(mut lock) = self.uuid.lock() else {
            return Err(HsmError::LockError.into());
        };
        *lock = Some(result.uuid.clone());

        Ok(result)
    }

    /// Sign a payload using PIN authentication
    pub async fn sign(&self, sign_payload: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        let uuid = {
            let Ok(lock) = self.uuid.lock() else {
                return Err(HsmError::LockError.into());
            };
            let Some(uuid) = lock.as_ref() else {
                return Err(HsmError::LockError.into());
            };
            uuid.clone()
        };
        self.get_sign_pin_nonce(SignStart { uuid: uuid.clone() })
            .await
            .map_err(|_e| HsmError::NoNonce)?;

        let pin_nonce = {
            let mut pin_nonce = lock!(self.pin_nonce => |_e| { Err(HsmError::LockError.into()) });
            let Some(pin_nonce) = pin_nonce.take() else {
                return Err(HsmError::NoNonce.into());
            };
            pin_nonce
        };
        let shasum = sha2::Sha256::digest(&sign_payload);

        let payload = self.generate_signatures(pin_nonce)?;
        println!("{payload:?}");
        let sign_payload = HsmSign {
            device_signature: payload.device_signature,
            pin_signature: payload.pin_signature,
            pin_nonce: payload.pin_nonce,
            uuid,
            payload: base64::prelude::BASE64_URL_SAFE.encode(shasum),
        };
        let result = self
            .client
            .post(format!("{}/sign/finalize", self.base_url))
            .json(&sign_payload)
            .send()
            .await?;
        if result.status() == StatusCode::UNAUTHORIZED {
            return Err(HsmError::InvalidPin.into());
        }
        let result: Value = result.json().await?;
        let Some(signature) = result.get("signature").and_then(|a| a.as_str()) else {
            return Err(HsmError::InvalidResult(result.to_string()).into());
        };
        let Ok(signature_bytes) = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(signature) else {
            return Err(HsmError::InvalidResult(signature.to_string()).into());
        };
        Ok(signature_bytes)
    }

    /// Retrieve a series of keys. Currently the backend returns 84 keys, 24 used for mdoc 24 used for sdjwt proof of possesions
    pub async fn batch_keys(self: &Arc<Self>) -> Result<HsmBatchResponse, ApiError> {
        let uuid = {
            let Ok(lock) = self.uuid.lock() else {
                return Err(HsmError::LockError.into());
            };
            let Some(uuid) = lock.as_ref() else {
                return Err(HsmError::LockError.into());
            };
            uuid.clone()
        };

        let pin_nonce = self.get_batch_pin_nonce().await?;

        let payload = self.generate_signatures(pin_nonce)?;
        let payload = HsmBatchRequest {
            device_signature: payload.device_signature,
            pin_signature: payload.pin_signature,
            pin_nonce: payload.pin_nonce,
            uuid,
        };
        let result = self
            .client
            .post(format!("{}/batch/batch-keys", self.base_url))
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;
        let result: HsmBatchResponse = result.json().await?;
        Ok(result)
    }
    // Sign N payloads with the N corresponding batch keys.
    // Order of payloads and signatures correspond to order in result from batch_keys creation.
    // To be used during credential issuance.
    // For each individual item, the result is equivalent to calling sign_batch_one.
    pub async fn sign_batch_all(
        self: &Arc<Self>,
        sign_payloads: Vec<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, ApiError> {
        let uuid = {
            let Ok(lock) = self.uuid.lock() else {
                return Err(HsmError::LockError.into());
            };
            let Some(uuid) = lock.as_ref() else {
                return Err(HsmError::LockError.into());
            };
            uuid.clone()
        };
        let pin_nonce = self.get_batch_pin_nonce().await?;
        let shasums = sign_payloads
            .into_iter()
            .map(sha2::Sha256::digest)
            .map(|item| base64::prelude::BASE64_URL_SAFE.encode(item))
            .collect::<Vec<_>>();
        let payload = self.generate_signatures(pin_nonce)?;
        let payload = HsmBatchKeySignManyRequest {
            device_signature: payload.device_signature,
            pin_signature: payload.pin_signature,
            pin_nonce: payload.pin_nonce,
            uuid,
            hashed_pops: shasums,
        };
        let result = self
            .client
            .post(format!("{}/batch/sign-batch-pops", self.base_url))
            .json(&payload)
            .send()
            .await?;
        if result.status() == StatusCode::UNAUTHORIZED {
            return Err(HsmError::InvalidPin.into());
        }
        let result: Value = result.json().await?;
        let Some(signatures) = result.get("hashedPoPsSignatures").and_then(|a| {
            a.as_array().map(|a| {
                a.iter()
                    .filter_map(|item| item.as_str())
                    .filter_map(|item| base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(item).ok())
                    .collect::<Vec<_>>()
            })
        }) else {
            return Err(HsmError::UnknownError.into());
        };
        Ok(signatures)
    }
    // Sign one payload with the key identified by key_id as returned from batch_keys.
    // To be used in presentation flow.
    pub async fn sign_batch_one(
        self: &Arc<Self>,
        key_id: String,
        sign_payload: Vec<u8>,
    ) -> Result<Vec<u8>, ApiError> {
        let uuid = {
            let Ok(lock) = self.uuid.lock() else {
                return Err(HsmError::LockError.into());
            };
            let Some(uuid) = lock.as_ref() else {
                return Err(HsmError::LockError.into());
            };
            uuid.clone()
        };

        let pin_nonce = self.get_batch_pin_nonce().await?;

        let shasum = sha2::Sha256::digest(&sign_payload);

        let payload = self.generate_signatures(pin_nonce)?;
        let payload = HsmBatchKeySignOneRequest {
            device_signature: payload.device_signature,
            pin_signature: payload.pin_signature,
            pin_nonce: payload.pin_nonce,
            key_id,
            payload: base64::prelude::BASE64_URL_SAFE.encode(shasum),
            uuid,
        };
        let result = self
            .client
            .post(format!("{}/batch/sign-device-auth", self.base_url))
            .json(&payload)
            .send()
            .await?;
        if result.status() == StatusCode::UNAUTHORIZED {
            return Err(HsmError::InvalidPin.into());
        }
        let result: Value = result.json().await?;
        let Some(signature) = result
            .get("deviceAuthHashSignature")
            .and_then(|a| a.as_str())
        else {
            return Err(HsmError::UnknownError.into());
        };
        let signature_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|e| HsmError::BatchError(format!("base64 decode error {e}")))?;
        Ok(signature_bytes)
    }

    /// Implement the change_pin method on the HSM. We sign the same nonce to proof knowledge of the previous PIN
    /// and knowledge of the new pin.
    pub async fn change_pin(
        self: &Arc<Self>,
        pin_callback: Arc<dyn EnterPin>,
        key_material: Arc<dyn AesKeyMaterial>,
    ) -> Result<Arc<Self>, ApiError> {
        let uuid = {
            let Ok(lock) = self.uuid.lock() else {
                return Err(HsmError::LockError.into());
            };
            let Some(uuid) = lock.as_ref() else {
                return Err(HsmError::LockError.into());
            };
            uuid.clone()
        };
        let wallet_attestation = {
            let Ok(lock) = self.wallet_attestation.lock() else {
                return Err(HsmError::LockError.into());
            };
            let Some(wallet_attestation) = lock.as_ref() else {
                return Err(HsmError::LockError.into());
            };
            wallet_attestation.clone()
        };
        let new_hsm = Arc::new(Hsm::from_uuid(
            pin_callback,
            self.native_signer.clone(),
            key_material,
            self.base_url.clone(),
            wallet_attestation,
            uuid.clone(),
        ));
        self.get_sign_pin_nonce(SignStart { uuid: uuid.clone() })
            .await?;

        let pin_nonce = {
            let mut pin_nonce = lock!(self.pin_nonce => |_e| { Err(HsmError::LockError.into()) });
            let Some(pin_nonce) = pin_nonce.take() else {
                return Err(HsmError::NoNonce.into());
            };
            pin_nonce
        };
        let old_signatures = self.generate_signatures(pin_nonce.clone())?;
        let new_signatures = new_hsm.generate_signatures(pin_nonce.clone())?;

        let payload = HsmChangePinRequest {
            old_device_signature: old_signatures.device_signature,
            old_pin_signature: old_signatures.pin_signature,
            new_device_signature: new_signatures.device_signature,
            new_pin_signature: new_signatures.pin_signature,
            pin_nonce,
            uuid,
            device_pub_key: new_signatures.device_pub_key,
            pin_pub_key: new_signatures.pin_pub_key,
        };

        let result = self
            .client
            .post(format!("{}/change/finalize", self.base_url))
            .json(&payload)
            .send()
            .await?;
        if result.status() == StatusCode::UNAUTHORIZED {
            return Err(HsmError::InvalidPin.into());
        }
        Ok(new_hsm)
    }
}

// build wallet attestation pop JWT (payload only, unsigned)
pub(crate) fn build_wallet_attestation_pop(
    client_id: String,
    credential_issuer_url: String,
    nonce: Option<String>,
) -> Result<String, ApiError> {
    let pop_header = serde_json::json!(        {
      "alg": "ES256"
    });
    let now = std::time::SystemTime::now();
    let Ok(unix_timestamp) = now.duration_since(std::time::UNIX_EPOCH) else {
        return Err(anyhow::anyhow!("timetravel not supported").into());
    };
    use std::ops::Add;
    let expires = unix_timestamp.add(std::time::Duration::from_secs(360));
    let nbf = unix_timestamp.as_secs();
    let exp = expires.as_secs();
    let uuid = generate_uuid_v4();

    let pop_body = serde_json::json!({
      "iss": client_id,
      "aud": credential_issuer_url,
      "nbf":nbf,
      "exp":exp,
      "jti": uuid
    });
    let pop_body = if let Some(nonce) = nonce {
        if let Value::Object(mut body) = pop_body {
            body.insert("nonce".to_string(), Value::String(nonce));
            Value::Object(body)
        } else {
            unreachable!()
        }
    } else {
        pop_body
    };

    let encoded_pop = encode_jwt(&pop_header, &pop_body);
    Ok(encoded_pop)
}

//
pub(crate) fn format_wallet_attestation_pop(encoded_pop: String, signature_bytes: &[u8]) -> String {
    let sig_base64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(signature_bytes);
    format!("{encoded_pop}.{sig_base64}")
}

#[derive(Record, serde::Serialize, serde::Deserialize, Debug)]
pub struct HsmPayload {
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "walletAuthPub"
    )]
    device_pub_key: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "walletAuthSignedNonce"
    )]
    device_signature: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "pinDerivedEphPub"
    )]
    pin_pub_key: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "userPinSignedNonce"
    )]
    pin_signature: Vec<u8>,
    #[serde(rename = "pinNonce")]
    pin_nonce: String,
}

#[derive(Record, serde::Serialize, serde::Deserialize, Debug)]
pub struct HsmSign {
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "walletAuthSignedNonce"
    )]
    device_signature: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "userPinSignedNonce"
    )]
    pin_signature: Vec<u8>,
    #[serde(rename = "pinNonce")]
    pin_nonce: String,
    uuid: String,
    payload: String,
}

#[derive(Record, serde::Serialize, serde::Deserialize, Debug)]
pub struct HsmRefreshWalletAttestation {
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "walletAuthSignedNonce"
    )]
    device_signature: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "userPinSignedNonce"
    )]
    pin_signature: Vec<u8>,
    #[serde(rename = "pinNonce")]
    pin_nonce: String,
    uuid: String,
}

#[derive(Record, serde::Serialize, serde::Deserialize, Debug)]
pub struct HsmBatchRequest {
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "walletAuthSignedNonce"
    )]
    device_signature: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "userPinSignedNonce"
    )]
    pin_signature: Vec<u8>,
    #[serde(rename = "pinNonce")]
    pin_nonce: String,
    uuid: String,
}
#[derive(Record, serde::Serialize, serde::Deserialize, Debug)]
pub struct HsmBatchResponse {
    #[serde(rename = "cloudWalletBatchKey")]
    keys: Vec<HsmBatchKey>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "cloudWalletBatchKeySignature"
    )]
    signature: Vec<u8>,
}

#[derive(Record, serde::Serialize, serde::Deserialize, Debug)]
pub struct HsmBatchKey {
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "publicKey"
    )]
    public_key: Vec<u8>,
}
#[derive(Record, serde::Serialize, serde::Deserialize, Debug)]
struct HsmBatchKeySignOneRequest {
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "walletAuthSignedNonce"
    )]
    device_signature: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "userPinSignedNonce"
    )]
    pin_signature: Vec<u8>,
    #[serde(rename = "pinNonce")]
    pin_nonce: String,
    uuid: String,
    #[serde(rename = "deviceAuthHash")]
    payload: String,
    #[serde(rename = "keyId")]
    key_id: String,
}

#[derive(Record, serde::Serialize, serde::Deserialize, Debug)]
struct HsmChangePinRequest {
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "oldWalletAuthSignedNonce"
    )]
    old_device_signature: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "oldUserPinSignedNonce"
    )]
    old_pin_signature: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "newWalletAuthSignedNonce"
    )]
    new_device_signature: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "newUserPinSignedNonce"
    )]
    new_pin_signature: Vec<u8>,
    #[serde(rename = "pinNonce")]
    pin_nonce: String,
    uuid: String,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "walletAuthPub"
    )]
    device_pub_key: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "pinDerivedEphPub"
    )]
    pin_pub_key: Vec<u8>,
}

#[derive(Record, serde::Serialize, serde::Deserialize, Debug)]
struct HsmBatchKeySignManyRequest {
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "walletAuthSignedNonce"
    )]
    device_signature: Vec<u8>,
    #[serde(
        serialize_with = "serialize_as_base64",
        deserialize_with = "deserialize_from_base64",
        rename = "userPinSignedNonce"
    )]
    pin_signature: Vec<u8>,
    #[serde(rename = "pinNonce")]
    pin_nonce: String,
    uuid: String,
    #[serde(rename = "hashedPoPs")]
    hashed_pops: Vec<String>,
}

pub(crate) fn serialize_as_base64<S>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encoded_string = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(value);
    serializer.serialize_str(&encoded_string)
}
pub(crate) fn deserialize_from_base64<'de, D>(val: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Base64Visitor;
    impl Visitor<'_> for Base64Visitor {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("Expecting a base64encoded string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(v)
                .map_err(|_e| Error::custom("not base64encoded"))?;
            Ok(bytes)
        }
        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: Error,
        {
            self.visit_str(&v)
        }
    }
    val.deserialize_str(Base64Visitor)
}
pub(crate) fn deserialize_from_base64_no_padding<'de, D>(val: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Base64Visitor;
    impl Visitor<'_> for Base64Visitor {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("Expecting a base64encoded string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(v)
                .map_err(|_e| Error::custom("not base64encoded"))?;
            Ok(bytes)
        }
        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: Error,
        {
            self.visit_str(&v)
        }
    }
    val.deserialize_str(Base64Visitor)
}

#[uniffi::export(with_foreign)]
pub trait EnterPin: Sync + Send + Debug {
    fn pin(&self) -> Vec<u8>;
}
#[uniffi::export(with_foreign)]
pub trait AesKeyMaterial: Sync + Send + Debug {
    fn get_key(&self) -> Vec<u8>;
    fn get_nonce(&self) -> Vec<u8>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::hsm::derive_pin_key;
    use aes_gcm::{AeadCore, Aes256Gcm};
    use rand::rngs::OsRng;

    #[test]
    fn test_pin_derived_key() {
        let key = { <Aes256Gcm as aes_gcm::KeyInit>::generate_key(OsRng) };
        println!("{}", key.as_slice().len());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let first = derive_pin_key(b"1234", key.as_slice(), nonce.as_slice()).unwrap();
        let second = derive_pin_key(b"1234", key.as_slice(), nonce.as_slice()).unwrap();
        assert_eq!(first, second);

        let third = derive_pin_key(b"12345".as_slice(), key.as_slice(), nonce.as_slice()).unwrap();
        assert_ne!(first, third);
    }
    // #[test]
    // fn stress_test_derived_key() {
    //     let mut keys = vec![];
    //     for i in 0..10000 {
    //         for _ in 0..3 {
    //             let pin = format!("{i}").as_bytes().to_vec();
    //             let wrong_pin = format!("{}", i + 1).as_bytes().to_vec();

    //             let key = { <Aes256Gcm as aes_gcm::KeyInit>::generate_key(OsRng) };
    //             let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    //             let first =
    //                 derive_pin_key(pin.as_slice(), key.as_slice(), nonce.as_slice()).unwrap();

    //             let second =
    //                 derive_pin_key(pin.as_slice(), key.as_slice(), nonce.as_slice()).unwrap();

    //             assert_eq!(first, second);
    //             assert!(!keys.contains(&second));
    //             keys.push(second);

    //             let third =
    //                 derive_pin_key(wrong_pin.as_slice(), key.as_slice(), nonce.as_slice()).unwrap();
    //             assert_ne!(first, third);
    //         }
    //     }
    // }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod hsm_tests {
    use crate::hsm::HsmPayload;

    #[test]
    fn test_serialize() {
        let payload = serde_json::to_string(&HsmPayload {
            device_pub_key: vec![0, 1, 2, 3],
            device_signature: vec![],
            pin_pub_key: vec![],
            pin_signature: vec![],
            pin_nonce: "".to_string(),
        })
        .unwrap();
        println!("{payload}");
        let s: HsmPayload = serde_json::from_str(&payload).unwrap();
        println!("{s:?}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod test_hsm {
    use reqwest_middleware::ClientBuilder;
    use std::sync::Arc;

    use p256::ecdsa::signature::Signer;
    use p256::PublicKey;

    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    use p256::ecdsa::{Signature, SigningKey};
    use rand::rngs::OsRng;

    use serde_json::{json, Value};

    use crate::error::SigningError;
    use crate::get_reqwest_client;
    use crate::hsm::{encode_jwt, EnterPin, Hsm};
    use crate::issuance::auth::{build_pushed_authorization_request, ClientAttestation};
    use crate::issuance::helper::{base64_encode_bytes, bytes_to_ec_jwk};
    use crate::issuance::models::PushedAuthorizationRequest;
    use crate::signing::NativeSigner;
    use crate::util::{generate_code_challenge, generate_code_verifier};

    use super::AesKeyMaterial;

    #[derive(Debug, Clone)]
    struct Stuff(SigningKey);

    impl EnterPin for Stuff {
        fn pin(&self) -> Vec<u8> {
            b"1234".to_vec()
        }
    }

    impl NativeSigner for Stuff {
        fn key_reference(&self) -> Vec<u8> {
            todo!()
        }

        fn sign(&self, msg: String) -> Result<Vec<u8>, SigningError> {
            self.sign_bytes(msg.as_bytes().to_vec())
        }

        fn sign_bytes(&self, msg: Vec<u8>) -> Result<Vec<u8>, SigningError> {
            let signature: Signature = self.0.sign(&msg);
            Ok(signature.to_vec())
        }

        fn public_key(&self) -> Vec<u8> {
            self.0.verifying_key().to_sec1_bytes().to_vec()
        }

        fn key_id(&self) -> String {
            "hsm".to_string()
        }

        fn jwt_header(&self) -> String {
            todo!()
        }

        fn alg(&self) -> String {
            todo!()
        }

        fn public_key_jwk(&self) -> String {
            todo!()
        }

        fn private_key(&self) -> Result<Vec<u8>, SigningError> {
            todo!()
        }

        fn private_key_exportable(&self) -> bool {
            todo!()
        }
        fn key_attestation(&self) -> Option<String> {
            None
        }
    }

    impl AesKeyMaterial for Stuff {
        fn get_key(&self) -> Vec<u8> {
            vec![0; 32]
        }

        fn get_nonce(&self) -> Vec<u8> {
            vec![0; 12]
        }
    }

    #[allow(unused)]
    pub fn new_testing_hsm() -> Arc<Hsm> {
        let stuff = Arc::new(Stuff(SigningKey::random(&mut OsRng)));

        Arc::new(Hsm::new(
            stuff.clone(),
            stuff.clone(),
            stuff.clone(),
            "https://sprind-eudi-hsm-connector-ws-dev.ubique.ch/v1".to_string(),
        ))
    }

    #[tokio::test]
    #[ignore]
    async fn stress_test_wallet_attestation() {
        for _i in 0..100 {
            test_wallet_attestation_helper().await;
        }
    }

    #[tokio::test]
    async fn test_wallet_attestation() {
        test_wallet_attestation_helper().await;
    }

    async fn test_wallet_attestation_helper() {
        let hsm = new_testing_hsm();
        let r = hsm.register().await.unwrap();
        assert!(PublicKey::from_sec1_bytes(&r.pub_key).is_ok());

        let wallet_attestation = hsm
            .wallet_attestation
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();

        let client_id = "c3ce7a6c-2bbb-4abe-909c-41bc9463d3c5";
        let issuer = "https://demo.pid-issuer.bundesdruckerei.de/c1";
        let pop = hsm
            .generate_pop(client_id.to_string(), issuer.to_string(), None)
            .await
            .unwrap();

        let code_verifier = generate_code_verifier();
        let code_challenge = generate_code_challenge(&code_verifier, "S256");
        let par = PushedAuthorizationRequest {
            response_type: "code".to_string(),
            client_id: client_id.to_string(),
            redirect_uri: Some("https://heidi.ubique.ch".to_string()),
            scope: Some("pid".to_string()),
            state: None,
            code_challenge: Some(code_challenge),
            code_challenge_method: Some("S256".to_string()),
            issuer_state: None,
        };
        let client_attestation = ClientAttestation {
            client_attestation: wallet_attestation,
            client_attestation_pop: pop,
        };
        let client = ClientBuilder::new(get_reqwest_client().build().unwrap()).build();
        let par_request = build_pushed_authorization_request(
            &client,
            "https://demo.pid-issuer.bundesdruckerei.de/c1/par"
                .parse()
                .unwrap(),
            par,
            Some(client_attestation),
        )
        .unwrap();
        let response = par_request.send().await.unwrap();
        println!("{response:?}");
        let status = response.status();
        let body = response.json::<Value>().await.unwrap();
        println!("{body}");
        assert!(status.is_success());
        assert!(body.get("request_uri").is_some());
    }

    #[tokio::test]
    async fn test_batch_keys() {
        let hsm = new_testing_hsm();
        let _ = hsm.register().await.unwrap();

        let keys = hsm.batch_keys().await.unwrap();
        // Signature should be decodable
        assert!(Signature::from_slice(&keys.signature).is_ok());
        // Public keys should be decodable
        for k in keys.keys.iter() {
            assert!(PublicKey::from_sec1_bytes(&k.public_key).is_ok());
        }
    }

    #[tokio::test]
    async fn test_batch_sign() {
        let hsm = new_testing_hsm();
        let _ = hsm.register().await.unwrap();
        let keys = hsm.batch_keys().await.unwrap();
        let msg = keys
            .keys
            .iter()
            .map(|i| format!("test{}", i.key_id).into_bytes())
            .collect::<Vec<_>>();
        let signatures = hsm.sign_batch_all(msg.clone()).await.unwrap();

        for ((key, msg), sig) in keys.keys.iter().zip(msg).zip(signatures) {
            let sig = Signature::from_slice(&sig).unwrap();
            // Verify the signature
            let verifying_key = VerifyingKey::from_sec1_bytes(&key.public_key).unwrap();
            assert!(dbg!(verifying_key.verify(msg.as_slice(), &sig)).is_ok());
        }
    }

    #[tokio::test]
    async fn test_batch_key_sign_one() {
        let hsm = new_testing_hsm();
        let _ = hsm.register().await.unwrap();
        let keys = hsm.batch_keys().await.unwrap();

        // Use one of the keys to sign a test message

        let k = &keys.keys[0];
        let jwk = serde_json::from_str::<serde_json::Value>(
            &bytes_to_ec_jwk(k.public_key.clone()).unwrap(),
        )
        .unwrap();
        // let jwk = serde_json::from_str::<serde_json::Value>(&bytes_to_ec_jwk(register.pub_key.clone()).unwrap()).unwrap();

        let test = json!({
          "typ": "openid4vci-proof+jwt",
          "alg": "ES256",
          "jwk" : jwk
        });
        let body = json!({
            "test" : 1234
        });

        let jwt = encode_jwt(&test, &body);

        let sig = hsm
            .sign_batch_one(k.key_id.clone(), jwt.as_bytes().to_vec())
            .await
            .unwrap();
        // let sig_other = hsm.sign(jwt.as_bytes().to_vec()).await.unwrap();
        let jwt_sig = base64_encode_bytes(&sig);
        println!("{jwt}.{jwt_sig}");
        let sig = Signature::from_slice(&sig).unwrap();
        // Verify the signature
        let verifying_key = VerifyingKey::from_sec1_bytes(&k.public_key).unwrap();
        assert!(dbg!(verifying_key.verify(jwt.as_bytes(), &sig)).is_ok());
    }

    #[tokio::test]
    async fn test_change_pin() {
        #[derive(Debug)]
        struct NewPin;
        impl EnterPin for NewPin {
            fn pin(&self) -> Vec<u8> {
                "4321".as_bytes().to_vec()
            }
        }
        #[derive(Debug)]
        struct NewAes;
        impl AesKeyMaterial for NewAes {
            fn get_key(&self) -> Vec<u8> {
                vec![1; 32]
            }

            fn get_nonce(&self) -> Vec<u8> {
                vec![1; 12]
            }
        }
        let hsm = new_testing_hsm();
        let _ = hsm.register().await.unwrap();

        let new_hsm = hsm
            .change_pin(Arc::new(NewPin), Arc::new(NewAes))
            .await
            .unwrap();

        assert!(dbg!(hsm.sign(b"test".to_vec()).await.is_err()));
        assert!(dbg!(new_hsm.sign(b"test".to_vec()).await.is_ok()));
    }
}
