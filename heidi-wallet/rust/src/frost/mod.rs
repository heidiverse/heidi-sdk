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

//! This module exposes functions to use [FROST](https://eprint.iacr.org/2020/852.pdf). The wallet uses
//! FROST signatures for the emergency passport. Generally speaking, FROST-Signatures are just normal
//! Schnorr-Signatures over a specific group. In order to push for a broader acceptance, we use Edward Curves,
//! namely the Ed25519 Curve, which can be verified using normal EdDSA algorithms, which are registered in the [IANA](https://www.iana.org/assignments/jose/jose.xhtml)
//! registry.
//!
//! Currently we don't directly use EdDSA signature for Keybinding, as the issuer used does not yet support it, though this could be easily made possible in the future.
use aes_gcm::{aead::Aead, KeyInit, Nonce};
use anyhow::anyhow;
use async_trait::async_trait;
use base64::Engine;
use bip39_dict::{seed_from_mnemonics, Entropy, Mnemonics, ENGLISH};
use elliptic_curve::generic_array::GenericArray;
use frost_ed25519::{
    self as frost,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Identifier, Signature, SigningPackage,
};
use rand::rngs::OsRng;
#[cfg(feature = "reqwest")]
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use std::{fmt::Debug, io::Cursor};

use crate::{
    error::{FrostError, FrostHsmError, HsmError},
    util::encode_jwt,
    ApiError,
};
#[cfg(target_family = "wasm")]
pub mod wasm;

#[cfg(feature = "reqwest")]
use crate::get_reqwest_client;
#[cfg(all(feature = "uniffi", feature = "reqwest"))]
use crate::hsm::{HsmRegistrationResult, WalletAttestationResult};
#[cfg(all(feature = "uniffi", feature = "reqwest"))]
use crate::uniffi_reqwest::HsmSupport;

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
/// Struct exposing functions to work with FROST signatures
pub struct FrostSigner {
    splits: Vec<Split>,
    pass_phrase_part: PassphraseSplit,
    pub_key_package: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
/// A arbitrary Frost-Key-Share
pub struct Split {
    pub identifier: Vec<u8>,
    pub package: Vec<u8>,
}

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
/// A FROST-Key-Share encrypted using keys derived from a passphrase
pub struct PassphraseSplit {
    pass_phrase_encrypted_blob: Vec<u8>,
    pass_phrase_identifier: Vec<u8>,
    pass_phrase: Option<String>,
}
impl From<PassphraseBackup> for PassphraseSplit {
    fn from(value: PassphraseBackup) -> Self {
        Self {
            pass_phrase_encrypted_blob: value.pass_phrase_encrypted_blob,
            pass_phrase_identifier: value.pass_phrase_identifier,
            pass_phrase: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
/// Convenience struct to hold a backup
pub struct PassphraseBackup {
    pass_phrase_encrypted_blob: Vec<u8>,
    pass_phrase_identifier: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
/// Convenience struct to hold a backup
pub struct FrostBackup {
    pub splits: Vec<Split>,
    pub pass_phrase_part: PassphraseBackup,
    pub pub_key_package: Vec<u8>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
/// Serialize a frost backup into CBOR and base64encode it (urlsafe, no pad)
pub fn serialize_frost_backup(frost_backup: FrostBackup) -> Option<String> {
    let mut bytes = vec![];
    ciborium::into_writer(&frost_backup, &mut bytes).ok()?;
    Some(base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
/// Deserialize a frost backup from base64encoded (urlsafe, nopad) CBOR encoded bytes
pub fn deserialize_frost_backup(frost_backup: String) -> Option<FrostBackup> {
    let bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
        .decode(&frost_backup)
        .ok()?;
    ciborium::from_reader(Cursor::new(&bytes)).ok()
}

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
/// Representing a commitment, which is part of the signing procedure
pub struct Commitment {
    identifier: Vec<u8>,
    signing_commitment: Vec<u8>,
}

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
/// A frost nonce which is part of the signing proceudre
pub struct FrostNonce {
    identifier: Vec<u8>,
    nonce: Vec<u8>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl FrostSigner {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    /// Construct a new signer with the posibility of threshould signing. The email is used for key derivaiton.
    pub fn new(min_signers: u16, max_signers: u16, email: String) -> Result<Self, FrostError> {
        if min_signers < 3 {
            return Err(FrostError::TooFewSigners);
        }
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            OsRng,
        )
        .map_err(|e| FrostError::FrostInitializationFailed(anyhow!(e)))?;

        let mut passphrase_package: Option<PassphraseSplit> = None;
        let bip39_str = generate_bip39()?;
        let mut splits = vec![];
        for (identifier, secret_share) in shares {
            let key_package = frost::keys::KeyPackage::try_from(secret_share)
                .map_err(|e| FrostError::FrostInitializationFailed(anyhow!(e)))?;
            if passphrase_package.is_none() {
                let bytes = key_package
                    .serialize()
                    .map_err(|e| FrostError::FrostInitializationFailed(anyhow!(e)))?;
                let identifier_bytes = identifier.serialize();
                let cipher_txt = encrypt_with_mnemonic(bytes, bip39_str.clone(), email.clone())?;

                passphrase_package = Some(PassphraseSplit {
                    pass_phrase_encrypted_blob: cipher_txt,
                    pass_phrase_identifier: identifier_bytes.to_vec(),
                    pass_phrase: Some(bip39_str.clone()),
                });
            } else {
                splits.push(Split {
                    identifier: identifier.serialize().to_vec(),
                    package: key_package
                        .serialize()
                        .map_err(|e| FrostError::FrostInitializationFailed(anyhow!(e)))?,
                });
            }
        }

        let Some(pass_phrase_part) = passphrase_package else {
            return Err(FrostError::FrostSigningFailed(anyhow!(
                "passphrase missing"
            )));
        };
        Ok(Self {
            splits,
            pass_phrase_part,
            pub_key_package: pubkey_package
                .serialize()
                .map_err(|e| FrostError::FrostInitializationFailed(anyhow!(e)))?,
        })
    }

    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    /// Create a signer from frost parts.
    pub fn from_packages(
        splits: Vec<Split>,
        pass_phrase_part: PassphraseSplit,
        pub_key_package: Vec<u8>,
    ) -> Self {
        Self {
            splits,
            pass_phrase_part,
            pub_key_package,
        }
    }
    /// Convenience function to return a backup struct (that can be used for serializing)
    pub fn get_backup_payload(&self) -> FrostBackup {
        let splits = self.splits.clone();
        let pub_key_package = self.pub_key_package.clone();
        let pass_phrase_part = PassphraseBackup {
            pass_phrase_encrypted_blob: self.pass_phrase_part.pass_phrase_encrypted_blob.clone(),
            pass_phrase_identifier: self.pass_phrase_part.pass_phrase_identifier.clone(),
        };
        FrostBackup {
            splits,
            pass_phrase_part,
            pub_key_package,
        }
    }
    /// The public key of this frost instance.
    /// Note: This is a normal EdDSA (Ed25519) public key.
    pub fn get_public_key(&self) -> Result<Vec<u8>, FrostError> {
        let pkg = PublicKeyPackage::deserialize(&self.pub_key_package)
            .map_err(|_| FrostError::InvalidPublicKey)?;
        Ok(pkg.verifying_key().serialize().to_vec())
    }
    /// Algorithm for JWK header
    pub fn get_alg(&self) -> String {
        "EdDSA".to_string()
    }
    /// Return this frost public key as a JWK
    pub fn get_public_key_as_jwk(&self) -> Result<String, FrostError> {
        let encoder = base64::prelude::BASE64_URL_SAFE_NO_PAD;
        let pk_bytes = self.get_public_key()?;
        use sha2::Digest;
        let digest: String = encoder.encode(Sha256::digest(&pk_bytes));
        let public_key_bytes = encoder.encode(pk_bytes);

        Ok(json!({
            "kty" : "OKP",
            "kid" : digest,
            "alg" : "EdDSA",
            "crv" : "Ed25519",
            "x" : public_key_bytes
        })
        .to_string())
    }
    /// Sign payload using this frost instance.
    /// Note: we need passphrase to decrypt the third share.
    pub fn sign(
        &self,
        payload: Vec<u8>,
        passphrase: String,
        email: String,
    ) -> Result<Vec<u8>, FrostError> {
        let nonce_commitments = self.round1_from_split()?;
        let passphrase_round1 = self.round1_from_passphrase(passphrase.clone(), email.clone())?;

        let mut commitments = nonce_commitments
            .iter()
            .map(|(c, _)| c.clone())
            .collect::<Vec<_>>();
        commitments.push(passphrase_round1.0);
        let commitments = commitments
            .into_iter()
            .filter_map(|c| {
                let mut id_bytes: [u8; 32] = [0; 32];
                id_bytes.copy_from_slice(c.identifier.as_slice());
                let Ok(id) = Identifier::deserialize(&id_bytes)
                    .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))
                else {
                    return None;
                };
                let Ok(commitment) =
                    SigningCommitments::deserialize(c.signing_commitment.as_slice())
                        .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))
                else {
                    return None;
                };
                Some((id, commitment))
            })
            .collect::<BTreeMap<_, _>>();

        let signing_package = SigningPackage::new(commitments, payload.as_slice());
        let mut round2_split = self.round2_from_split(
            signing_package.clone(),
            nonce_commitments.iter().map(|(_, n)| n.clone()).collect(),
        )?;
        let round2_passphrase = self.round2_from_passphrase(
            signing_package.clone(),
            passphrase_round1.1,
            passphrase,
            email,
        )?;
        let mut passphrase_id_bytes: [u8; 32] = [0; 32];
        passphrase_id_bytes
            .copy_from_slice(self.pass_phrase_part.pass_phrase_identifier.as_slice());
        let passphrase_id = Identifier::deserialize(&passphrase_id_bytes)
            .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
        round2_split.insert(passphrase_id, round2_passphrase);
        let pubkeys = PublicKeyPackage::deserialize(self.pub_key_package.as_slice())
            .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
        let group_signature = frost::aggregate(&signing_package, &round2_split, &pubkeys)
            .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
        Ok(group_signature.serialize().to_vec())
    }

    /// Convenience function to allow certain integrity checks
    pub fn verify(&self, msg: Vec<u8>, gs: Vec<u8>) -> Result<(), FrostError> {
        let mut group_signature: [u8; 64] = [0; 64];
        group_signature.copy_from_slice(gs.as_slice());
        let group_signature: Signature = Signature::deserialize(group_signature)
            .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
        let pubkeys = PublicKeyPackage::deserialize(self.pub_key_package.as_slice())
            .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
        let is_signature_valid = pubkeys
            .verifying_key()
            .verify(msg.as_slice(), &group_signature)
            .is_ok();
        if is_signature_valid {
            Ok(())
        } else {
            Err(FrostError::SignatureInvalid)
        }
    }
    /// Get the passphrase part. Use this to show the passphrase to the user
    pub fn get_passphrase_split(self: &Arc<Self>) -> PassphraseSplit {
        self.pass_phrase_part.clone()
    }
    /// Get the backup parts. Use this to attach the FROST part to the backup.
    pub fn get_splits(self: &Arc<Self>) -> Vec<Split> {
        self.splits.clone()
    }
}
/// Frost signature specific functions.
impl FrostSigner {
    pub fn round2_from_split(
        &self,
        signing_package: SigningPackage,
        nonces: Vec<FrostNonce>,
    ) -> Result<BTreeMap<Identifier, SignatureShare>, FrostError> {
        let nonces: BTreeMap<_, _> = nonces
            .into_iter()
            .filter_map(|nonce| {
                let mut identifier_bytes: [u8; 32] = [0; 32];
                identifier_bytes.copy_from_slice(nonce.identifier.as_slice());
                if let (Ok(id), Ok(nonce)) = (
                    Identifier::deserialize(&identifier_bytes),
                    SigningNonces::deserialize(nonce.nonce.as_slice()),
                ) {
                    Some((id, nonce))
                } else {
                    None
                }
            })
            .collect();
        let mut signature_shares = BTreeMap::new();
        for Split {
            identifier,
            package,
        } in &self.splits
        {
            let mut identifier_bytes: [u8; 32] = [0; 32];
            identifier_bytes.copy_from_slice(identifier);
            let identifier = Identifier::deserialize(&identifier_bytes)
                .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
            let package = KeyPackage::deserialize(package)
                .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
            let Some(nonce) = nonces.get(&identifier) else {
                return Err(FrostError::FrostSigningFailed(anyhow!("nonce not found")));
            };

            let signature_share = frost::round2::sign(&signing_package, nonce, &package)
                .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
            signature_shares.insert(identifier, signature_share);
        }
        Ok(signature_shares)
    }
    pub fn round2_from_passphrase(
        &self,
        signing_package: SigningPackage,
        nonce: FrostNonce,
        passphrase: String,
        email: String,
    ) -> Result<SignatureShare, FrostError> {
        let key_package = decrypt_with_mnemonic(
            self.pass_phrase_part.pass_phrase_encrypted_blob.clone(),
            passphrase,
            email,
        )?;
        let package = KeyPackage::deserialize(&key_package)
            .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
        let nonce = SigningNonces::deserialize(nonce.nonce.as_slice())
            .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
        let signature_share = frost::round2::sign(&signing_package, &nonce, &package)
            .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
        Ok(signature_share)
    }
    pub fn round1_from_split(&self) -> Result<Vec<(Commitment, FrostNonce)>, FrostError> {
        let mut commitments = vec![];

        for Split {
            identifier,
            package,
        } in &self.splits
        {
            let mut identifier_bytes: [u8; 32] = [0; 32];
            identifier_bytes.copy_from_slice(identifier);
            let identifier = Identifier::deserialize(&identifier_bytes)
                .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
            let package = KeyPackage::deserialize(package)
                .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;
            let (nonces, c) = frost::round1::commit(package.signing_share(), &mut OsRng);
            commitments.push((
                Commitment {
                    identifier: identifier.serialize().to_vec(),
                    signing_commitment: c
                        .serialize()
                        .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?,
                },
                FrostNonce {
                    identifier: identifier.serialize().to_vec(),
                    nonce: nonces
                        .serialize()
                        .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?,
                },
            ));
        }
        Ok(commitments)
    }
    pub fn round1_from_passphrase(
        &self,
        passphrase: String,
        email: String,
    ) -> Result<(Commitment, FrostNonce), FrostError> {
        let key_package = decrypt_with_mnemonic(
            self.pass_phrase_part.pass_phrase_encrypted_blob.clone(),
            passphrase,
            email,
        )?;
        let key_package = KeyPackage::deserialize(&key_package)
            .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?;

        let (n, c) = frost::round1::commit(key_package.signing_share(), &mut OsRng);

        Ok((
            Commitment {
                identifier: self.pass_phrase_part.pass_phrase_identifier.to_vec(),
                signing_commitment: c
                    .serialize()
                    .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?,
            },
            FrostNonce {
                identifier: self.pass_phrase_part.pass_phrase_identifier.to_vec(),
                nonce: n
                    .serialize()
                    .map_err(|e| FrostError::FrostSigningFailed(anyhow!(e)))?,
            },
        ))
    }
}

/// Using a mnemonic use BIP39 to recover bytes, together with the email address used to derive key material and decrypt cipher text.
pub fn decrypt_with_mnemonic(
    cipher_text: Vec<u8>,
    bip39_str: String,
    email: String,
) -> Result<Vec<u8>, FrostError> {
    let (key, iv) = derive_key_material(bip39_str, email)
        .map_err(|e| FrostError::InvalidPassphrase(anyhow!(e)))?;
    let cipher = aes_gcm::Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce = Nonce::from_slice(&iv);
    cipher
        .decrypt(nonce, cipher_text.as_slice())
        .map_err(|e| FrostError::InvalidPassphrase(anyhow!(e)))
}
/// Using a mnemonic use BIP39 to recover bytes, together with the email address to derive key material and encrypt the plaintext
fn encrypt_with_mnemonic(
    plaintext: Vec<u8>,
    bip39_str: String,
    email: String,
) -> Result<Vec<u8>, FrostError> {
    let (key, iv) = derive_key_material(bip39_str, email)?;
    let cipher = aes_gcm::Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce = Nonce::from_slice(&iv);
    cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| FrostError::AesFailed(anyhow!(e)))
}
/// Using BIP39 recover the 4 bytes of entropy and use it to derive a seed together with the email address.
fn derive_key_material(bip39_str: String, email: String) -> Result<(Vec<u8>, Vec<u8>), FrostError> {
    let mnemonics: Mnemonics<4> = Mnemonics::from_string(&ENGLISH, &bip39_str)
        .map_err(|e| FrostError::BipFailed(anyhow!(e)))?;
    let seed: [u8; 32 + 12] = seed_from_mnemonics(&ENGLISH, &mnemonics, email.as_bytes(), 2048);
    Ok((seed[..32].to_vec(), seed[32..].to_vec()))
}
/// Generate a BIP39 compliant mnemonic
/// Note: Currently only english language is supported
fn generate_bip39() -> Result<String, FrostError> {
    let entropy: [u8; 5] = rand::random();
    let entropy = Entropy(entropy);
    let mnemonics: Mnemonics<4> = entropy
        .to_mnemonics::<4, 4>()
        .map_err(|e| FrostError::BipFailed(anyhow!(e)))?;
    Ok(mnemonics.to_string(&ENGLISH))
}

#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
/// A trait to allow prompting the user for the passphrase
pub trait EnterPassphrase: Sync + Send + Debug {
    fn passphrase(&self) -> String;
}

#[cfg_attr(all(feature = "uniffi", feature = "reqwest"), derive(uniffi::Object))]
/// A struct using frost to authenticate towards the cloud HSM to derive P256 signatures.
#[cfg(all(feature = "uniffi", feature = "reqwest"))]
pub struct FrostHsm {
    email: String,
    passphrase_callback: Arc<dyn EnterPassphrase>,
    uuid: Mutex<Option<String>>,
    attestation: Mutex<Option<String>>,
    frost_signer: Arc<FrostSigner>,
    client: Client,
    base_url: String,
}

#[async_trait]
#[cfg(all(feature = "uniffi", feature = "reqwest"))]
impl HsmSupport for FrostHsm {
    fn get_wallet_attestation(&self) -> Option<String> {
        FrostHsm::get_wallet_attestation(self)
    }
    async fn generate_pop(
        &self,
        client_id: String,
        credential_issuer_url: String,
    ) -> Option<String> {
        FrostHsm::generate_pop(self, client_id, credential_issuer_url).await
    }
}

#[cfg_attr(
    all(feature = "uniffi", feature = "reqwest"),
    uniffi::export(async_runtime = "tokio")
)]
#[cfg(all(feature = "uniffi", feature = "reqwest"))]
impl FrostHsm {
    #[uniffi::constructor]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    /// Create new FrostHsm Client with the respective frost signer
    ///
    /// SAFETY:
    /// ClientBuilder does not panic
    pub fn new(
        base_url: String,
        email: String,
        passphrase_callback: Arc<dyn EnterPassphrase>,
        frost_signer: Arc<FrostSigner>,
    ) -> Self {
        Self {
            uuid: Mutex::new(None),
            attestation: Mutex::new(None),
            email,
            passphrase_callback,
            frost_signer,
            client: get_reqwest_client().build().unwrap(),
            base_url,
        }
    }
    #[uniffi::constructor]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    /// Construct a FrostHsm client from the HSM UUID
    ///
    /// SAFETY:
    /// CLient builder does not panic
    #[cfg(feature = "reqwest")]
    pub fn with_uuid(
        base_url: String,
        email: String,
        passphrase_callback: Arc<dyn EnterPassphrase>,
        uuid: String,
        attestation: String,
        frost_signer: Arc<FrostSigner>,
    ) -> Self {
        Self {
            email,
            uuid: Mutex::new(Some(uuid)),
            attestation: Mutex::new(Some(attestation)),
            frost_signer,
            passphrase_callback,
            client: get_reqwest_client().build().unwrap(),
            base_url,
        }
    }
    /// Generate Proof of Possesion for the wallet attestation
    pub async fn generate_pop(
        &self,
        client_id: String,
        credential_issuer_url: String,
    ) -> Option<String> {
        let pop_header = serde_json::json!(        {
          "alg": "ES256"
        });
        let now = std::time::SystemTime::now();
        let Ok(unix_timestamp) = now.duration_since(std::time::UNIX_EPOCH) else {
            return None;
        };
        use std::ops::Add;
        let expires = unix_timestamp.add(std::time::Duration::from_secs(360));
        let nbf = unix_timestamp.as_secs();
        let exp = expires.as_secs();
        let rng = &mut OsRng;
        use rand::Rng;
        let uuid = uuid::Builder::from_random_bytes(rng.gen())
            .into_uuid()
            .to_string();

        let pop_body = serde_json::json!({
          "iss": client_id,
          "aud": credential_issuer_url,
          "nbf":nbf,
          "exp":exp,
          "jti": uuid
        });

        let encoded_pop = encode_jwt(&pop_header, &pop_body);

        let Ok(pop_hsm_bytes) = self.sign(encoded_pop.as_bytes().to_vec()).await else {
            return None;
        };

        use base64::Engine;
        let pop_signature: p256::ecdsa::Signature =
            p256::ecdsa::Signature::from_slice(&pop_hsm_bytes).ok()?;
        let pop_bytes = pop_signature.to_vec();
        let pop_base64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(pop_bytes);
        Some(format!("{encoded_pop}.{pop_base64}"))
    }
    /// Return cached wallet attestation
    pub fn get_wallet_attestation(&self) -> Option<String> {
        {
            let Ok(lock) = self.attestation.lock() else {
                return None;
            };
            lock.clone()
        }
    }
    /// Register a new client on the HSM using frost authentication
    pub async fn register(self: &Arc<Self>) -> Result<HsmRegistrationResult, ApiError> {
        let coder = base64::prelude::BASE64_URL_SAFE_NO_PAD;
        let (key_nonce, mut nonce) = self.get_nonce("register").await?;
        let public_key = self
            .frost_signer
            .get_public_key()
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?;
        nonce.extend_from_slice(&public_key);
        let signature = self
            .frost_signer
            .sign(
                nonce.clone(),
                self.passphrase_callback.passphrase(),
                self.email.clone(),
            )
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?;

        let group_pub = coder.encode(&public_key);
        let user_device_signed_nonce = coder.encode(signature);

        let register_request = json!({
            "groupPub" : group_pub,
            "userDeviceSignedNonce" : user_device_signed_nonce,
            "keyNonce" : key_nonce
        });
        //https://sprind-eudi-hsm-connector-ws-dev.ubique.ch/v1
        let result = self
            .client
            .post(format!("{}/register/frost/finalize", self.base_url))
            .json(&register_request)
            .send()
            .await
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?
            .json::<HsmRegistrationResult>()
            .await
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?;

        {
            let Ok(mut lock) = self.uuid.lock() else {
                return Err(FrostHsmError::UnknownError.into());
            };
            *lock = Some(result.uuid.clone());
        };
        {
            let Ok(mut lock) = self.attestation.lock() else {
                return Err(FrostHsmError::UnknownError.into());
            };
            *lock = Some(result.wallet_attestation.clone());
        };
        Ok(result)
    }
    /// Sign payload using Frost HSM. Issues a P256 signature. Uses frost for authentication with the
    /// HSM API.
    pub async fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, ApiError> {
        let coder = base64::prelude::BASE64_URL_SAFE_NO_PAD;
        let uuid = {
            let Ok(lock) = self.uuid.lock() else {
                return Err(FrostHsmError::UnknownError.into());
            };
            let Some(uuid) = lock.as_ref() else {
                return Err(FrostHsmError::UnknownError.into());
            };
            uuid.clone()
        };
        let (key_nonce, mut nonce) = self.get_nonce_with_uuid(&uuid, "sign").await?;
        let public_key = self
            .frost_signer
            .get_public_key()
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?;
        nonce.extend_from_slice(&public_key);
        let signature = self.frost_signer.sign(
            nonce.clone(),
            self.passphrase_callback.passphrase(),
            self.email.clone(),
        )?;
        use sha2::Digest;
        let shasum = sha2::Sha256::digest(&payload);
        let payload = base64::prelude::BASE64_URL_SAFE.encode(shasum);
        let user_device_signed_nonce = coder.encode(signature);

        let sign_payload = json!({"userDeviceSignedNonce" : user_device_signed_nonce, "payload" : payload, "keyNonce": key_nonce, "uuid" : self.uuid});

        let result = self
            .client
            .post(format!("{}/sign/frost/finalize", self.base_url))
            .json(&sign_payload)
            .send()
            .await?;
        if result.status() == StatusCode::UNAUTHORIZED {
            return Err(HsmError::InvalidPin.into());
        }
        let result: Value = result.json().await?;
        let Some(signature) = result.get("signature").and_then(|a| a.as_str()) else {
            return Err(FrostHsmError::CouldNotGetNonce(anyhow!("no signature")).into());
        };
        let Ok(signature_bytes) = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(signature) else {
            return Err(FrostHsmError::CouldNotGetNonce(anyhow!("no signature")).into());
        };
        Ok(signature_bytes)
    }
    /// Refresh wallet attestation
    pub async fn refresh_wallet_attestation(
        self: &Arc<Self>,
    ) -> Result<WalletAttestationResult, ApiError> {
        let coder = base64::prelude::BASE64_URL_SAFE_NO_PAD;
        let uuid = {
            let Ok(lock) = self.uuid.lock() else {
                return Err(FrostHsmError::UnknownError.into());
            };
            let Some(uuid) = lock.as_ref() else {
                return Err(FrostHsmError::UnknownError.into());
            };
            uuid.clone()
        };
        let (key_nonce, mut nonce) = self
            .get_nonce_with_uuid(&uuid, "attestation")
            .await
            .map_err(|_e| FrostHsmError::UnknownError)?;
        let public_key = self
            .frost_signer
            .get_public_key()
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?;
        nonce.extend_from_slice(&public_key);
        let signature = self
            .frost_signer
            .sign(
                nonce.clone(),
                self.passphrase_callback.passphrase(),
                self.email.clone(),
            )
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?;
        let user_device_signed_nonce = coder.encode(signature);

        let payload = json!({"userDeviceSignedNonce" : user_device_signed_nonce, "keyNonce": key_nonce, "uuid" : self.uuid});

        let result = self
            .client
            .post(format!("{}/attestation/frost/finalize", self.base_url))
            .json(&payload)
            .send()
            .await
            .map_err(|_e| FrostHsmError::UnknownError)?
            .error_for_status()?;
        let result: WalletAttestationResult = result.json().await?;

        Ok(result)
    }
}
#[cfg(all(feature = "reqwest", feature = "uniffi"))]
impl FrostHsm {
    /// Get nonce for registration process
    pub async fn get_nonce(
        self: &Arc<Self>,
        nonce_type: &str,
    ) -> Result<(String, Vec<u8>), ApiError> {
        let client = get_reqwest_client()
            .build()
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?;
        let coder = base64::prelude::BASE64_URL_SAFE_NO_PAD;
        let nonce = client
            .get(format!("{}/{nonce_type}/frost/start", self.base_url))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        let Some(key_nonce) = nonce
            .get("pinNonce")
            .and_then(|a| a.as_str())
            .map(|a| a.to_string())
        else {
            return Err(
                FrostHsmError::CouldNotGetNonce(anyhow!("No nonce in resutl: {nonce}")).into(),
            );
        };
        let nonce = coder
            .decode(&key_nonce)
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?;
        Ok((key_nonce, nonce))
    }
    /// Get a nonce for various HSM opperations
    pub async fn get_nonce_with_uuid(
        &self,
        uuid: &str,
        nonce_type: &str,
    ) -> Result<(String, Vec<u8>), ApiError> {
        let client = get_reqwest_client()
            .build()
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?;
        let coder = base64::prelude::BASE64_URL_SAFE_NO_PAD;
        let nonce = client
            .post(format!("{}/{nonce_type}/frost/start", self.base_url))
            .json(&json!({"uuid" : uuid}))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        let Some(key_nonce) = nonce
            .get("pinNonce")
            .and_then(|a| a.as_str())
            .map(|a| a.to_string())
        else {
            return Err(
                FrostHsmError::CouldNotGetNonce(anyhow!("No nonce in resutl: {nonce}")).into(),
            );
        };
        let nonce = coder
            .decode(&key_nonce)
            .map_err(|e| FrostHsmError::CouldNotGetNonce(anyhow!(e)))?;
        Ok((key_nonce, nonce))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod test {

    use crate::frost::{EnterPassphrase, FrostHsm};

    use super::FrostSigner;
    use std::sync::Arc;

    #[test]
    fn test_api() {
        let frost_signer = FrostSigner::new(3, 3, "test@example.ch".to_string()).unwrap();
        let splits = frost_signer.splits;
        let mut pass_phrase_part = frost_signer.pass_phrase_part;
        let pub_key_package = frost_signer.pub_key_package;
        let pass_phrase = pass_phrase_part.pass_phrase.take().unwrap();
        let signature_msg = b"test".to_vec();
        let frost_signer = Arc::new(FrostSigner::from_packages(
            splits,
            pass_phrase_part,
            pub_key_package,
        ));
        let signature = frost_signer
            .sign(
                signature_msg.clone(),
                pass_phrase.clone(),
                "test@example.ch".to_string(),
            )
            .unwrap();
        assert!(frost_signer
            .verify(signature_msg.clone(), signature.clone())
            .is_ok());

        // can we verify the signature with edward?
        let mut vk_bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] =
            [0; ed25519_dalek::PUBLIC_KEY_LENGTH];
        vk_bytes.copy_from_slice(&frost_signer.get_public_key().unwrap());
        let vk: ed25519_dalek::VerifyingKey =
            ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).unwrap();
        let sig: ed25519_dalek::Signature =
            ed25519_dalek::Signature::from_slice(signature.as_slice()).unwrap();
        assert!(vk.verify_strict(&signature_msg, &sig).is_ok());
    }

    #[test]
    fn test_we_need_at_least_min_signer() {
        let frost_signer = FrostSigner::new(3, 5, "test@example.ch".to_string()).unwrap();
        let mut splits = frost_signer.splits;
        splits.pop();
        splits.pop();
        let mut pass_phrase_part = frost_signer.pass_phrase_part;
        let pub_key_package = frost_signer.pub_key_package;
        let pass_phrase = pass_phrase_part.pass_phrase.take().unwrap();

        let signature_msg = b"test".to_vec();
        let frost_signer = Arc::new(FrostSigner::from_packages(
            splits.clone(),
            pass_phrase_part.clone(),
            pub_key_package.clone(),
        ));
        let signature = frost_signer
            .sign(
                signature_msg.clone(),
                pass_phrase.clone(),
                "test@example.ch".to_string(),
            )
            .unwrap();
        assert!(frost_signer.verify(signature_msg, signature).is_ok());

        splits.pop();
        let signature_msg = b"test".to_vec();
        let frost_signer = Arc::new(FrostSigner::from_packages(
            splits.clone(),
            pass_phrase_part,
            pub_key_package,
        ));
        // we cannot sign with fewer than min_signer signers
        assert!(frost_signer
            .sign(
                signature_msg.clone(),
                pass_phrase.clone(),
                "test@example.ch".to_string(),
            )
            .is_err());
    }

    #[tokio::test]
    async fn test_hsm() {
        let mut frost_signer = FrostSigner::new(3, 3, "test@example.ch".to_string()).unwrap();
        let passphrase = frost_signer.pass_phrase_part.pass_phrase.take().unwrap();
        #[derive(Debug)]
        struct Passphraser(String);

        impl EnterPassphrase for Passphraser {
            fn passphrase(&self) -> String {
                self.0.clone()
            }
        }

        let frost_signer = Arc::new(frost_signer);
        let frost_hsm = Arc::new(FrostHsm::new(
            "https://sprind-eudi-hsm-connector-ws-dev.ubique.ch/v1".to_string(),
            "test@example.ch".to_string(),
            Arc::new(Passphraser(passphrase)),
            frost_signer,
        ));

        let result = frost_hsm.register().await.unwrap();
        let signature = frost_hsm.sign(b"test_payload".to_vec()).await.unwrap();
        let attestation = frost_hsm.refresh_wallet_attestation().await.unwrap();

        println!("{}: {}", result.uuid, result.wallet_attestation);
        println!("signature {signature:?}");
        println!("new attestation: {}", attestation.wallet_attestation);
    }
}
