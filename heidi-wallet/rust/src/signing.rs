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
//! Traits for signing. Wallets use these traits to implement secure hardware
//! specific signing.
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use oid4vc::oid4vc_core::authentication::sign::ExternalSign;
use oid4vc::oid4vc_core::{Sign, Subject, Verify};
use oid4vc::oid4vci::jsonwebtoken;
use sdjwt::ExternalSigner;

use crate::error::SigningError;

#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
/// A Trait which enables secure hardware signing
pub trait NativeSigner: Send + Sync + Debug {
    fn key_reference(&self) -> Vec<u8>;
    fn private_key(&self) -> Result<Vec<u8>, SigningError>;
    fn sign(&self, msg: String) -> Result<Vec<u8>, SigningError>;
    fn sign_bytes(&self, msg: Vec<u8>) -> Result<Vec<u8>, SigningError>;
    fn public_key(&self) -> Vec<u8>;
    fn key_id(&self) -> String;
    fn jwt_header(&self) -> String;
    fn alg(&self) -> String;
    fn public_key_jwk(&self) -> String;
    fn private_key_exportable(&self) -> bool;
    fn key_attestation(&self) -> Option<String>;
}

#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
/// A trait that enables signing a series of messagers at once
pub trait BatchSigner: Send + Sync + Debug {
    fn batch_sign(&self, msg: Vec<String>) -> Result<Vec<Vec<u8>>, SigningError>;
    fn batch_sign_bytes(&self, msg: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, SigningError>;
}

#[derive(Clone, Copy, Debug)]
#[derive(PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeyType {
    Software,    // lowest level, software-based key management
    DeviceBound, // secure, device-bound keys
    RemoteHSM,
    None // for claim based binding
}

#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait SignerFactory: Send + Sync + Debug {
    fn new_signer(&self, key_type: KeyType) -> Arc<dyn NativeSigner>;
}

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
/// A [Subject] implementation using a [NativeSigner]
pub struct SecureSubject {
    pub(crate) signer: Arc<dyn NativeSigner>,
}

impl SecureSubject {
    pub fn get_key_reference(self: &Arc<Self>) -> Vec<u8> {
        self.signer.key_reference()
    }
}

impl ExternalSign for SecureSubject {
    fn sign(&self, message: &str) -> anyhow::Result<Vec<u8>> {
        let Ok(signature) = self.signer.sign(message.to_string()) else {
            bail!("failed to sign")
        };
        Ok(signature)
    }
}

impl ExternalSigner for SecureSubject {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, sdjwt::Error> {
        match self.signer.sign_bytes(payload.to_vec()) {
            Ok(signature) => Ok(signature),
            Err(SigningError::InvalidSecret) => {
                Err(sdjwt::Error::SigningFailed("InvalidSecret".to_string()))
            }
            _ => Err(sdjwt::Error::InvalidDisclosureKey(
                "Could not sign with external signer".to_string(),
            )),
        }
    }

    fn alg(&self) -> String {
        self.signer.alg()
    }
}

#[async_trait]
impl Verify for SecureSubject {
    async fn public_key(&self, kid: &str) -> anyhow::Result<Vec<u8>> {
        SecureSubject::public_key(self, kid).await
    }
}

#[async_trait]
impl Sign for SecureSubject {
    async fn jwt_header(&self) -> jsonwebtoken::Header {
        let header_string = self.signer.jwt_header();
        serde_json::from_str(&header_string).unwrap_or(jsonwebtoken::Header::default())
    }
    async fn key_id(&self, subject_syntax_type: &str) -> Option<String> {
        let Ok(key_id) = self.identifier(subject_syntax_type).await else {
            return None;
        };
        Some(key_id)
    }
    async fn sign(&self, message: &str, _: &str) -> anyhow::Result<Vec<u8>> {
        self.signer
            .sign(message.to_string())
            .map_err(|e| anyhow!(e))
    }
    fn external_signer(&self) -> Option<Arc<dyn ExternalSign>> {
        None
    }
}

#[async_trait]
impl Subject for SecureSubject {
    async fn identifier(&self, subject_syntax_type: &str) -> anyhow::Result<String> {
        let codec: &[u8] = &[0x80, 0x24];
        let data = [codec, self.signer.public_key().as_ref()].concat();
        Ok(format!(
            "{subject_syntax_type}:z{}",
            bs58::encode(data).into_string()
        ))
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SecureSubject {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn with_signer(signer: Arc<dyn NativeSigner>) -> Self {
        Self { signer }
    }
}
