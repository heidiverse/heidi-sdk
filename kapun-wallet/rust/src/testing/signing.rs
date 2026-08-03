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
use std::fmt::Debug;
use std::sync::Arc;

//use did_key::{generate, CoreSign, KeyMaterial, P256KeyPair, PatchedKeyPair};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::rngs::OsRng;

use crate::error::SigningError;
#[cfg(feature = "uniffi")]
use crate::issuance::helper::bytes_to_ec_jwk;
#[cfg(feature = "uniffi")]
use crate::signing::NativeSigner;

#[derive(Debug)]
pub struct TestSigner {
    key: SigningKey,
}

impl TestSigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }
}

#[cfg(feature = "uniffi")]
impl NativeSigner for TestSigner {
    fn sign(&self, msg: String) -> Result<Vec<u8>, SigningError> {
        self.sign_bytes(msg.as_bytes().to_vec())
    }

    fn sign_bytes(&self, msg: Vec<u8>) -> Result<Vec<u8>, SigningError> {
        let signature: Signature = self.key.sign(&msg);
        Ok(signature.to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_sec1_bytes().to_vec()
    }

    fn key_id(&self) -> String {
        String::from("testkey")
    }

    fn jwt_header(&self) -> String {
        let jwk = bytes_to_ec_jwk(self.public_key()).unwrap_or_default();
        let output =
            format!("{{\"typ\":\"openid4vci-proof+jwt\",\"alg\":\"ES256\",\"jwk\" : {jwk} }}");
        output
    }

    fn alg(&self) -> String {
        "ES256".to_string()
    }
    fn key_reference(&self) -> Vec<u8> {
        b"test_key".to_vec()
    }

    fn public_key_jwk(&self) -> String {
        bytes_to_ec_jwk(self.public_key()).unwrap_or_default()
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

#[cfg(feature = "uniffi")]
pub fn new_native_signer() -> Arc<dyn NativeSigner> {
    Arc::new(TestSigner::new(SigningKey::random(&mut OsRng)))
}
