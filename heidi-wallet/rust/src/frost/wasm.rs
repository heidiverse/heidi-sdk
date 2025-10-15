
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

//! Expose FROST signature functions to wasm (aka Browser)

use wasm_bindgen::prelude::wasm_bindgen;

use crate::frost::{deserialize_frost_backup, serialize_frost_backup};

use super::FrostSigner;

#[wasm_bindgen]
pub struct FrostSignerWasm {
    inner: FrostSigner,
}

#[wasm_bindgen]
impl FrostSignerWasm {
    pub fn new(
        min_signers: u16,
        max_signers: u16,
        email: String,
    ) -> Result<FrostSignerWasm, String> {
        let inner =
            FrostSigner::new(min_signers, max_signers, email).map_err(|e| format!("{e}"))?;
        Ok(FrostSignerWasm { inner })
    }
    pub fn from_packages(frost_backup: String) -> Result<FrostSignerWasm, String> {
        let Some(backup) = deserialize_frost_backup(frost_backup) else {
            return Err("Could not deserialize".into());
        };
        let inner = FrostSigner::from_packages(
            backup.splits,
            backup.pass_phrase_part.into(),
            backup.pub_key_package,
        );
        Ok(FrostSignerWasm { inner })
    }
    pub fn get_backup_payload(&self) -> String {
        serialize_frost_backup(self.inner.get_backup_payload()).unwrap_or_default()
    }
    pub fn get_passphrase(&self) -> Option<String> {
        self.inner.pass_phrase_part.pass_phrase.clone()
    }
    pub fn get_public_key(&self) -> Result<Vec<u8>, String> {
        self.inner.get_public_key().map_err(|e| format!("{e}"))
    }
    pub fn get_alg(&self) -> String {
        self.inner.get_alg()
    }
    pub fn get_public_key_as_jwk(&self) -> Result<String, String> {
        self.inner
            .get_public_key_as_jwk()
            .map_err(|e| format!("{e}"))
    }
    pub fn sign(
        &self,
        payload: Vec<u8>,
        passphrase: String,
        email: String,
    ) -> Result<Vec<u8>, String> {
        self.inner
            .sign(payload, passphrase, email)
            .map_err(|e| format!("{e}"))
    }
    pub fn verify(&self, msg: Vec<u8>, gs: Vec<u8>) -> Result<(), String> {
        self.inner.verify(msg, gs).map_err(|e| format!("{e}"))
    }
}
