/* Copyright 2025 Ubique Innovation AG

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

use heidi_util_rust::value::{JsonNumber, Value};
use serde::{Deserialize, Serialize};
use std::{hash::Hash, sync::Arc};

use crate::claims_pointer::Selector;

pub type Pointer = Vec<PointerPart>;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Hash, uniffi::Enum)]
#[serde(untagged)]
pub enum PointerPart {
    String(String),
    Index(u64),
    Null(Option<bool>),
}

impl From<PointerPart> for Value {
    fn from(value: PointerPart) -> Self {
        match value {
            PointerPart::String(s) => Value::String(s.to_string()),
            PointerPart::Index(i) => Value::Number(JsonNumber::Integer(i as i64)),
            PointerPart::Null(_) => Value::Null,
        }
    }
}

impl From<&str> for PointerPart {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}
impl From<usize> for PointerPart {
    fn from(value: usize) -> Self {
        Self::Index(value as u64)
    }
}
impl<T> From<Option<T>> for PointerPart {
    fn from(_value: Option<T>) -> Self {
        Self::Null(None)
    }
}

#[derive(uniffi::Enum, Copy, Clone, Debug)]
pub enum SpecVersion {
    PotentialUc5, // Specification for LSP POTENTIAL Usecase 5 (QES) - final draft v2: Transaction data included verbatim in key-binding JWT
    Oid4VpDraft23, // OpenID for Verifiable Presentations - draft 23: Transaction data is hashed in key-binding JWT
}

pub const fn default_required() -> bool {
    true
}

#[derive(Debug, uniffi::Error)]
pub enum SigningError {
    FailedToSign,
    InvalidSecret,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:?}", self))
    }
}

impl std::error::Error for SigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[uniffi::export(with_foreign)]
pub trait SignatureCreator: Send + Sync {
    fn alg(&self) -> String;
    fn sign(&self, bytes: Vec<u8>) -> Result<Vec<u8>, SigningError>;
}

#[uniffi::export(with_foreign)]
pub trait ClaimGetter: Send + Sync {
    fn get(&self, pointer: Arc<dyn Selector>) -> Vec<Value>;
}
