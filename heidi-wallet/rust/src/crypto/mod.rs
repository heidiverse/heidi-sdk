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

//! Exposing some utilities for encoding/decoding, signing and hashing.

use std::sync::Arc;

#[cfg(feature = "uniffi")]
use crate::signing::NativeSigner;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use ciborium::Value;
use sha2::Digest;

pub mod encryption;
pub mod signing;

/// Base64 url encode bytes using no padding
pub fn b64url_encode_bytes(bytes: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Base64 URL decode bytes using no padding
pub fn b64url_decode_bytes(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_URL_SAFE_NO_PAD.decode(value)
}

/// Sha256 digest helper function
pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);

    hasher.finalize().to_vec()
}

/// Construct a CoseSign1 struct and signing it with the respective [NativeSigner] (usually a callback into Kotlin/Swift code).
#[cfg(feature = "uniffi")]
pub fn cose_sign1(
    body_protected: Vec<u8>,
    external_aad: Vec<u8>,
    payload: Vec<u8>,
    signer: Arc<dyn NativeSigner>,
) -> anyhow::Result<Vec<u8>> {
    let context = String::from("Signature1");

    // 1. Create a Sig_structure and populate it with the appropriate
    //    fields.
    let sig_structure = Value::Array(vec![
        Value::Text(context),
        Value::Bytes(body_protected),
        Value::Bytes(external_aad),
        Value::Bytes(payload),
    ]);

    // 2. Create the value ToBeSigned by encoding the Sig_structure to a
    //    byte string, using the encoding described in Section 14 (CBOR).
    let mut to_be_signed = Vec::<u8>::new();
    ciborium::into_writer(&sig_structure, &mut to_be_signed)?;

    // 3. Call the signature creation algorithm passing in K (the key to
    //    sign with), alg (the algorithm to sign with), and ToBeSigned (the
    //    value to sign).
    let signature = signer.sign_bytes(to_be_signed)?;

    Ok(signature)
}
