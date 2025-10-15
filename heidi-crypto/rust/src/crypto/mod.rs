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

use base64::{prelude::BASE64_URL_SAFE, prelude::BASE64_URL_SAFE_NO_PAD, Engine};

use crate::SigningError;
use sha2::Digest;

pub mod eddsa;
pub mod multihash;
pub mod signing;
pub mod x509;

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

#[uniffi::export]
pub fn sha256_rs(input: Vec<u8>) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

#[uniffi::export]
pub fn blake3_hash(input: Vec<u8>) -> Vec<u8> {
    blake3::hash(input.as_slice()).as_bytes().to_vec()
}

#[uniffi::export]
pub fn base64_url_encode(input: Vec<u8>) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(input)
}

#[uniffi::export]
pub fn base64_url_decode(input: String) -> Vec<u8> {
    BASE64_URL_SAFE_NO_PAD.decode(input).unwrap()
}

#[uniffi::export]
pub fn base64_url_encode_pad(input: Vec<u8>) -> String {
    BASE64_URL_SAFE.encode(input)
}

#[uniffi::export]
pub fn base64_url_decode_pad(input: String) -> Vec<u8> {
    BASE64_URL_SAFE.decode(input).unwrap()
}

#[uniffi::export]
pub fn base58btc_encode(input: Vec<u8>) -> String {
    multibase::Base::Base58Btc.encode(&input)
}

#[uniffi::export]
pub fn base58btc_decode(input: &str) -> Vec<u8> {
    multibase::Base::Base58Btc.decode(input).unwrap()
}

#[uniffi::export]
pub fn truncated_hash(input: Vec<u8>, length: u64) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let size = result.len();
    result[..size.min(length as usize)].to_vec()
}

#[uniffi::export(with_foreign)]
pub trait SignatureCreator: Send + Sync {
    fn alg(&self) -> String;
    fn sign(&self, bytes: Vec<u8>) -> Result<Vec<u8>, SigningError>;
}

// /// Construct a CoseSign1 struct and signing it with the respective [NativeSigner] (usually a callback into Kotlin/Swift code).
// #[cfg(feature = "uniffi")]
// pub fn cose_sign1(
//     body_protected: Vec<u8>,
//     external_aad: Vec<u8>,
//     payload: Vec<u8>,
//     signer: Arc<dyn NativeSigner>,
// ) -> anyhow::Result<Vec<u8>> {
//     let context = String::from("Signature1");
//
//     // 1. Create a Sig_structure and populate it with the appropriate
//     //    fields.
//     let sig_structure = Value::Array(vec![
//         Value::Text(context),
//         Value::Bytes(body_protected),
//         Value::Bytes(external_aad),
//         Value::Bytes(payload),
//     ]);
//
//     // 2. Create the value ToBeSigned by encoding the Sig_structure to a
//     //    byte string, using the encoding described in Section 14 (CBOR).
//     let mut to_be_signed = Vec::<u8>::new();
//     ciborium::into_writer(&sig_structure, &mut to_be_signed)?;
//
//     // 3. Call the signature creation algorithm passing in K (the key to
//     //    sign with), alg (the algorithm to sign with), and ToBeSigned (the
//     //    value to sign).
//     let signature = signer.sign_bytes(to_be_signed)?;
//
//     Ok(signature)
// }
