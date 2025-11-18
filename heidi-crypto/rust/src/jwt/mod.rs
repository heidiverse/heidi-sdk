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

use std::str::FromStr;

use crate::crypto::{
    base64_url_decode,
    x509::{extract_certs, X509Certificate},
};
use base64::{prelude::BASE64_STANDARD, Engine};
use heidi_jwt::{
    jwt::{
        ec_verifier_from_sec1, verifier::DefaultVerifier, verifier_for_der, verifier_for_jwk, Jwt,
        JwtVerifier,
    },
    Jwk, JwsHeader,
};
use heidi_util_rust::{log_error, log_warn, value::Value};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[uniffi::export]
pub fn parse_encoded_jwt_header(jwt: String) -> Option<String> {
    let jwt = Jwt::<Value>::from_str(&jwt).ok()?;
    serde_json::to_string_pretty(jwt.header().ok()?.claims_set()).ok()
}

#[uniffi::export]
pub fn parse_encoded_jwt_payload(jwt: String) -> Option<String> {
    let jwt = Jwt::<Value>::from_str(&jwt).ok()?;
    serde_json::to_string_pretty(jwt.payload_unverified().insecure()).ok()
}

#[uniffi::export]
pub fn parse_and_verify_encoded_jwt_payload(jwt: String) -> Option<String> {
    let jwt = Jwt::<Value>::from_str(&jwt).ok()?;
    let p = jwt
        .payload_with_verifier_from_header(&SimpleVerifier)
        .ok()?;
    serde_json::to_string_pretty(p).ok()
}

#[uniffi::export]
pub fn validate_jwt_signature(jwt: &str, jwt_type: &str) -> bool {
    let Ok(jwt) = Jwt::<serde_json::Value>::from_str(jwt) else {
        return false;
    };
    let public_ca = match BASE64_STANDARD.decode(PUBLIC_KEY) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let Some(verifier) = ec_verifier_from_sec1(&public_ca, "P-256") else {
        return false;
    };
    let Ok(_) = jwt.verify_signature_with_verifier(verifier.as_ref()) else {
        return false;
    };
    let Ok(_) = jwt.verify(&DefaultVerifier::new(jwt_type.to_string(), vec![])) else {
        return false;
    };
    true
}

pub struct SimpleVerifier;

impl<T: Serialize + DeserializeOwned> JwtVerifier<T> for SimpleVerifier {
    fn verify_header(&self, _jwt: &Jwt<T>) -> Result<(), heidi_jwt::models::errors::JwtError> {
        Ok(())
    }

    fn verify_body(&self, _jwt: &Jwt<T>) -> Result<(), heidi_jwt::models::errors::JwtError> {
        Ok(())
    }
}

const PUBLIC_KEY: &str =
    "BB5YD+gnv9Nt34RiVpy3SC7vN7vhbnYuDAXrIuna1XtjVM1E+9/iPeuv0HLh1OFFKdBUTUOv1nBOO++UDfzGGjY=";

#[uniffi::export]
/// Get x509 Chain from JWT Header
pub fn get_x509_from_jwt(jwt: String) -> Option<Vec<X509Certificate>> {
    let jwt = Jwt::<serde_json::Value>::from_str(&jwt).ok()?;
    let header = jwt.header().ok()?;
    let jws_header: &JwsHeader = header.as_any().downcast_ref()?;
    let x5c = jws_header.x509_certificate_chain()?;

    let mut certs = vec![];
    for c in x5c {
        let cert_list = extract_certs(c);
        let first = cert_list.first().cloned()?;
        certs.push(first);
    }
    Some(certs)
}

#[uniffi::export]
pub fn validate_jwt_with_pub_key(jwt: &str, pub_key: crate::crypto::x509::X509PublicKey) -> bool {
    let Ok(jwt) = Jwt::<serde_json::Value>::from_str(jwt) else {
        return false;
    };
    let verifier = match pub_key {
        crate::crypto::x509::X509PublicKey::P256 { x, y } => {
            let x_bytes = base64_url_decode(x);
            let y_bytes = base64_url_decode(y);
            let mut key = vec![0x04u8; 65];
            key[1..33].copy_from_slice(&x_bytes);
            key[33..].copy_from_slice(&y_bytes);
            let Some(verifier) = ec_verifier_from_sec1(&key, "P-256") else {
                return false;
            };
            verifier
        }
        crate::crypto::x509::X509PublicKey::Other { data } => {
            let Ok(verifier) = verifier_for_der(data.as_slice()) else {
                return false;
            };
            verifier
        }
    };
    // Perform full validation with signature check.
    jwt.verify_signature_with_verifier(verifier.as_ref())
        .is_ok()
}

#[uniffi::export]
pub fn validate_jwt_with_jwk(jwt: &str, jwk: Value) -> bool {
    let Ok(jwt) = Jwt::<serde_json::Value>::from_str(jwt) else {
        return false;
    };
    let Some(jwk) = jwk.transform::<Jwk>() else {
        return false;
    };

    let Some(verifier) = verifier_for_jwk(jwk) else {
        return false;
    };
    // Perform full validation with signature check.
    jwt.verify_signature_with_verifier(verifier.as_ref())
        .is_ok()
}

#[derive(Serialize, Deserialize, uniffi::Record)]
pub struct DidVerificationDocument {
    #[serde(rename = "verificationMethod")]
    verification_method: Vec<VerificationMethod>,
}

impl JwtVerifier<serde_json::Value> for DidVerificationDocument {
    fn verify_header(
        &self,
        _jwt: &Jwt<serde_json::Value>,
    ) -> Result<(), heidi_jwt::models::errors::JwtError> {
        Ok(())
    }

    fn verify_body(
        &self,
        _jwt: &Jwt<serde_json::Value>,
    ) -> Result<(), heidi_jwt::models::errors::JwtError> {
        Ok(())
    }
}

#[derive(Serialize, Deserialize, uniffi::Record)]
pub struct VerificationMethod {
    id: String,
    controller: String,
    #[serde(rename = "type")]
    ty: String,
    #[serde(rename = "publicKeyJwk")]
    public_key_jwk: Value,
}

#[uniffi::export]
pub fn parse_did_verification_document(doc: &Value) -> Option<DidVerificationDocument> {
    doc.transform()
}

#[uniffi::export]
pub fn get_kid_from_jwt(jwt: &str) -> Option<String> {
    let j = Jwt::<serde_json::Value>::from_str(jwt).ok()?;
    let header = j.header().ok()?;
    header
        .claim("kid")
        .and_then(|a| a.as_str())
        .map(|kid| kid.to_string())
}

#[uniffi::export]
pub fn validate_jwt_with_did_document(
    jwt: &str,
    doc: DidVerificationDocument,
    validate_aud: bool,
) -> bool {
    let Ok(jwt) = Jwt::<serde_json::Value>::from_str(jwt) else {
        log_error!("VALIDATER", "could not parse jwt");
        return false;
    };
    let header = match jwt.header() {
        Ok(header) => header,
        Err(_) => return false,
    };
    let Some(kid) = header.claim("kid").and_then(|a| a.as_str()) else {
        log_error!("VALIDATER", "no kid");
        return false;
    };
    log_warn!("VALIDATER", &format!("kid: {}", kid));

    let Some(key) = doc.verification_method.iter().find(|vm| vm.id == kid) else {
        log_error!("VALIDATER", "no matching key found");
        return false;
    };

    let Some(jwk) = key.public_key_jwk.transform() else {
        log_error!("VALIDATER", "failed to transform to jwk");
        return false;
    };
    let Some(verifier) = verifier_for_jwk(jwk) else {
        log_error!("VALIDATER", "could not parse jwk into key");
        return false;
    };

    let v: Box<dyn JwtVerifier<serde_json::Value>> = if validate_aud {
        Box::new(doc)
    } else {
        Box::new(SimpleVerifier)
    };

    jwt.payload_with_verifier(verifier.as_ref(), v.as_ref())
        .is_ok()
}

#[uniffi::export]
pub fn validate_jwt_with_did(jwt: &str, did: &Value) -> bool {
    let Value::Array(elements) = did else {
        log_error!("VALIDATER", "not an array");
        return false;
    };
    let Some(doc) = elements[3]
        .get("value")
        .and_then(|a| a.transform::<DidVerificationDocument>())
    else {
        log_error!("VALIDATER", "no value");
        return false;
    };
    validate_jwt_with_did_document(jwt, doc, true)
}

// Specifically for SD-JWTs and KB-JWTs
pub struct SdJwtVerifier;

impl<T: Serialize + DeserializeOwned> JwtVerifier<T> for SdJwtVerifier {
    fn verify_header(&self, jwt: &Jwt<T>) -> Result<(), heidi_jwt::models::errors::JwtError> {
        self.assert_type(jwt, "dc+sd-jwt")
    }

    fn verify_body(&self, _jwt: &Jwt<T>) -> Result<(), heidi_jwt::models::errors::JwtError> {
        Ok(())
    }
}

pub struct KbJwtVerifier;

impl<T: Serialize + DeserializeOwned> JwtVerifier<T> for KbJwtVerifier {
    fn verify_header(&self, jwt: &Jwt<T>) -> Result<(), heidi_jwt::models::errors::JwtError> {
        self.assert_type(jwt, "kb+jwt")
    }

    fn verify_body(&self, _jwt: &Jwt<T>) -> Result<(), heidi_jwt::models::errors::JwtError> {
        Ok(())
    }
}

#[uniffi::export]
pub fn validate_sd_jwt_with_did_document(
    sd_jwt_original_jwt: &str,
    doc: DidVerificationDocument,
) -> bool {
    let Ok(jwt) = Jwt::<serde_json::Value>::from_str(sd_jwt_original_jwt) else {
        log_error!("VALIDATER", "could not parse jwt");
        return false;
    };
    let header = match jwt.header() {
        Ok(header) => header,
        Err(_) => return false,
    };
    let Some(kid) = header.claim("kid").and_then(|a| a.as_str()) else {
        log_error!("VALIDATER", "no kid");
        return false;
    };
    log_warn!("VALIDATER", &format!("kid: {}", kid));

    let Some(key) = doc.verification_method.iter().find(|vm| vm.id == kid) else {
        log_error!("VALIDATER", "no matching key found");
        return false;
    };

    let Some(jwk) = key.public_key_jwk.transform() else {
        log_error!("VALIDATER", "failed to transform to jwk");
        return false;
    };
    let Some(verifier) = verifier_for_jwk(jwk) else {
        log_error!("VALIDATER", "could not parse jwk into key");
        return false;
    };

    jwt.payload_with_verifier(verifier.as_ref(), &SdJwtVerifier)
        .is_ok()
}

#[uniffi::export]
pub fn validate_kb_jwt_with_jwk(kb_jwt: &str, jwk: Value) -> bool {
    let Ok(jwt) = Jwt::<serde_json::Value>::from_str(kb_jwt) else {
        log_error!("VALIDATER", "could not parse jwt");
        return false;
    };
    let Some(jwk) = jwk.transform::<Jwk>() else {
        log_error!("VALIDATER", "failed to transform to jwk");
        return false;
    };

    let Some(verifier) = verifier_for_jwk(jwk) else {
        log_error!("VALIDATER", "could not parse jwk into key");
        return false;
    };
    // Perform full validation with signature check.
    jwt.payload_with_verifier(verifier.as_ref(), &KbJwtVerifier)
        .is_ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_jwk_parsing() {
        let jwk_str = r#"{"crv":"P-256","kty":"EC","x":"1fwnwoN8zatr6kD_bvwY2zQDV4D6blE7mzTliQF11Jc","y":"9-cDZlPqXVlJnE0rcUUyy7P_15x7RLE-jiNGqHA9FP4"}"#;
        match p256::PublicKey::from_jwk_str(jwk_str) {
            Ok(_) => {}
            Err(e) => {
                panic!("{e}");
            }
        }
    }
}
