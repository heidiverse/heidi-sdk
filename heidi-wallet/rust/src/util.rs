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
//! Various util functions

use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use rand::random;
use rand::rngs::OsRng;
use sha2::Digest;

/// *DANGER*: return unverified JWT payload.
/// Use with care
#[cfg(feature = "oid4vp")]
pub fn jwt_get_payload_unchecked(jwt: &str) -> anyhow::Result<String> {
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;

    let parts = jwt.split('.').collect::<Vec<_>>();

    if parts.len() != 3 {
        anyhow::bail!("JWT has less/more than 3 parts: jwt = {jwt}")
    }

    let payload = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(parts[1])?)?;

    Ok(payload)
}

pub fn generate_code_verifier_bytes() -> [u8; 32] {
    random()
}

#[cfg(feature = "oid4vp")]
pub fn generate_code_verifier() -> String {
    BASE64_URL_SAFE_NO_PAD.encode(generate_code_verifier_bytes())
}

#[cfg(feature = "oid4vp")]
pub fn generate_code_challenge(code_verifier: &str, code_challenge_method: &str) -> String {
    if code_challenge_method == "plain" {
        code_verifier.to_string()
    } else if code_challenge_method == "S256" {
        use base64::prelude::BASE64_URL_SAFE_NO_PAD;

        let mut sha = sha2::Sha256::new();
        sha.update(code_verifier.as_bytes());
        let bytes = sha.finalize().to_vec();
        BASE64_URL_SAFE_NO_PAD.encode(&bytes)
    } else {
        panic!(
            "logic error, unsupported code_challenge_method {}",
            code_challenge_method
        );
    }
}
/// Helper function to encode a jwt, and prepare it for signing
pub fn encode_jwt(header: &serde_json::Value, body: &serde_json::Value) -> String {
    let header_base64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_base64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(body.to_string());
    format!("{header_base64}.{payload_base64}")
}

pub fn generate_uuid_v4() -> String {
    let rng = &mut OsRng;
    use rand::Rng;
    uuid::Builder::from_random_bytes(rng.gen())
        .into_uuid()
        .to_string()
}

#[macro_export]
/// Helper macro to abstract common mutex opperations
macro_rules! lock {
    ($entity:expr) => {
        #[allow(unused_braces)]
        match $entity.lock() {
            Ok(guard) => guard,
            Err(e) => {
                panic!("{e}")
            }
        }
    };
    ($entity:expr => |$x:ident|  $theBlock:block ) => {
        match $entity.lock() {
            Ok(guard) => guard,
            Err($x) => return $theBlock,
        }
    };
}
