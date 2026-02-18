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

use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD, BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD},
};

pub mod crypto;
pub mod iso180135;
pub mod jws;
pub mod jwt;

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
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

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    if let Ok(decoded) = BASE64_URL_SAFE_NO_PAD.decode(input) {
        return Some(decoded);
    }
    if let Ok(decoded) = BASE64_URL_SAFE.decode(input) {
        return Some(decoded);
    }
    if let Ok(decoded) = BASE64_STANDARD_NO_PAD.decode(input) {
        return Some(decoded);
    }
    if let Ok(decoded) = BASE64_STANDARD.decode(input) {
        return Some(decoded);
    }
    return None;
}

uniffi::setup_scaffolding!();
