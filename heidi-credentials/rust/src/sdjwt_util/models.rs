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

use heidi_util_rust::value::Value;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]

pub struct Header {
    #[uniffi(default = "sd-jwt")]
    pub typ: String,
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[uniffi(default = None)]
    pub cty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[uniffi(default = None)]
    pub jku: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[uniffi(default = None)]
    pub jwk: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[uniffi(default = None)]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[uniffi(default = None)]
    pub x5u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[uniffi(default = None)]
    pub x5c: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[uniffi(default = None)]
    pub x5t: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[uniffi(default = None)]
    pub x5t_s256: Option<String>,
}

impl Header {
    pub fn new(algorithm: &str) -> Self {
        Header {
            typ: "sd-jwt".to_string(),
            alg: algorithm.to_string(),
            cty: None,
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
        }
    }
}

impl Default for Header {
    fn default() -> Self {
        Header::new("ES256")
    }
}
