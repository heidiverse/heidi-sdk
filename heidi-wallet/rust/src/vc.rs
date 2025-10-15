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
//! Traits for interfacing with a credential store on the wallets

use std::{collections::HashMap, fmt::Debug};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::ApiError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct VerifiableCredential {
    pub id: i64,

    pub identity_id: i64,

    pub name: String,

    pub metadata: String,

    pub payload: String,
}

impl VerifiableCredential {
    pub fn get_type(&self) -> Result<String, ApiError> {
        Ok(serde_json::from_str::<serde_json::Value>(&self.metadata)?
            .get("credentialType")
            .context("Credetial metadata does not have 'credentialType'")?
            .as_str()
            .context("'credentialType' is not a string!")?
            .to_owned())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PresentableCredential {
    /// The underlying VerifiableCredential
    pub credential: VerifiableCredential,

    /// A JSON Object holding the Vec<InputDescriptorMappingObject>
    pub descriptor_map: String,

    /// The values that will be presented
    pub values: HashMap<String, String>,
    /// The id for the credential
    pub response_id: String,
}
