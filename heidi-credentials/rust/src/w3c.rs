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

use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    sync::Arc,
};

use heidi_util_rust::value::Value;
use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::{
    claims_pointer::Selector,
    sdjwt_util::{self, Disclosure, DisclosureTree, SdJwtDecodeError},
};

#[derive(Debug, Clone, uniffi::Error)]
pub enum W3CParseError {
    SdJwtError(SdJwtDecodeError),
    NoType,
}

impl Display for W3CParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[derive(Debug, Clone, uniffi::Record, Serialize)]
pub struct W3CSdJwt {
    /// The credential document type
    pub doctype: String,

    /// The credential as a JSON object
    pub json: Value,

    /// The original JWT (SD-JWT without the disclosures and kb-jwt)
    pub original_jwt: String,

    /// The original SD-JWT
    pub original_sdjwt: String,

    /// The disclosure map, mapping sd-hashes to decoded disclosures
    pub disclosure_map: HashMap<String, Disclosure>,

    /// The disclosure tree, mapping paths to disclosures
    pub disclosure_tree: DisclosureTree,

    /// The number of disclosures in the disclosure map
    pub num_disclosures: u32,
}

impl W3CSdJwt {
    pub fn get(&self, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
        selector.select(self.json.clone()).ok()
    }
}

#[uniffi::export]
pub fn parse_w3c_sd_jwt(credential: &str) -> Result<W3CSdJwt, W3CParseError> {
    let decoded = sdjwt_util::decode_sdjwt(credential).map_err(W3CParseError::SdJwtError)?;

    let types = match decoded.claims.get("type") {
        Some(JsonValue::Array(types)) => types
            .iter()
            .filter_map(|t| t.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>(),
        Some(JsonValue::String(r#type)) => vec![r#type.clone()],
        _ => return Err(W3CParseError::NoType),
    };

    let Some(doctype) = types
        .iter()
        .find(|t| t.as_str() != "VerifiableCredential")
        .or(types.first())
    else {
        return Err(W3CParseError::NoType);
    };

    Ok(W3CSdJwt {
        doctype: doctype.clone(),
        json: decoded.claims.into(),
        original_sdjwt: decoded.original_sdjwt,
        original_jwt: decoded.original_jwt,
        disclosure_map: decoded.disclosure_map,
        disclosure_tree: decoded.disclosure_tree,
        num_disclosures: decoded.num_disclosures as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_w3c_sd_jwt() {
        let credential = "eyJraWQiOiJFeEhrQk1XOWZtYmt2VjI2Nm1ScHVQMnNVWV9OX0VXSU4xbGFwVXpPOHJvIiwiYWxnIjoiRVMyNTYifQ.eyJpYXQiOjE3NDU3NzY3MTMsImV4cCI6MTc0Njk4NjMxMywiX3NkX2FsZyI6InNoYS0yNTYiLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaXNzdWVyIjoiaHR0cHM6Ly91bml2ZXJzaXR5LmV4YW1wbGUvaXNzdWVycy81NjUwNDkiLCJ2YWxpZEZyb20iOiIyMDEwLTAxLTAxVDAwOjAwOjAwWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJuYW1lIjoiQmFjaGVsb3Igb2YgU2NpZW5jZSBhbmQgQXJ0cyIsIl9zZCI6WyJEUkg1aWVsZHdHNXJPMlVQNXlYYlBXWHNTaFFNSmxESlJfZlFVbmhZVDNFIl19LCJfc2QiOlsiUzRvTGpDb0dNckpuMnFFR2lXY1JNNmdFNGZ6cVVFcVIzNC1FOWdjZzIyWSJdfSwiX3NkIjpbIlZtWnFMMkpKUFB0RDk2TmxwNE43TzFRMXhFRmNMZ1hCVzVfQWFGQXp4Sm8iLCJaYTdxRkpZSnRSTExSOFNRT1VUYUxwaDZBY21QSGlYVkc5Ni03Wnp3MEtJIl19.ypl46Q1EqUERV-IUUS_-qGoAESfv_WdXwtHOk2vX7QTZNFf0NNfg-w2OR8JPRe97kZBDQLuBZKPJhBXdFjbSwg~WyIxeDVielRkZXhsLW4zWVVIQXF5ZUxBIiwgImlkIiwgImh0dHA6Ly91bml2ZXJzaXR5LmV4YW1wbGUvY3JlZGVudGlhbHMvMzczMiJd~WyJablVReVZXRmo0UlFfTHFmOVBkbmN3IiwgInR5cGUiLCBbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwgIkV4YW1wbGVEZWdyZWVDcmVkZW50aWFsIl1d~WyI5TG1nOHhaUVJxWEZZaVRlV0hRZjV3IiwgImlkIiwgImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJd~WyJZMVBDaVA3YnJ3TjFHMEVMWmJXRlZRIiwgInR5cGUiLCAiRXhhbXBsZUJhY2hlbG9yRGVncmVlIl0~";
        let parsed = parse_w3c_sd_jwt(credential).unwrap();

        assert_eq!(parsed.doctype, "ExampleDegreeCredential");
    }
}
