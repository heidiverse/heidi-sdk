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

use base64::Engine;
use std::{
    fmt::{Display, Formatter},
    sync::Arc,
};

use heidi_util_rust::value::{JsonNumber, OrderedMap, Value};

use crate::claims_pointer::Selector;

#[derive(Debug, Clone, uniffi::Record, serde::Serialize)]
pub struct MdocRust {
    pub issuer_auth: Value,
    pub namespace_map: Value,
    pub original_decoded: Value,
    pub original_mdoc: String,
}

#[derive(Debug, Clone, uniffi::Error)]
pub enum MdocParseError {
    InvalidEncoding,
    NoCbor,
    NoIssuerAuth,
    NoNamespaces,
    NamespaceNotMap,
}
impl Display for MdocParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}
#[uniffi::export]
pub fn decode_mdoc(mdoc: &str) -> Result<MdocRust, MdocParseError> {
    let parsed = ciborium::from_reader::<ciborium::Value, _>(
        base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(mdoc)
            .map_err(|_| MdocParseError::InvalidEncoding)?
            .as_slice(),
    )
    .map_err(|_| MdocParseError::NoCbor)?;
    let original_value: Value = parsed.clone().into();
    let issuer_auth = get_issuer_auth(&parsed).ok_or(MdocParseError::NoIssuerAuth)?;
    let namespace = parsed
        .get("nameSpaces")
        .ok_or(MdocParseError::NoNamespaces)?
        .as_map()
        .ok_or(MdocParseError::NamespaceNotMap)?;
    let mut map = OrderedMap::new();
    for (namespace, inner) in namespace {
        let mut namespace_map = OrderedMap::new();
        let ciborium::Value::Text(namespace) = namespace else {
            continue;
        };
        let ciborium::Value::Array(inner) = inner else {
            continue;
        };
        for v in inner {
            let ciborium::Value::Tag(_, obj) = v else {
                continue;
            };
            let ciborium::Value::Bytes(b) = obj.as_ref() else {
                continue;
            };
            let Ok(inner_body) = ciborium::from_reader::<ciborium::Value, _>(b.as_slice()) else {
                continue;
            };
            let Some(element_value) = inner_body.get("elementValue") else {
                continue;
            };
            let Some(ciborium::Value::Text(element_identifier)) =
                inner_body.get("elementIdentifier")
            else {
                continue;
            };
            namespace_map.insert(
                Value::String(element_identifier.to_string()),
                Value::from(element_value.clone()),
            );
        }
        map.insert(
            Value::String(namespace.to_string()),
            Value::OrderedObject(namespace_map),
        );
    }
    Ok(MdocRust {
        issuer_auth: issuer_auth.into(),
        namespace_map: Value::OrderedObject(map),
        original_decoded: original_value,
        original_mdoc: mdoc.to_string(),
    })
}

pub trait CborHelper {
    fn get(&self, k: &str) -> Option<&ciborium::Value>;
    /// Treats this object as a tag, verifies if the found tag matches the expected one
    fn as_expect_tag(&self, expected: u64) -> Option<&ciborium::Value>;
    fn equals(&self, value: &Value) -> bool;
}

impl CborHelper for ciborium::Value {
    fn get(&self, k: &str) -> Option<&ciborium::Value> {
        let map = self.as_map()?;
        map.iter()
            .find(|a| a.0 == ciborium::Value::Text(k.to_string()))
            .map(|a| &a.1)
    }
    fn as_expect_tag(&self, expected: u64) -> Option<&ciborium::Value> {
        let ciborium::Value::Tag(tag, value) = self else {
            return None;
        };
        if *tag != expected {
            return None;
        }
        Some(value)
    }

    fn equals(&self, value: &Value) -> bool {
        match (self, value) {
            (ciborium::Value::Integer(integer), Value::Number(JsonNumber::Integer(jn))) => {
                let cn = i128::from(*integer);
                *jn as i128 == cn
            }
            (ciborium::Value::Float(f), Value::Number(JsonNumber::Float(jf))) => jf == f,
            (ciborium::Value::Text(t), Value::String(s)) => t == s,
            (ciborium::Value::Bool(a), Value::Boolean(b)) => a == b,
            (ciborium::Value::Null, Value::Null) => true,
            (ciborium::Value::Tag(_, value), val) => value.equals(val),
            (ciborium::Value::Array(vec), Value::Array(vec2)) => {
                vec.iter().zip(vec2).all(|(a, b)| a.equals(b))
            }
            (ciborium::Value::Map(vec), Value::Object(map)) => vec.iter().all(|(key, value)| {
                let ciborium::Value::Text(key) = key else {
                    return false;
                };
                let Some(json_obj) = map.get(key) else {
                    return false;
                };
                value.equals(json_obj)
            }),
            _ => false,
        }
    }
}
fn get_issuer_auth(issuer_signed: &ciborium::Value) -> Option<ciborium::Value> {
    let payload_bytes = issuer_signed
        .get("issuerAuth")?
        .as_array()?
        .get(2)?
        .as_bytes()?;
    let inner = ciborium::from_reader::<ciborium::Value, _>(payload_bytes.as_slice()).ok()?;
    let bytes = inner.as_expect_tag(24)?.as_bytes()?;
    ciborium::from_reader(bytes.as_slice()).ok()
}

impl MdocRust {
    pub fn get(&self, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
        selector.select(self.namespace_map.clone()).ok()
    }

    pub fn get_element(&self, namespace: &str, claim_name: &str) -> Option<&Value> {
        self.namespace_map
            .get(namespace)
            .and_then(|a| a.get(claim_name))
    }
    pub fn get_doc_type(&self) -> String {
        self.issuer_auth
            .get("docType")
            .and_then(|a| a.as_str())
            .map(|a| a.to_string())
            .unwrap_or("".to_string())
    }
}

#[uniffi::export]
pub fn random_32_bytes() -> Value {
    let randomness: [u8; 32] = rand::random();
    Value::Bytes(randomness.to_vec())
}

#[cfg(test)]
mod tests {
    use crate::mdoc::decode_mdoc;

    #[test]
    fn test_cbor() {
        let mdoc = "omppc3N1ZXJBdXRohEOhASahGCFZArYwggKyMIICV6ADAgECAhQS35vrt8RGJm7DTUyfLLtiNIySczAKBggqhkjOPQQDAjCBxjELMAkGA1UEBhMCREUxHTAbBgNVBAgMFEdlbWVpbmRlIE11c3RlcnN0YWR0MRQwEgYDVQQHDAtNdXN0ZXJzdGFkdDEdMBsGA1UECgwUR2VtZWluZGUgTXVzdGVyc3RhZHQxCzAJBgNVBAsMAklUMSkwJwYDVQQDDCBpc3N1YW5jZS5nZW1laW5kZS1tdXN0ZXJzdGFkdC5kZTErMCkGCSqGSIb3DQEJARYcdGVzdEBnZW1laW5kZS1tdXN0ZXJzdGFkdC5kZTAeFw0yNDExMjYxMzI1NThaFw0yNTExMjYxMzI1NThaMIHGMQswCQYDVQQGEwJERTEdMBsGA1UECAwUR2VtZWluZGUgTXVzdGVyc3RhZHQxFDASBgNVBAcMC011c3RlcnN0YWR0MR0wGwYDVQQKDBRHZW1laW5kZSBNdXN0ZXJzdGFkdDELMAkGA1UECwwCSVQxKTAnBgNVBAMMIGlzc3VhbmNlLmdlbWVpbmRlLW11c3RlcnN0YWR0LmRlMSswKQYJKoZIhvcNAQkBFhx0ZXN0QGdlbWVpbmRlLW11c3RlcnN0YWR0LmRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENhe3wz7kTUAOPk3ZG__MjAGW-ROW3eCyxyso_ijCDqSb0SO_lseoNZj6dCLb17M0fa2SEasp7RmyZ4f1mpSwj6MhMB8wHQYDVR0OBBYEFFJbYAZiPV0nk3Pzj9eiMMOMfTRfMAoGCCqGSM49BAMCA0kAMEYCIQDNrXhdq3GuHw95uGgrATAcdscR4_zpITilmIe9Uhp9lAIhAPaOqy5JBt4oK6L3lHAKSoCBavJnCgpc7hOZv4u7rKlfWQMB2BhZAvymZ2RvY1R5cGV4I2NoLnViaXF1ZS5zdHVkaWVyZW5kZW5hdXN3ZWlzLjMxaXEyZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTEyLTE4VDExOjEwOjM3Wml2YWxpZEZyb23AdDIwMjQtMTItMThUMTE6MTA6MzdaanZhbGlkVW50aWzAdDIwMjUtMDEtMDFUMTE6MTA6MzdabHZhbHVlRGlnZXN0c6F4JWNoLnViaXF1ZS5kZXYtc3NpLXNjaGVtYS1jcmVhdG9yLXdzLjGsAFgg23BGu4LdRj7yPGXxcLDk_epZFqj8iRrYzq-gp1HVV6wBWCBuk-TqGMPpKa-pVRg2wctLqb01cBrByeop19V7D54fgAJYIDHcOh7Qrjv4VmHftCXSfms4cS_J5NHrSbTzY17T3UW3A1ggAggJhjj_k2XJWniIZQwWvAIvJUFOkpApczHUkU4Q5zQEWCAWD7tIx-kCXHJLzeviVkjq3N4w2w7qlKiHldV8AcC1zAVYIMsD8NLVyXUYbNMCKgqlezVeBadyqAKP7A7v_lIGpiTxBlggNKvz9ayo9ac7U-Mpv7z_3crWGRLNwJwjLIJpUBZJO50HWCCrDQ67BngIcDJTeDD8eVrN1Ivfu3dXG2JRBe5qidsOOQhYIAjnwHdCN28IWaiH6m7Oq9HpxMtxSLeYq3IDxE_MfycVCVgggveVj1GHSyz2aebxGhGsofV6IamFOPYtyaA9WVTMiawKWCA1UFjXVRmSMsc93rIAc4AVeS3R0h7OiYeo2dAAVMmhVQtYIHwiMpcGndwX3UBbe13BbFL6QW8zHoGdgiJLmco2EImTbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggalOOa-fMSY0g1p5i8c-BesIi-5JQMYPP7BEjLgzazl4iWCB3G5WR4cYYeWY0RCIVgrC5j37o2aUUafG9w-r1wOw9x29kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAYlPPfiD3bl7pOL6vtlgTudD3JIJ5IQKE7K0rVVXfIKtO6ZKJB73k2IlYIoIcR0rxainfl1u65PX4L4j2zTuvYmpuYW1lU3BhY2VzoXglY2gudWJpcXVlLmRldi1zc2ktc2NoZW1hLWNyZWF0b3Itd3MuMYzYGFhrpGZyYW5kb21Q6uuwtYHxyyuPlXpIR-HUKmhkaWdlc3RJRABsZWxlbWVudFZhbHVlwHgYMjAyNC0xMi0xOFQxMToxMDozNy4wMjVacWVsZW1lbnRJZGVudGlmaWVybWlzc3VhbmNlX2RhdGXYGFhWpGZyYW5kb21QIuzmtjT92G_cQQCzrBITqWhkaWdlc3RJRAFsZWxlbWVudFZhbHVlak11c3Rlcm1hbm5xZWxlbWVudElkZW50aWZpZXJobGFzdE5hbWXYGFhUpGZyYW5kb21QPaU3yGmm728d8VTiUaTnNGhkaWdlc3RJRAJsZWxlbWVudFZhbHVlaTEyMzQ1Njc4OXFlbGVtZW50SWRlbnRpZmllcmdiYWRnZU5y2BhYVKRmcmFuZG9tULa1ffJG7gni8VSESFDupqpoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZWgyMDI0MTIxOHFlbGVtZW50SWRlbnRpZmllcmhpc3N1ZWRPbtgYWFWkZnJhbmRvbVB7TISRkZ3ROYPZZi0LQ4YCaGRpZ2VzdElEBGxlbGVtZW50VmFsdWViQ0hxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ52BhYaaRmcmFuZG9tUDGdMbXtJ8TbIBKLKBSHR9JoZGlnZXN0SUQFbGVsZW1lbnRWYWx1ZcB4GDIwMjUtMDEtMDFUMTE6MTA6MzcuMDI1WnFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZdgYWFSkZnJhbmRvbVDkneH7P_ynyRrUH8ERTyHzaGRpZ2VzdElEBmxlbGVtZW50VmFsdWVnTWFydGluYXFlbGVtZW50SWRlbnRpZmllcmlmaXJzdE5hbWXYGFhXpGZyYW5kb21Qx98jL5scaybVlNk5kNR7dGhkaWdlc3RJRAdsZWxlbWVudFZhbHVlaDIwMDEwODEycWVsZW1lbnRJZGVudGlmaWVya2RhdGVPZkJpcnRo2BhYVqRmcmFuZG9tUJEm7q_3068JNHX5PAKZITtoZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZWgyMDI1MTIxOHFlbGVtZW50SWRlbnRpZmllcmp2YWxpZFVudGls2BhYXaRmcmFuZG9tUPC-V7TJgFNFeJ-fiqCeYURoZGlnZXN0SUQJbGVsZW1lbnRWYWx1ZWowMS83NjU0MzIxcWVsZW1lbnRJZGVudGlmaWVyb21hdHJpY3VsYXRpb25OctgYWFekZnJhbmRvbVAjXwpwMZWKKgDLpBVmew8baGRpZ2VzdElECmxlbGVtZW50VmFsdWViQ0hxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHnYGFhlpGZyYW5kb21Q7dpm6J4EvICXj4m8076g_mhkaWdlc3RJRAtsZWxlbWVudFZhbHVleBhVbml2ZXJzaXTDpHQgTXVzdGVyc3RhZHRxZWxlbWVudElkZW50aWZpZXJoaXNzdWVkQnk";

        let _mdoc = decode_mdoc(mdoc).unwrap();
    }
}
