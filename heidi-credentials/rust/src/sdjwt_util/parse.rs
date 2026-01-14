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
};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use heidi_util_rust::value::Value;
use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::sdjwt_util::hash_algs::SdJwtHasher;

const UNDISCLOSABLE_CLAIMS: [&str; 9] = [
    // Regular JWT claims
    "iss",
    "iat",
    "exp",
    "nbf",
    "vct",
    // JSON-LD JWT claims
    "@context",
    "issuer",
    "validFrom",
    "validUntil",
];

#[derive(Debug, uniffi::Error, Clone, Copy)]
pub enum SdJwtDecodeError {
    NoDisclosures,
    InvalidBody,
    InvalidJwt,
    InvalidDisclosure,
}

impl Display for SdJwtDecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[derive(Debug, Clone, uniffi::Record, Serialize)]
pub struct Disclosure {
    pub salt: String,
    pub key: Option<String>,
    pub value: Value,
    pub enc: String,
}

#[derive(Debug, Clone)]
pub struct ParsedSdJwt {
    pub claims: JsonValue,
    pub disclosure_map: HashMap<String, Disclosure>,
    pub disclosure_tree: DisclosureTree,
    pub original_jwt: String,
    pub original_sdjwt: String,
    pub keybinding_jwt: Option<String>,
    pub num_disclosures: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, uniffi::Enum)]
pub enum DisclosureIndex {
    String(String),
    Index(u64),
}

#[derive(Debug, Clone, Serialize, uniffi::Enum)]
pub enum DisclosureNode {
    Node(DisclosureTree),
    Leaf(Vec<Disclosure>),
}

impl DisclosureNode {
    pub fn get_disclosures(&self) -> Vec<Disclosure> {
        match self {
            DisclosureNode::Node(tree) => tree
                .values()
                .flat_map(DisclosureNode::get_disclosures)
                .collect(),
            DisclosureNode::Leaf(disclosure) => disclosure.clone(),
        }
    }
}

pub type DisclosureTree = HashMap<DisclosureIndex, DisclosureNode>;

fn parse_disclosure(disclosure: &str) -> Result<Disclosure, SdJwtDecodeError> {
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(disclosure)
        .map_err(|_| SdJwtDecodeError::InvalidBody)?;

    let JsonValue::Array(arr) =
        serde_json::from_slice(&decoded).map_err(|_| SdJwtDecodeError::InvalidBody)?
    else {
        return Err(SdJwtDecodeError::InvalidDisclosure);
    };

    let mut it = arr.into_iter();
    match (it.next(), it.next(), it.next()) {
        (Some(JsonValue::String(salt)), Some(JsonValue::String(key)), Some(value)) => {
            Ok(Disclosure {
                salt,
                key: Some(key),
                value: value.into(),
                enc: disclosure.to_string(),
            }
            .into())
        }
        (Some(JsonValue::String(salt)), Some(value), None) => Ok(Disclosure {
            salt,
            key: None,
            value: value.into(),
            enc: disclosure.to_string(),
        }
        .into()),
        _ => Err(SdJwtDecodeError::InvalidDisclosure),
    }
}

fn reconstruct(
    mut claims: JsonValue,
    disclosure_map: &HashMap<String, Disclosure>,
) -> (JsonValue, DisclosureTree) {
    fn inner(
        sdjwt: &mut JsonValue,
        disclosure_map: &HashMap<String, Disclosure>,
        disclosure_tree: &mut DisclosureTree,
        parent: Vec<Disclosure>,
    ) {
        match sdjwt {
            JsonValue::Object(obj) => {
                // Replace _sd disclosures with actual values
                if let Some(JsonValue::Array(sd)) = obj.get("_sd").cloned() {
                    for hash in sd {
                        let JsonValue::String(hash) = hash else {
                            continue;
                        };

                        let Some(disclosure) = disclosure_map.get(&hash) else {
                            continue;
                        };

                        let Some(key) = &disclosure.key else {
                            continue;
                        };

                        obj.insert(
                            key.clone(),
                            serde_json::to_value(&disclosure.value).unwrap(),
                        );
                        let mut parent = parent.clone();
                        parent.push(disclosure.to_owned());
                        parent.sort_by(|a, b| a.enc.cmp(&b.enc));
                        parent.dedup_by(|a, b| a.enc == b.enc);
                        disclosure_tree.insert(
                            DisclosureIndex::String(key.clone()),
                            DisclosureNode::Leaf(parent),
                        );
                    }
                }

                // Recursively reconstruct nested objects
                for (key, value) in obj.iter_mut() {
                    let index = DisclosureIndex::String(key.clone());
                    let node = disclosure_tree
                        .entry(index)
                        .or_insert_with(|| DisclosureNode::Node(DisclosureTree::new()));

                    if !matches!(value, JsonValue::Object(_) | JsonValue::Array(_)) {
                        // If the value is not an object or array, skip further processing
                        // Make sure to set the last disclosure node if we had some
                        if matches!(node, DisclosureNode::Node(_)) {
                            *node = DisclosureNode::Leaf(parent.clone());
                        }

                        continue;
                    }
                    match node {
                        DisclosureNode::Node(subtree) => {
                            inner(value, disclosure_map, subtree, parent.clone())
                        }
                        DisclosureNode::Leaf(disclosure) => {
                            let mut subtree = DisclosureTree::new();
                            let mut parent = parent.clone();
                            parent.extend_from_slice(disclosure.as_slice());
                            parent.sort_by(|a, b| a.enc.cmp(&b.enc));
                            parent.dedup_by(|a, b| a.enc == b.enc);
                            inner(value, disclosure_map, &mut subtree, parent);
                            let new_node = DisclosureNode::Node(subtree);
                            if !new_node.get_disclosures().is_empty() {
                                *node = new_node;
                            }
                        }
                    }
                }
            }
            JsonValue::Array(arr) => {
                for (idx, value) in arr.iter_mut().enumerate() {
                    let index = DisclosureIndex::Index(idx as u64);
                    let node = disclosure_tree
                        .entry(index)
                        .or_insert_with(|| DisclosureNode::Node(DisclosureTree::new()));

                    // Check for recursive disclosures
                    if let JsonValue::Object(obj) = value {
                        if let Some(JsonValue::String(hash)) = obj.get("...") {
                            let Some(disclosure) = disclosure_map.get(hash) else {
                                continue;
                            };
                            let mut parent = parent.clone();
                            parent.push(disclosure.to_owned());
                            parent.sort_by(|a, b| a.enc.cmp(&b.enc));
                            parent.dedup_by(|a, b| a.enc == b.enc);
                            *value = serde_json::to_value(&disclosure.value).unwrap();
                            *node = DisclosureNode::Leaf(parent);
                        }
                    }

                    if !matches!(value, JsonValue::Object(_) | JsonValue::Array(_)) {
                        // If the value is not an object or array, skip further processing
                        // Make sure to set the last disclosure node if we had some
                        if matches!(node, DisclosureNode::Node(_)) {
                            *node = DisclosureNode::Leaf(parent.clone());
                        }
                        continue;
                    }

                    match node {
                        DisclosureNode::Node(subtree) => {
                            inner(value, disclosure_map, subtree, parent.clone())
                        }
                        DisclosureNode::Leaf(disclosure) => {
                            let mut subtree = DisclosureTree::new();
                            let mut parent = parent.clone();
                            parent.extend_from_slice(disclosure.as_slice());
                            parent.sort_by(|a, b| a.enc.cmp(&b.enc));
                            parent.dedup_by(|a, b| a.enc == b.enc);
                            inner(value, disclosure_map, &mut subtree, parent);
                            let new_node = DisclosureNode::Node(subtree);
                            if !new_node.get_disclosures().is_empty() {
                                *node = new_node;
                            }
                        }
                    }
                }
            }
            _ => (),
        }
    }

    let mut disclosure_tree = DisclosureTree::new();

    inner(&mut claims, disclosure_map, &mut disclosure_tree, vec![]);
    (claims, disclosure_tree)
}

pub fn decode_sdjwt(payload: &str) -> Result<ParsedSdJwt, SdJwtDecodeError> {
    // Remove whitespace from the payload
    let payload = {
        let mut tmp = payload.to_string();
        tmp.retain(|c| !c.is_whitespace());
        tmp
    };

    let (jwt, disclosures_and_kb_jwt) = payload
        .split_once("~")
        .ok_or(SdJwtDecodeError::InvalidJwt)?;

    // Remove the key binding JWT
    let (disclosures, kb_jwt) = match disclosures_and_kb_jwt.rsplit_once("~") {
        Some((disclosures, kb_jwt)) => (disclosures, kb_jwt),
        None => ("", ""),
    };

    let kb_jwt = if kb_jwt.trim().is_empty() {
        None
    } else {
        Some(kb_jwt.to_string())
    };

    let disclosures = disclosures
        .split('~')
        // Parse disclosures, ignoring invalid ones
        .filter_map(|d| parse_disclosure(d).ok().map(|v| (d.to_string(), v)))
        // Filter out undisclosable claims
        .filter(|(_, v)| {
            v.key
                .as_deref()
                .map(|k| !UNDISCLOSABLE_CLAIMS.contains(&k))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();

    // Parse the JWT, ignore the header and signature
    let claims = {
        let jwt_parts = jwt.split('.').collect::<Vec<_>>();
        let body = match jwt_parts.as_slice() {
            [_, body, _] => body,
            _ => return Err(SdJwtDecodeError::InvalidJwt),
        };

        let Ok(body) = BASE64_URL_SAFE_NO_PAD.decode(body) else {
            return Err(SdJwtDecodeError::InvalidBody);
        };

        let Ok(claims) = serde_json::from_slice::<JsonValue>(body.as_slice()) else {
            return Err(SdJwtDecodeError::InvalidBody);
        };
        claims
    };

    // Get the digest algorithm, default to SHA-256
    let digest: SdJwtHasher = {
        let digest_alg = claims
            .get("_sd_alg")
            .and_then(|a| a.as_str())
            .unwrap_or("sha-256")
            .to_string();
        let Ok(mut digest) = digest_alg.parse::<SdJwtHasher>() else {
            return Err(SdJwtDecodeError::InvalidJwt);
        };
        if let Some(params) = claims.get("_sd_alg_param") {
            digest.0.update_params(params);
        }
        digest
    };

    let disclosure_map = disclosures
        .into_iter()
        .map(|(enc, val)| {
            let hash = digest.0.disclosure_hash((&val, enc.as_str()));
            (hash, val)
        })
        .collect::<HashMap<_, _>>();

    let num_disclosures = disclosure_map.len();
    // let num_total_disclosures = get_total_num_disclosures(&claims);

    let (reconstructed, disclosure_tree) = reconstruct(claims, &disclosure_map);

    Ok(ParsedSdJwt {
        claims: reconstructed,
        disclosure_map,
        disclosure_tree,
        original_jwt: jwt.to_string(),
        original_sdjwt: payload.to_string(),
        keybinding_jwt: kb_jwt,
        num_disclosures,
    })
}
