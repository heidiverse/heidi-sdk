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
    io::Cursor,
    str::FromStr,
    sync::{Arc, Mutex},
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use heidi_util_rust::value::Value;
use next_gen_signatures::crypto::zkp::{
    deserialize_public_key_uncompressed, deserialize_signature,
};
use num_bigint::BigUint;
use rand_core::OsRng;
use rdf_util::oxrdf::{Graph, GraphName};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use zkp_util::{
    device_binding::{DeviceBindingPresentation, SecpFr},
    vc::{
        presentation::{present, VerifiablePresentation},
        requirements::{
            DeviceBindingRequirement, DeviceBindingVerificationParams, DiscloseRequirement,
            EqualClaimsRequirement, ProofRequirement,
        },
        VerifiableCredential,
    },
};

use crate::claims_pointer::Selector;

#[derive(Clone, Debug, uniffi::Record, Serialize)]
pub struct BbsRust {
    pub document: String,
    pub proof: String,

    pub original_bbs: String,
}

impl BbsRust {
    pub fn get(&self, selector: Arc<dyn Selector>) -> Option<Vec<Value>> {
        selector.select(self.body()).ok()
    }

    pub fn document(&self) -> rdf_util::Value {
        rdf_util::from_str(&self.document).unwrap()
    }

    pub fn proof(&self) -> rdf_util::Value {
        rdf_util::from_str(&self.proof).unwrap()
    }

    pub fn body(&self) -> Value {
        serde_json::from_value(
            self.document().to_json()["https://www.w3.org/2018/credentials#credentialSubject"]
                .clone(),
        )
        .unwrap()
    }

    pub fn types(&self) -> Vec<String> {
        let types = self.document()["http://www.w3.org/1999/02/22-rdf-syntax-ns#type"].clone();
        match types {
            rdf_util::Value::String(s) => vec![s],
            rdf_util::Value::Typed(s, t) if t == "http://www.w3.org/2001/XMLSchema#string" => {
                vec![s]
            }
            rdf_util::Value::ObjectRef(rdf_util::ObjectId::NamedNode(name)) => vec![name],
            rdf_util::Value::Object(_, rdf_util::ObjectId::NamedNode(name)) => vec![name],
            rdf_util::Value::Array(arr) => arr
                .into_iter()
                .filter_map(|v| match v {
                    rdf_util::Value::String(s) => Some(s),
                    rdf_util::Value::Typed(s, t)
                        if t == "http://www.w3.org/2001/XMLSchema#string" =>
                    {
                        Some(s)
                    }
                    rdf_util::Value::ObjectRef(rdf_util::ObjectId::NamedNode(name)) => Some(name),
                    rdf_util::Value::Object(_, rdf_util::ObjectId::NamedNode(name)) => Some(name),
                    _ => None,
                })
                .collect(),
            _ => vec![],
        }
    }
}

#[uniffi::export]
pub fn bbs_get_body(cred: &BbsRust) -> Value {
    cred.body()
}

#[derive(Debug, Clone, uniffi::Error)]
pub enum BbsParseError {
    InvalidEncoding(String),
    NoDocument,
    NoProof,
    InvalidVCContent,
    InvalidProofContent,
    InvalidDeviceBindingContent,
    InvalidProof(String),
    InvalidDefinition(String),
    LockError,
}

impl Display for BbsParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[uniffi::export]
pub fn decode_bbs(bbs: &str) -> Result<BbsRust, BbsParseError> {
    let json = String::from_utf8(
        BASE64_URL_SAFE_NO_PAD
            .decode(bbs)
            .map_err(|_| BbsParseError::InvalidEncoding("vc not base64url encoded".into()))?,
    )
    .map_err(|_| BbsParseError::InvalidEncoding("vc is not valid utf8".into()))?;

    let vc = serde_json::from_str::<JsonValue>(&json)
        .map_err(|_| BbsParseError::InvalidEncoding("vc is not json".into()))?;

    let Some(JsonValue::String(document)) = vc.get("document") else {
        return Err(BbsParseError::NoDocument);
    };

    let Some(JsonValue::String(proof)) = vc.get("proof") else {
        return Err(BbsParseError::NoProof);
    };

    let document =
        String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(document).map_err(|_| {
            BbsParseError::InvalidEncoding("document not base64url encoded".into())
        })?)
        .map_err(|_| BbsParseError::InvalidEncoding("document not valid utf8".into()))?;

    let proof = String::from_utf8(
        BASE64_URL_SAFE_NO_PAD
            .decode(proof)
            .map_err(|_| BbsParseError::InvalidEncoding("proof not base64url encoded".into()))?,
    )
    .map_err(|_| BbsParseError::InvalidEncoding("proof not valid utf8".into()))?;

    let Ok(_) = rdf_util::from_str(&document) else {
        return Err(BbsParseError::InvalidVCContent);
    };

    Ok(BbsRust {
        document,
        proof,
        original_bbs: bbs.to_string(),
    })
}

#[derive(Debug, Clone, uniffi::Object)]
pub struct BbsBuilder {
    vc: VerifiableCredential,
    requirements: Vec<ProofRequirement>,
    device_binding: Option<DeviceBindingRequirement>,
    proving_keys: HashMap<String, String>,
    issuer_pk: String,
    issuer_id: String,
    issuer_key_id: String,
}

#[derive(Debug, Clone, uniffi::Object)]
pub struct BbsBuilderObject {
    inner: Arc<Mutex<BbsBuilder>>,
}

#[derive(Debug, Clone, uniffi::Error)]
pub enum BbsBuilderError {
    Anyhow(String),
    SerializationError(String),
    LockError,
    ThreadError(String),
}

impl Display for BbsBuilderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[uniffi::export]
impl BbsBuilderObject {
    #[uniffi::constructor]
    pub fn new(vc: &BbsRust, issuer_pk: String, issuer_id: String, issuer_key_id: String) -> Self {
        let vc = VerifiableCredential::new(vc.document().to_graph(None), vc.proof().to_graph(None));

        let inner = Arc::new(Mutex::new(BbsBuilder {
            vc,
            requirements: Vec::new(),
            device_binding: None,
            proving_keys: HashMap::new(),
            issuer_pk,
            issuer_id,
            issuer_key_id,
        }));

        Self { inner }
    }

    pub fn add_disclosure(self: &Arc<Self>, key: String) -> Result<(), BbsBuilderError> {
        let mut inner = self.inner.lock().map_err(|_| BbsBuilderError::LockError)?;

        inner
            .requirements
            .push(ProofRequirement::Required(DiscloseRequirement { key }));

        Ok(())
    }

    pub fn add_zkp(
        self: &Arc<Self>,
        circuit_id: String,
        private_var: String,
        private_key: String,
        public_var: String,
        public_val_value: String,
        public_val_type: String,
        proving_key: String,
    ) -> Result<(), BbsBuilderError> {
        let mut inner = self.inner.lock().map_err(|_| BbsBuilderError::LockError)?;

        inner.requirements.push(ProofRequirement::Circuit {
            id: circuit_id.clone(),
            private_var,
            private_key,
            public_var,
            public_val: rdf_util::Value::Typed(public_val_value, public_val_type),
        });

        inner.proving_keys.insert(circuit_id, proving_key);

        Ok(())
    }

    pub fn set_device_binding(
        self: &Arc<Self>,
        uncompressed_public_key: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
        comm_key_secp_label: Vec<u8>,
        comm_key_tom_label: Vec<u8>,
        comm_key_bls_label: Vec<u8>,
        bpp_setup_label: Vec<u8>,
    ) -> Result<(), BbsBuilderError> {
        let mut inner = self.inner.lock().map_err(|_| BbsBuilderError::LockError)?;

        let public_key = deserialize_public_key_uncompressed(&uncompressed_public_key)
            .map_err(|e| BbsBuilderError::Anyhow(e.to_string()))?;

        let message = SecpFr::from(BigUint::from_bytes_be(&message));

        let message_signature = deserialize_signature(&signature)
            .map_err(|e| BbsBuilderError::Anyhow(e.to_string()))?;

        inner.device_binding = Some(DeviceBindingRequirement {
            public_key,
            message,
            message_signature,
            comm_key_secp_label,
            comm_key_tom_label,
            comm_key_bls_label,
            bpp_setup_label,
        });

        Ok(())
    }

    pub fn build_with_stacksize(
        self: Arc<Self>,
        stack_size: u32,
    ) -> Result<String, BbsBuilderError> {
        let handle = std::thread::Builder::new()
            .stack_size(stack_size as usize)
            .spawn(|| self.build())
            .map_err(|e| BbsBuilderError::ThreadError(e.to_string()))?;

        handle
            .join()
            .map_err(|e| BbsBuilderError::ThreadError(format!("{e:?}")))?
    }

    pub fn build(self: Arc<Self>) -> Result<String, BbsBuilderError> {
        let inner = self.inner.lock().map_err(|_| BbsBuilderError::LockError)?;

        let vp = present(
            &mut OsRng,
            inner.vc.clone(),
            &inner.requirements,
            inner.device_binding.clone(),
            &inner.proving_keys,
            &inner.issuer_pk,
            &inner.issuer_id,
            &inner.issuer_key_id,
        )
        .map_err(|e| BbsBuilderError::Anyhow(e.to_string()))?;

        let db = if let Some(db) = vp.device_binding {
            let mut bytes = Vec::<u8>::new();
            db.serialize_compressed(&mut bytes)
                .map_err(|e| BbsBuilderError::SerializationError(e.to_string()))?;
            Some(BASE64_URL_SAFE_NO_PAD.encode(bytes))
        } else {
            None
        };

        let vp_token = BASE64_URL_SAFE_NO_PAD.encode(
            json!({
                "proof": BASE64_URL_SAFE_NO_PAD.encode(vp.proof.dataset().to_string()),
                "device_binding": db
            })
            .to_string(),
        );

        Ok(vp_token)
    }
}

#[derive(uniffi::Record)]
pub struct ClaimBasedParams {
    pub vc1: BbsRust,
    pub dis1: Vec<String>,
    pub uncompressed_public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub comm_key_secp_label: Vec<u8>,
    pub comm_key_tom_label: Vec<u8>,
    pub comm_key_bls_label: Vec<u8>,
    pub bpp_setup_label: Vec<u8>,
    pub vc2: BbsRust,
    pub dis2: Vec<String>,
    pub common: Vec<String>,
    pub issuer_pk: String,
    pub issuer_id: String,
    pub issuer_key_id: String,
    pub stack_size: u32,
}

#[uniffi::export]
pub fn bbs_derive_claim_based_proof(params: ClaimBasedParams) -> Result<String, BbsBuilderError> {
    let ClaimBasedParams {
        vc1,
        dis1,
        uncompressed_public_key,
        message,
        signature,
        comm_key_secp_label,
        comm_key_tom_label,
        comm_key_bls_label,
        bpp_setup_label,
        vc2,
        dis2,
        common,
        issuer_pk,
        issuer_id,
        issuer_key_id,
        stack_size,
    } = params;

    let vc1 = VerifiableCredential::new(
        Graph::from_iter(rdf_util::parse_triples(&vc1.document).unwrap()),
        Graph::from_iter(rdf_util::parse_triples(&vc1.proof).unwrap()),
    );
    let vc2 = VerifiableCredential::new(
        Graph::from_iter(rdf_util::parse_triples(&vc2.document).unwrap()),
        Graph::from_iter(rdf_util::parse_triples(&vc2.proof).unwrap()),
    );

    let req1 = dis1
        .into_iter()
        .map(|key| DiscloseRequirement { key })
        .collect::<Vec<_>>();

    let req2 = dis2
        .into_iter()
        .map(|key| DiscloseRequirement { key })
        .collect::<Vec<_>>();

    let claims_eq = common
        .into_iter()
        .map(|key| EqualClaimsRequirement {
            key1: key.clone(),
            key2: key,
        })
        .collect::<Vec<_>>();

    let public_key = deserialize_public_key_uncompressed(&uncompressed_public_key)
        .map_err(|e| BbsBuilderError::Anyhow(e.to_string()))?;

    let message = SecpFr::from(BigUint::from_bytes_be(&message));

    let message_signature =
        deserialize_signature(&signature).map_err(|e| BbsBuilderError::Anyhow(e.to_string()))?;

    let db1 = Some(DeviceBindingRequirement {
        public_key,
        message,
        message_signature,
        comm_key_secp_label,
        comm_key_tom_label,
        comm_key_bls_label,
        bpp_setup_label,
    });

    let handle = std::thread::Builder::new()
        .stack_size(stack_size as usize)
        .spawn(move || {
            zkp_util::vc::presentation::present_two(
                &mut OsRng,
                // first credential
                vc1,
                &req1,
                db1,
                // second credential
                vc2,
                &req2,
                // equal claims proof
                &claims_eq,
                // common
                &issuer_pk,
                &issuer_id,
                &issuer_key_id,
            )
            .map_err(|e| BbsBuilderError::Anyhow(e.to_string()))
        })
        .map_err(|e| BbsBuilderError::ThreadError(e.to_string()))?;

    let vp = handle
        .join()
        .map_err(|e| BbsBuilderError::ThreadError(format!("{e:?}")))??;

    let Some(db) = vp.device_binding else {
        return Err(BbsBuilderError::Anyhow(
            "device binding missing in derived proof".into(),
        ));
    };

    let mut bytes = Vec::<u8>::new();
    db.serialize_compressed(&mut bytes)
        .map_err(|e| BbsBuilderError::SerializationError(e.to_string()))?;
    let db = BASE64_URL_SAFE_NO_PAD.encode(bytes);

    let vp_token = BASE64_URL_SAFE_NO_PAD.encode(
        json!({
            "proof": BASE64_URL_SAFE_NO_PAD.encode(vp.proof.dataset().to_string()),
            "device_binding": db
        })
        .to_string(),
    );

    Ok(vp_token)
}

#[derive(Debug, Serialize, Deserialize)]
struct BbsPresentation {
    pub proof: String,
    pub device_binding: Option<String>,
}

#[derive(uniffi::Object)]
pub struct BbsPresentationRust {
    presentation: VerifiablePresentation,
}

impl BbsPresentationRust {
    pub fn claims(&self) -> rdf_util::Value {
        let proof = self.presentation.proof.to_value(GraphName::DefaultGraph);
        proof["https://www.w3.org/2018/credentials#verifiableCredential"]
            ["https://www.w3.org/2018/credentials#credentialSubject"]
            .clone()
    }

    pub fn get_types(&self) -> rdf_util::Value {
        let proof = self.presentation.proof.to_value(GraphName::DefaultGraph);
        proof["https://www.w3.org/2018/credentials#verifiableCredential"]
            ["http://www.w3.org/1999/02/22-rdf-syntax-ns#type"]
            .clone()
    }
}

#[uniffi::export]
pub fn bbs_presentation_get_claims(pres: &BbsPresentationRust) -> Value {
    serde_json::from_value(pres.claims().to_json()).unwrap()
}

pub fn parse_bbs_presentation(vp_token: String) -> Result<VerifiablePresentation, BbsParseError> {
    let json =
        String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(vp_token).map_err(|_| {
            BbsParseError::InvalidEncoding("vp_token not base64url encoded".into())
        })?)
        .map_err(|_| BbsParseError::InvalidEncoding("vp_token not valid utf8".into()))?;

    let presentation = serde_json::from_str::<BbsPresentation>(&json)
        .map_err(|_| BbsParseError::InvalidEncoding("vp_token not json".into()))?;

    let proof =
        rdf_util::MultiGraph::from_str(
            &String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(presentation.proof).map_err(
                |_| BbsParseError::InvalidEncoding("proof not base64url encoded".into()),
            )?)
            .map_err(|_| BbsParseError::InvalidEncoding("proof not valid utf8".into()))?,
        )
        .map_err(|_| BbsParseError::InvalidProofContent)?;

    let device_binding = if let Some(db) = presentation.device_binding {
        Some(
            DeviceBindingPresentation::deserialize_compressed(Cursor::new(
                BASE64_URL_SAFE_NO_PAD.decode(db).map_err(|_| {
                    BbsParseError::InvalidEncoding("device_binding not base64url encoded".into())
                })?,
            ))
            .map_err(|_| BbsParseError::InvalidDeviceBindingContent)?,
        )
    } else {
        None
    };

    Ok(VerifiablePresentation {
        proof,
        device_binding,
    })
}

#[uniffi::export]
impl BbsPresentationRust {
    #[uniffi::constructor]
    pub fn parse(vp_token: String) -> Result<Self, BbsParseError> {
        let presentation = parse_bbs_presentation(vp_token)?;
        Ok(Self { presentation })
    }

    pub fn verify(
        self: &Arc<Self>,
        definition: String,
        verifying_keys: &HashMap<String, String>,
        issuer_pk: &str,
        issuer_id: &str,
        issuer_key_id: &str,
        db_message: Vec<u8>,
        db_secp_label: Vec<u8>,
        db_tom_label: Vec<u8>,
        db_bls_label: Vec<u8>,
        db_bpp_setup_label: Vec<u8>,
    ) -> Result<Value, BbsParseError> {
        let requirements = serde_json::from_str::<Vec<ProofRequirement>>(&definition)
            .map_err(|e| BbsParseError::InvalidDefinition(e.to_string()))?;

        let result = zkp_util::vc::verification::verify(
            &mut OsRng,
            self.presentation.clone(),
            &requirements,
            Some(DeviceBindingVerificationParams {
                message: SecpFr::from(BigUint::from_bytes_be(&db_message)),
                comm_key_secp_label: db_secp_label,
                comm_key_tom_label: db_tom_label,
                comm_key_bls_label: db_bls_label,
                bpp_setup_label: db_bpp_setup_label,
            }),
            verifying_keys,
            issuer_pk,
            issuer_id,
            issuer_key_id,
            1,
        )
        .map_err(|e| BbsParseError::InvalidProof(e.to_string()))?;

        Ok(serde_json::from_value(result).unwrap())
    }

    pub fn get_num_original_claims(self: &Arc<Self>) -> i32 {
        zkp_util::vc::utils::get_original_num_claims(&self.presentation.proof.dataset()) as i32
    }

    pub fn get_num_disclosed(self: &Arc<Self>) -> i32 {
        zkp_util::vc::utils::get_num_disclosed_claims(&self.presentation.proof.dataset()) as i32
    }

    pub fn get_vc_types(self: &Arc<Self>) -> Vec<String> {
        match self.get_types() {
            rdf_util::Value::String(s) => vec![s],
            rdf_util::Value::Typed(s, t) if t == "http://www.w3.org/2001/XMLSchema#string" => {
                vec![s]
            }
            rdf_util::Value::ObjectRef(rdf_util::ObjectId::NamedNode(name)) => vec![name],
            rdf_util::Value::Object(_, rdf_util::ObjectId::NamedNode(name)) => vec![name],
            rdf_util::Value::Array(arr) => arr
                .into_iter()
                .filter_map(|v| match v {
                    rdf_util::Value::String(s) => Some(s),
                    rdf_util::Value::Typed(s, t)
                        if t == "http://www.w3.org/2001/XMLSchema#string" =>
                    {
                        Some(s)
                    }
                    rdf_util::Value::ObjectRef(rdf_util::ObjectId::NamedNode(name)) => Some(name),
                    rdf_util::Value::Object(_, rdf_util::ObjectId::NamedNode(name)) => Some(name),
                    _ => None,
                })
                .collect(),
            _ => vec![],
        }
    }
}

#[derive(uniffi::Object)]
pub struct BbsClaimBasedPresentationRust {
    presentation: VerifiablePresentation,
    db_message: Vec<u8>,
    db_secp_label: Vec<u8>,
    db_tom_label: Vec<u8>,
    db_bls_label: Vec<u8>,
    db_bpp_setup_label: Vec<u8>,
    issuer_pk: String,
    issuer_id: String,
    issuer_key_id: String,
    requirements: Arc<Mutex<Vec<ProofRequirement>>>,
}

#[uniffi::export]
impl BbsClaimBasedPresentationRust {
    #[uniffi::constructor]
    pub fn parse(
        vp_token: String,
        db_message: Vec<u8>,
        db_secp_label: Vec<u8>,
        db_tom_label: Vec<u8>,
        db_bls_label: Vec<u8>,
        db_bpp_setup_label: Vec<u8>,
        issuer_pk: String,
        issuer_id: String,
        issuer_key_id: String,
    ) -> Result<Self, BbsParseError> {
        let presentation = parse_bbs_presentation(vp_token)?;
        Ok(Self {
            presentation,
            db_message,
            db_secp_label,
            db_tom_label,
            db_bls_label,
            db_bpp_setup_label,
            issuer_pk,
            issuer_id,
            issuer_key_id,
            requirements: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn add_disclosure_requirement(
        self: &Arc<Self>,
        requirements: Vec<String>,
    ) -> Result<(), BbsParseError> {
        let mut reqs = self
            .requirements
            .lock()
            .map_err(|_| BbsParseError::LockError)
            .unwrap();

        reqs.extend(
            requirements
                .into_iter()
                .map(|key| ProofRequirement::Required(DiscloseRequirement { key })),
        );

        Ok(())
    }

    pub fn add_equal_claims_requirement(
        self: &Arc<Self>,
        key1: String,
        key2: String,
    ) -> Result<(), BbsParseError> {
        let mut reqs = self
            .requirements
            .lock()
            .map_err(|_| BbsParseError::LockError)
            .unwrap();

        reqs.push(ProofRequirement::EqualClaims(EqualClaimsRequirement {
            key1,
            key2,
        }));

        Ok(())
    }

    pub fn verify(self: &Arc<Self>, num_credentials: u32) -> Result<Value, BbsParseError> {
        let requirements = self
            .requirements
            .lock()
            .map_err(|_| BbsParseError::LockError)?
            .clone();

        let result = zkp_util::vc::verification::verify(
            &mut OsRng,
            self.presentation.clone(),
            &requirements,
            Some(DeviceBindingVerificationParams {
                message: SecpFr::from(BigUint::from_bytes_be(&self.db_message)),
                comm_key_secp_label: self.db_secp_label.clone(),
                comm_key_tom_label: self.db_tom_label.clone(),
                comm_key_bls_label: self.db_bls_label.clone(),
                bpp_setup_label: self.db_bpp_setup_label.clone(),
            }),
            &HashMap::new(),
            &self.issuer_pk,
            &self.issuer_id,
            &self.issuer_key_id,
            num_credentials as usize,
        )
        .map_err(|e| BbsParseError::InvalidProof(e.to_string()))?;

        Ok(serde_json::from_value(result).unwrap())
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use heidi_util_rust::value::Value;

    use crate::models::PointerPart;

    use super::decode_bbs;

    const BBS_CREDENTIAL: &str = "eyJkb2N1bWVudCI6IlBHUnBaRHBsZUdGdGNHeGxPbXB2YUc1a2IyVS1JRHhvZEhSd09pOHZjMk5vWlcxaExtOXlaeTlpYVhKMGFFUmhkR1UtSUNJeE9Ua3dMVEF4TFRBeFZEQXdPakF3T2pBd1dpSmVYanhvZEhSd09pOHZkM2QzTG5jekxtOXlaeTh5TURBeEwxaE5URk5qYUdWdFlTTmtZWFJsVkdsdFpUNGdMZ284Wkdsa09tVjRZVzF3YkdVNmFtOW9ibVJ2WlQ0Z1BHaDBkSEE2THk5elkyaGxiV0V1YjNKbkwyNWhiV1UtSUNKS2IyaHVJRVJ2WlNJZ0xnbzhaR2xrT21WNFlXMXdiR1U2YW05b2JtUnZaVDRnUEdoMGRIQTZMeTkzZDNjdWR6TXViM0puTHpFNU9Ua3ZNREl2TWpJdGNtUm1MWE41Ym5SaGVDMXVjeU4wZVhCbFBpQThhSFIwY0RvdkwzTmphR1Z0WVM1dmNtY3ZVR1Z5YzI5dVBpQXVDanhrYVdRNlpYaGhiWEJzWlRwcWIyaHVaRzlsUGlBOGFIUjBjRG92TDNOamFHVnRZUzV2Y21jdmRHVnNaWEJvYjI1bFBpQWlLRFF5TlNrZ01USXpMVFExTmpjaUlDNEtQR2gwZEhBNkx5OWxlR0Z0Y0d4bExtOXlaeTlqY21Wa1pXNTBhV0ZzY3k5d1pYSnpiMjR2TUQ0Z1BHaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekkyVjRjR2x5WVhScGIyNUVZWFJsUGlBaU1qQXpNQzB3TVMwd01WUXdNRG93TURvd01Gb2lYbDQ4YUhSMGNEb3ZMM2QzZHk1M015NXZjbWN2TWpBd01TOVlUVXhUWTJobGJXRWpaR0YwWlZScGJXVS1JQzRLUEdoMGRIQTZMeTlsZUdGdGNHeGxMbTl5Wnk5amNtVmtaVzUwYVdGc2N5OXdaWEp6YjI0dk1ENGdQR2gwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpJMk55WldSbGJuUnBZV3hUZFdKcVpXTjBQaUE4Wkdsa09tVjRZVzF3YkdVNmFtOW9ibVJ2WlQ0Z0xnbzhhSFIwY0RvdkwyVjRZVzF3YkdVdWIzSm5MMk55WldSbGJuUnBZV3h6TDNCbGNuTnZiaTh3UGlBOGFIUjBjRG92TDNkM2R5NTNNeTV2Y21jdk1UazVPUzh3TWk4eU1pMXlaR1l0YzNsdWRHRjRMVzV6STNSNWNHVS1JRHhvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeU5XWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkQ0Z0xnbzhhSFIwY0RvdkwyVjRZVzF3YkdVdWIzSm5MMk55WldSbGJuUnBZV3h6TDNCbGNuTnZiaTh3UGlBOGFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNamFYTnpkV0Z1WTJWRVlYUmxQaUFpTWpBeU1DMHdNUzB3TVZRd01Eb3dNRG93TUZvaVhsNDhhSFIwY0RvdkwzZDNkeTUzTXk1dmNtY3ZNakF3TVM5WVRVeFRZMmhsYldFalpHRjBaVlJwYldVLUlDNEtQR2gwZEhBNkx5OWxlR0Z0Y0d4bExtOXlaeTlqY21Wa1pXNTBhV0ZzY3k5d1pYSnpiMjR2TUQ0Z1BHaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekkybHpjM1ZsY2o0Z1BHUnBaRHBsZUdGdGNHeGxPbWx6YzNWbGNqQS1JQzRLUEdoMGRIQTZMeTlsZUdGdGNHeGxMbTl5Wnk5amNtVmtaVzUwYVdGc2N5OXdaWEp6YjI0dk1ENGdQR2gwZEhCek9pOHZlbXR3TFd4a0xtOXlaeTlrWlhacFkyVkNhVzVrYVc1blBpQmZPbUl3SUM0S1h6cGlNQ0E4YUhSMGNITTZMeTk2YTNBdGJHUXViM0puTDJSbGRtbGpaVUpwYm1ScGJtY2plRDRnSWxwSFJrOXZTQzkxUlhRMU0yOXVablZ3VVRoVVZFcEtVVFFyYWxKcU1IazVaMVpRV1dwd2MzVlNielE5SWw1ZVBHaDBkSEE2THk5M2QzY3Vkek11YjNKbkx6SXdNREV2V0UxTVUyTm9aVzFoSTJKaGMyVTJORUo1ZEdWelFtVS1JQzRLWHpwaU1DQThhSFIwY0hNNkx5OTZhM0F0YkdRdWIzSm5MMlJsZG1salpVSnBibVJwYm1jamVUNGdJazF1ZVhRd1RWWTBRMXBDU1dWUGJsTmxVVzFCVFdSUlVUSjVLMFJQTkVNd09HOXRjMU4wVTJOWlpVMDlJbDVlUEdoMGRIQTZMeTkzZDNjdWR6TXViM0puTHpJd01ERXZXRTFNVTJOb1pXMWhJMkpoYzJVMk5FSjVkR1Z6UW1VLUlDNEsiLCJwcm9vZiI6Ilh6cGlNQ0E4YUhSMGNITTZMeTkzTTJsa0xtOXlaeTl6WldOMWNtbDBlU04yWlhKcFptbGpZWFJwYjI1TlpYUm9iMlEtSUR4a2FXUTZaWGhoYlhCc1pUcHBjM04xWlhJd0kySnNjekV5WHpNNE1TMW5NaTF3ZFdJd01ERS1JQzRLWHpwaU1DQThhSFIwY0hNNkx5OTNNMmxrTG05eVp5OXpaV04xY21sMGVTTmpjbmx3ZEc5emRXbDBaVDRnSW1KaWN5MTBaWEp0ZDJselpTMXphV2R1WVhSMWNtVXRNakF5TXlJZ0xncGZPbUl3SUR4b2RIUndPaTh2ZDNkM0xuY3pMbTl5Wnk4eE9UazVMekF5THpJeUxYSmtaaTF6ZVc1MFlYZ3Ribk1qZEhsd1pUNGdQR2gwZEhCek9pOHZkek5wWkM1dmNtY3ZjMlZqZFhKcGRIa2pSR0YwWVVsdWRHVm5jbWwwZVZCeWIyOW1QaUF1Q2w4NllqQWdQR2gwZEhBNkx5OXdkWEpzTG05eVp5OWtZeTkwWlhKdGN5OWpjbVZoZEdWa1BpQWlNakF5TlMwd01TMHdNVlF3TURvd01Eb3dNRm9pWGw0OGFIUjBjRG92TDNkM2R5NTNNeTV2Y21jdk1qQXdNUzlZVFV4VFkyaGxiV0VqWkdGMFpWUnBiV1UtSUM0S1h6cGlNQ0E4YUhSMGNITTZMeTkzTTJsa0xtOXlaeTl6WldOMWNtbDBlU053Y205dlpsQjFjbkJ2YzJVLUlEeG9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwzTmxZM1Z5YVhSNUkyRnpjMlZ5ZEdsdmJrMWxkR2h2WkQ0Z0xncGZPbUl3SUR4b2RIUndjem92TDNjemFXUXViM0puTDNObFkzVnlhWFI1STNCeWIyOW1WbUZzZFdVLUlDSjFja05NTUd4U00wcFdTMG90YlUxUGJDMVNTemRpYzA4d1Z6TkNUMmgyWVRKdmRFazNUWFJSWjNwM01VeE1XVEF3YmxGVlRqTlZabmxuYUU5cE5tRTBPV0Z4UzAxRVFrSnVSbmhsVGt4UGVIbHdOV1p0TFZaTmRHWjJSelJ6VWxoeWJqVnJPVGgwVmpsQlJYaFhVbDlmY2xGeFQweFJabU5hVWs5WWFVVjZNMXBqTTNveGVVRllRbGRxVUhaRWFqZGFSelZHYTFwM0lsNWVQR2gwZEhCek9pOHZkek5wWkM1dmNtY3ZjMlZqZFhKcGRIa2piWFZzZEdsaVlYTmxQaUF1Q2cifQ";

    #[test]
    pub fn test_decode_bbs() {
        let bbs = decode_bbs(BBS_CREDENTIAL).unwrap();

        let name = bbs
            .get(Arc::new(vec![PointerPart::String(
                "http://schema.org/name".to_string(),
            )]))
            .unwrap();
        assert_eq!(name, vec![Value::String("John Doe".to_string())]);
    }
}
