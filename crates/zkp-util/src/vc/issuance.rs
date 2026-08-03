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

use std::{collections::BTreeMap, time::SystemTime};

use anyhow::Context;
use chrono::{DateTime, Months, Utc};
use rand_core::RngCore;
use rdf_proofs::{vocab::BASE_64_BYTES_BE, VerifiableCredential};
use rdf_util::{
    oxrdf::{NamedNode, Subject},
    ObjectId, Value as RdfValue,
};

use crate::device_binding::{
    DEVICE_BINDING_KEY, DEVICE_BINDING_KEY_X, DEVICE_BINDING_KEY_X_1, DEVICE_BINDING_KEY_X_2,
    DEVICE_BINDING_KEY_Y,
};

#[allow(clippy::too_many_arguments)]
pub fn issue<R: RngCore>(
    rng: &mut R,
    claims: RdfValue,
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
    issuance_date: Option<DateTime<Utc>>,
    created_date: Option<DateTime<Utc>>,
    expiration_date: Option<DateTime<Utc>>,
    device_binding: Option<(String, String, String, String)>,
    vc_type: Option<&str>,
) -> anyhow::Result<VerifiableCredential> {
    let issuer = rdf_util::from_str_with_hint(
        format!(
            r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#secretKeyMultibase> "{issuer_sk}" .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}" .
            "#
        ),
        Subject::NamedNode(NamedNode::new_unchecked(issuer_id)),
    )?;

    let now: DateTime<Utc> = SystemTime::now().into();
    let issuance_date = issuance_date.unwrap_or(now);
    let created_date = created_date.unwrap_or(now);
    let expiration_date = expiration_date.unwrap_or(
        now.checked_add_months(Months::new(32))
            .expect("Failed to get expiration date"),
    );
    let issuance_date = issuance_date.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let created_date = created_date.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let expiration_date = expiration_date.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let (claims, claims_id) = claims.as_object().context("Claims is not an object!")?;
    let (claims, mut claims_id) = (claims.clone(), claims_id.clone());
    if let ObjectId::BlankNode(_) = claims_id {
        claims_id = ObjectId::None;
    };

    let mut data = rdf_util::from_str(format!(
        r#"
        _:b0 <https://www.w3.org/2018/credentials#issuer> <{issuer_id}> .
        _:b0 <https://www.w3.org/2018/credentials#issuanceDate> "{issuance_date}"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        _:b0 <https://www.w3.org/2018/credentials#expirationDate> "{expiration_date}"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        "#,
    ))?;

    let vc_type = if let Some(t) = vc_type {
        RdfValue::Array(vec![
            RdfValue::ObjectRef(ObjectId::NamedNode(
                "https://www.w3.org/2018/credentials#VerifiableCredential".into(),
            )),
            RdfValue::String(t.into()),
        ])
    } else {
        RdfValue::ObjectRef(ObjectId::NamedNode(
            "https://www.w3.org/2018/credentials#VerifiableCredential".into(),
        ))
    };
    data["http://www.w3.org/1999/02/22-rdf-syntax-ns#type"] = vc_type;

    data["https://www.w3.org/2018/credentials#credentialSubject"] =
        RdfValue::Object(claims, claims_id);

    if let Some((x, y, x_1, x_2)) = device_binding {
        data[DEVICE_BINDING_KEY] = RdfValue::Object(
            BTreeMap::from([
                (
                    DEVICE_BINDING_KEY_X.into(),
                    RdfValue::Typed(x, BASE_64_BYTES_BE.into()),
                ),
                (
                    DEVICE_BINDING_KEY_Y.into(),
                    RdfValue::Typed(y, BASE_64_BYTES_BE.into()),
                ),
                (
                    DEVICE_BINDING_KEY_X_1.into(),
                    RdfValue::Typed(x_1, BASE_64_BYTES_BE.into()),
                ),
                (
                    DEVICE_BINDING_KEY_X_2.into(),
                    RdfValue::Typed(x_2, BASE_64_BYTES_BE.into()),
                ),
            ]),
            ObjectId::None,
        )
    }

    let proof_cfg = rdf_util::from_str(format!(
        r#"
        _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
        _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
        _:b0 <http://purl.org/dc/terms/created> "{created_date}"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
        _:b0 <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
        "#
    ))?;

    let mut vc = VerifiableCredential::new(data.to_graph(None), proof_cfg.to_graph(None));
    rdf_proofs::sign(rng, &mut vc, &issuer.to_graph(None).into()).expect("Failed to sign vc!");

    Ok(vc)
}
