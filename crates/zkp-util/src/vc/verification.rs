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

use anyhow::Context;
use ark_bls12_381::Bls12_381;
use proof_system::prelude::{
    ped_comm::PedersenCommitment, r1cs_legogroth16::VerifyingKey, EqualWitnesses, MetaStatements,
    Statements,
};
use rand_core::RngCore;
use rdf_proofs::{multibase_to_ark, KeyGraph};
use rdf_util::{
    oxrdf::{GraphName, NamedNode, Subject},
    Value as RdfValue,
};
use serde_json::Value as JsonValue;
use std::collections::{BTreeSet, HashMap};

use crate::{
    constants::{CHALLENGE_LABEL, MERLIN_TRANSCRIPT_LABEL},
    device_binding::{
        from_g1_to_arkg1, DEVICE_BINDING_KEY_X, DEVICE_BINDING_KEY_X_1, DEVICE_BINDING_KEY_X_2,
        DEVICE_BINDING_KEY_Y,
    },
    vc::{index::index_of_vp, presentation::VerifiablePresentationNative},
};

use super::{
    presentation::VerifiablePresentationSigma,
    requirements::{DeviceBindingVerificationParams, ProofRequirement},
};

#[allow(clippy::too_many_arguments)]
pub fn verify<R: RngCore>(
    rng: &mut R,
    presentation: VerifiablePresentationSigma,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DeviceBindingVerificationParams>,
    verifying_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
    num_vcs: usize,
) -> anyhow::Result<JsonValue> {
    let verifying_keys: HashMap<NamedNode, VerifyingKey<Bls12_381>> = verifying_keys
        .iter()
        .map(|(k, v)| (NamedNode::new_unchecked(k), multibase_to_ark(v).unwrap()))
        .collect();

    let proof = presentation.proof.to_value(GraphName::DefaultGraph);
    let credentials = match &proof["https://www.w3.org/2018/credentials#verifiableCredential"] {
        RdfValue::Object(m, id) => vec![RdfValue::Object(m.clone(), id.clone())],
        RdfValue::Array(arr) => arr.clone(),
        _ => anyhow::bail!("Invalid credential: {proof:#?}"),
    };
    let predicates = match proof.get("https://zkp-ld.org/security#predicate") {
        Some(RdfValue::Object(m, id)) => vec![RdfValue::Object(m.clone(), id.clone())],
        Some(RdfValue::Array(array)) => array.clone(),
        None => vec![],
        _ => anyhow::bail!("Invalid predicates: {proof:#?}"),
    };

    // Verify the device binding
    let mut statements = Statements::new();
    let mut meta_statements = MetaStatements::new();

    if let Some(db) = presentation.device_binding {
        let Some(params) = device_binding else {
            anyhow::bail!("Device binding verification params expected!")
        };

        // add the statements about the public key commitment
        statements.add(PedersenCommitment::new_statement_from_params(
            db.bls_comm_key.clone(),
            db.bls_comm_pk_x,
        ));
        // add the statements about the public key commitment
        statements.add(PedersenCommitment::new_statement_from_params(
            db.bls_comm_key.clone(),
            db.bls_comm_pk_y,
        ));

        // TODO: This is a biiiiig hack
        let (x_index, graph_idx) = {
            if let Some(idx) = index_of_vp(
                &presentation.proof.dataset(),
                &NamedNode::new_unchecked(DEVICE_BINDING_KEY_X),
                0,
            ) {
                (idx + 1, 0)
            } else {
                (
                    index_of_vp(
                        &presentation.proof.dataset(),
                        &NamedNode::new_unchecked(DEVICE_BINDING_KEY_X),
                        1,
                    )
                    .unwrap()
                        + 1,
                    1,
                )
            }
        };
        let y_index = index_of_vp(
            &presentation.proof.dataset(),
            &NamedNode::new_unchecked(DEVICE_BINDING_KEY_Y),
            graph_idx,
        )
        .unwrap()
            + 1;

        meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
            (graph_idx, x_index),
            (num_vcs + 0, 0),
        ])));
        meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
            (graph_idx, y_index),
            (num_vcs + 1, 0),
        ])));

        db.verify(
            rng,
            params.message,
            &params.comm_key_secp_label,
            &params.comm_key_tom_label,
            &params.comm_key_bls_label,
            &params.bpp_setup_label,
            MERLIN_TRANSCRIPT_LABEL,
            CHALLENGE_LABEL,
        )?;
    }

    let issuer = KeyGraph::from(rdf_util::from_str_with_hint(format!(
        r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}"^^<https://w3id.org/security#multibase> .
        "#
    ), Subject::NamedNode(NamedNode::new_unchecked(issuer_id)))?.to_graph(None));

    for req in requirements {
        if let ProofRequirement::EqualClaims(eq) = req {
            let idx1 = index_of_vp(
                &presentation.proof.dataset(),
                &NamedNode::new_unchecked(&eq.key1),
                0,
            )
            .unwrap()
                + 1;
            let idx2 = index_of_vp(
                &presentation.proof.dataset(),
                &NamedNode::new_unchecked(&eq.key2),
                1,
            )
            .unwrap()
                + 1;

            meta_statements
                .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, idx1), (1, idx2)])));
        }
    }

    let result = rdf_proofs::verify_proof(
        rng,
        &presentation.proof.dataset(),
        &issuer,
        None,
        None,
        verifying_keys,
        Some(statements),
        Some(meta_statements),
    );

    assert!(result.is_ok(), "{result:#?}");

    let bodies = credentials
        .iter()
        .map(|c| c["https://www.w3.org/2018/credentials#credentialSubject"].to_json())
        .collect::<Vec<_>>();

    // Make sure the claims were reveiled
    for requirement in requirements {
        match requirement {
            ProofRequirement::Required(req) => {
                anyhow::ensure!(bodies.iter().find(|b| b.get(&req.key).is_some()).is_some())
            }
            ProofRequirement::Circuit {
                id,
                private_var,
                private_key,
                public_var,
                public_val,
            } => {
                // Find the matching predicate
                let predicate = predicates
                    .iter()
                    .find(|p| {
                        p["https://zkp-ld.org/security#circuit"].id().unwrap() == id
                            && &p["https://zkp-ld.org/security#public"]
                                ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                                ["https://zkp-ld.org/security#val"]
                                == public_val
                            && p["https://zkp-ld.org/security#public"]
                                ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                                ["https://zkp-ld.org/security#var"]
                                .as_string()
                                .unwrap()
                                == public_var
                            && p["https://zkp-ld.org/security#private"]
                                ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                                ["https://zkp-ld.org/security#var"]
                                .as_string()
                                .unwrap()
                                == private_var
                    })
                    .context("Couldn't find predicate!")?;

                // Make sure the id of the blank node matches the id specified in the predicate
                let Some(private_id) = predicate["https://zkp-ld.org/security#private"]
                    ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                    ["https://zkp-ld.org/security#val"]
                    .id()
                else {
                    anyhow::bail!("Couldn't get the private value of the circuit: {predicates:#?}")
                };

                let mut satisfied = false;
                for credential in &credentials {
                    let private_val = &credential
                        ["https://www.w3.org/2018/credentials#credentialSubject"][private_key];

                    let object_id = match private_val {
                        RdfValue::Object(_, id) | RdfValue::ObjectRef(id) => id,
                        _ => anyhow::bail!(
                            "Invalid private value, expected object, got {private_val:#?}"
                        ),
                    };
                    satisfied |= object_id == private_id;
                }

                anyhow::ensure!(satisfied, "circuit not satisfied!")
            }
            ProofRequirement::EqualClaims(_) => {}
        }
    }

    let body = if bodies.len() == 1 {
        bodies.into_iter().next().unwrap()
    } else {
        JsonValue::Array(bodies)
    };

    Ok(body)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_native<R: RngCore>(
    rng: &mut R,
    presentation: VerifiablePresentationNative,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DeviceBindingVerificationParams>,
    verifying_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
    num_vcs: usize,
) -> anyhow::Result<JsonValue> {
    let verifying_keys: HashMap<NamedNode, VerifyingKey<Bls12_381>> = verifying_keys
        .iter()
        .map(|(k, v)| (NamedNode::new_unchecked(k), multibase_to_ark(v).unwrap()))
        .collect();

    let proof = presentation.proof.to_value(GraphName::DefaultGraph);
    let credentials = match &proof["https://www.w3.org/2018/credentials#verifiableCredential"] {
        RdfValue::Object(m, id) => vec![RdfValue::Object(m.clone(), id.clone())],
        RdfValue::Array(arr) => arr.clone(),
        _ => anyhow::bail!("Invalid credential: {proof:#?}"),
    };
    let predicates = match proof.get("https://zkp-ld.org/security#predicate") {
        Some(RdfValue::Object(m, id)) => vec![RdfValue::Object(m.clone(), id.clone())],
        Some(RdfValue::Array(array)) => array.clone(),
        None => vec![],
        _ => anyhow::bail!("Invalid predicates: {proof:#?}"),
    };

    // Verify the device binding
    let mut statements = Statements::new();
    let mut meta_statements = MetaStatements::new();

    if let Some(db) = presentation.device_binding {
        let Some(params) = device_binding else {
            anyhow::bail!("Device binding verification params expected!")
        };
        let keys = vec![
            from_g1_to_arkg1(db.params.ck_bls()),
            from_g1_to_arkg1(db.params.ck_bls_blinding()),
        ];
        // add the statements about the public key commitment
        statements.add(PedersenCommitment::new_statement_from_params(
            keys.clone(),
            db.bls_comm_pk_x1,
        ));
        // add the statements about the public key commitment
        statements.add(PedersenCommitment::new_statement_from_params(
            keys.clone(),
            db.bls_comm_pk_x2,
        ));

        // TODO: This is a biiiiig hack
        let (x_index, graph_idx) = {
            if let Some(idx) = index_of_vp(
                &presentation.proof.dataset(),
                &NamedNode::new_unchecked(DEVICE_BINDING_KEY_X_1),
                0,
            ) {
                (idx + 1, 0)
            } else {
                (
                    index_of_vp(
                        &presentation.proof.dataset(),
                        &NamedNode::new_unchecked(DEVICE_BINDING_KEY_X_1),
                        1,
                    )
                    .unwrap()
                        + 1,
                    1,
                )
            }
        };
        let y_index = index_of_vp(
            &presentation.proof.dataset(),
            &NamedNode::new_unchecked(DEVICE_BINDING_KEY_X_2),
            graph_idx,
        )
        .unwrap()
            + 1;

        meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
            (graph_idx, x_index),
            (num_vcs + 0, 0),
        ])));
        meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
            (graph_idx, y_index),
            (num_vcs + 1, 0),
        ])));

        db.verify(b"pop native proof", params.message)?;
    }

    let issuer = KeyGraph::from(rdf_util::from_str_with_hint(format!(
        r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}"^^<https://w3id.org/security#multibase> .
        "#
    ), Subject::NamedNode(NamedNode::new_unchecked(issuer_id)))?.to_graph(None));

    for req in requirements {
        if let ProofRequirement::EqualClaims(eq) = req {
            let idx1 = index_of_vp(
                &presentation.proof.dataset(),
                &NamedNode::new_unchecked(&eq.key1),
                0,
            )
            .unwrap()
                + 1;
            let idx2 = index_of_vp(
                &presentation.proof.dataset(),
                &NamedNode::new_unchecked(&eq.key2),
                1,
            )
            .unwrap()
                + 1;

            meta_statements
                .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, idx1), (1, idx2)])));
        }
    }

    let result = rdf_proofs::verify_proof(
        rng,
        &presentation.proof.dataset(),
        &issuer,
        None,
        None,
        verifying_keys,
        Some(statements),
        Some(meta_statements),
    );

    assert!(result.is_ok(), "{result:#?}");

    let bodies = credentials
        .iter()
        .map(|c| c["https://www.w3.org/2018/credentials#credentialSubject"].to_json())
        .collect::<Vec<_>>();

    // Make sure the claims were reveiled
    for requirement in requirements {
        match requirement {
            ProofRequirement::Required(req) => {
                anyhow::ensure!(bodies.iter().find(|b| b.get(&req.key).is_some()).is_some())
            }
            ProofRequirement::Circuit {
                id,
                private_var,
                private_key,
                public_var,
                public_val,
            } => {
                // Find the matching predicate
                let predicate = predicates
                    .iter()
                    .find(|p| {
                        p["https://zkp-ld.org/security#circuit"].id().unwrap() == id
                            && &p["https://zkp-ld.org/security#public"]
                                ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                                ["https://zkp-ld.org/security#val"]
                                == public_val
                            && p["https://zkp-ld.org/security#public"]
                                ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                                ["https://zkp-ld.org/security#var"]
                                .as_string()
                                .unwrap()
                                == public_var
                            && p["https://zkp-ld.org/security#private"]
                                ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                                ["https://zkp-ld.org/security#var"]
                                .as_string()
                                .unwrap()
                                == private_var
                    })
                    .context("Couldn't find predicate!")?;

                // Make sure the id of the blank node matches the id specified in the predicate
                let Some(private_id) = predicate["https://zkp-ld.org/security#private"]
                    ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                    ["https://zkp-ld.org/security#val"]
                    .id()
                else {
                    anyhow::bail!("Couldn't get the private value of the circuit: {predicates:#?}")
                };

                let mut satisfied = false;
                for credential in &credentials {
                    let private_val = &credential
                        ["https://www.w3.org/2018/credentials#credentialSubject"][private_key];

                    let object_id = match private_val {
                        RdfValue::Object(_, id) | RdfValue::ObjectRef(id) => id,
                        _ => anyhow::bail!(
                            "Invalid private value, expected object, got {private_val:#?}"
                        ),
                    };
                    satisfied |= object_id == private_id;
                }

                anyhow::ensure!(satisfied, "circuit not satisfied!")
            }
            ProofRequirement::EqualClaims(_) => {}
        }
    }

    let body = if bodies.len() == 1 {
        bodies.into_iter().next().unwrap()
    } else {
        JsonValue::Array(bodies)
    };

    Ok(body)
}
