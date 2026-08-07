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
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Instant,
};

use anyhow::Context;
use ark_bls12_381::Bls12_381;
use ecdsa_pops::PoPNativeNizk;
use proof_system::prelude::{
    ped_comm::PedersenCommitment, EqualWitnesses, MetaStatements, Statements, Witness, Witnesses,
};
use rand_core::RngCore;
use rdf_proofs::{KeyGraph, VcPair, VerifiableCredential};
use rdf_util::{
    oxrdf::{BlankNode, Graph, Literal, NamedNode, NamedOrBlankNode, Subject, Term},
    BlankGenerator, MultiGraph, ObjectId, Value as RdfValue,
};

use crate::{
    circuits::load_circuits,
    constants::{CHALLENGE_LABEL, MERLIN_TRANSCRIPT_LABEL},
    device_binding::{
        from_blsfr_to_arkblsfr, from_g1_to_arkg1, DeviceBindingNative,
        DeviceBindingPresentationNative, DeviceBindingPresentationSigma, DeviceBindingSigma,
        DEVICE_BINDING_KEY, DEVICE_BINDING_KEY_X, DEVICE_BINDING_KEY_X_1, DEVICE_BINDING_KEY_X_2,
        DEVICE_BINDING_KEY_Y,
    },
    vc::{
        index::index_of_vc,
        requirements::{DiscloseRequirement, EqualClaimsRequirement},
    },
};

use super::requirements::{DeviceBindingRequirement, ProofRequirement};

#[derive(Debug, Clone)]
pub struct VerifiablePresentationSigma {
    pub proof: MultiGraph,
    pub device_binding: Option<DeviceBindingPresentationSigma>,
}

#[derive(Clone)]
pub struct VerifiablePresentationNative {
    pub proof: MultiGraph,
    pub device_binding: Option<DeviceBindingPresentationNative>,
}

#[allow(clippy::too_many_arguments)]
pub fn present<R: RngCore>(
    rng: &mut R,
    vc: VerifiableCredential,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DeviceBindingRequirement>,
    proving_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<VerifiablePresentationSigma> {
    let mut deanon_map = HashMap::<NamedOrBlankNode, Term>::new();
    let mut predicates = Vec::<Graph>::new();
    let circuits = load_circuits(proving_keys);

    // Figure out what information needs to be disclosed and prepare the vp
    let vc_document = rdf_util::Value::from(&vc.document);

    let (body, id) = vc_document["https://www.w3.org/2018/credentials#credentialSubject"]
        .as_object()
        .context("Couldn't get the vc_document credentialSubject!")?;

    let mut generator = BlankGenerator::default();
    let mut disclosed = BTreeMap::<String, RdfValue>::new();

    for requirement in requirements {
        match requirement {
            ProofRequirement::Required(req) => {
                disclosed.insert(req.key.clone(), body[&req.key].clone());
            }
            ProofRequirement::Circuit {
                id,
                private_var,
                private_key,
                public_var,
                public_val,
                ..
            } => {
                let (_, value) = body.iter().find(|(k, _)| private_key == *k).unwrap();

                let value = match value {
                    RdfValue::String(s) => Term::Literal(Literal::new_simple_literal(s)),
                    RdfValue::Typed(v, t) => {
                        Term::Literal(Literal::new_typed_literal(v, NamedNode::new_unchecked(t)))
                    }
                    _ => anyhow::bail!("Invalid private value"),
                };

                let blank_id = generator.next("e");
                let blank = deanon_map
                    .iter()
                    .find_map(|(k, v)| (v == &value).then_some(k.clone()))
                    .unwrap_or_else(|| {
                        NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(blank_id.clone()))
                    });

                deanon_map.insert(blank.clone(), value);

                let public_val = match public_val {
                    RdfValue::String(s) => format!("\"{s}\""),
                    RdfValue::Typed(v, t) => format!("\"{v}\"^^<{t}>"),
                    _ => unimplemented!(),
                };

                let predicate = rdf_util::from_str(format!(
                    r#"
                    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#Predicate> .
                    _:b0 <https://zkp-ld.org/security#circuit> <{id}> .
                    _:b0 <https://zkp-ld.org/security#private> _:b1 .
                    _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b2 .
                    _:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PrivateVariable> .
                    _:b2 <https://zkp-ld.org/security#var> "{private_var}" .
                    _:b2 <https://zkp-ld.org/security#val> _:{blank_id} .
                    _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
                    _:b0 <https://zkp-ld.org/security#public> _:b3 .
                    _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b4 .
                    _:b4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PublicVariable> .
                    _:b4 <https://zkp-ld.org/security#var> "{public_var}" .
                    _:b4 <https://zkp-ld.org/security#val> {public_val} .
                    _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
                    "#
                )).unwrap().to_graph(None);

                predicates.push(predicate);

                disclosed.insert(
                    private_key.clone(),
                    RdfValue::ObjectRef(ObjectId::BlankNode(blank_id)),
                );
            }
            ProofRequirement::EqualClaims(_) => {
                return Err(anyhow::anyhow!(
                    "Equal claims should be handled in present_two!"
                ))
            }
        }
    }

    let mut vp_document = vc_document.clone();

    vp_document["https://www.w3.org/2018/credentials#credentialSubject"] =
        RdfValue::Object(disclosed, id.clone());

    // Handle device binding
    let mut statements = Statements::<Bls12_381>::new();
    let mut meta_statements = MetaStatements::new();
    let mut witnesses = Witnesses::<Bls12_381>::new();

    let device_binding = if let Some(db_req) = device_binding {
        let db = DeviceBindingSigma::new(
            rng,
            db_req.public_key,
            db_req.message,
            db_req.message_signature,
            &db_req.comm_key_secp_label,
            &db_req.comm_key_tom_label,
            &db_req.comm_key_bls_label,
            &db_req.bpp_setup_label,
            MERLIN_TRANSCRIPT_LABEL,
            CHALLENGE_LABEL,
        )?;

        statements.add(PedersenCommitment::new_statement_from_params(
            db.bls_comm_key.clone(),
            db.bls_comm_pk_x,
        ));

        statements.add(PedersenCommitment::new_statement_from_params(
            db.bls_comm_key.clone(),
            db.bls_comm_pk_y,
        ));

        witnesses.add(Witness::PedersenCommitment(db.bls_scalars_x.clone()));
        witnesses.add(Witness::PedersenCommitment(db.bls_scalars_y.clone()));

        let (db_map, db_id) = vc_document[DEVICE_BINDING_KEY]
            .as_object()
            .context("verifiable credential has no device_binding")?;

        anyhow::ensure!(
            !matches!(db_id, ObjectId::None),
            "device binding object id can't be none!"
        );
        let RdfValue::Typed(x_1_value, x_1_type) = db_map
            .get(DEVICE_BINDING_KEY_X_1)
            .context("device binding has no x_1 value")?
        else {
            anyhow::bail!("device binding invalid x_1 value")
        };
        let x1_term = Term::Literal(Literal::new_typed_literal(
            x_1_value,
            NamedNode::new_unchecked(x_1_type),
        ));

        let RdfValue::Typed(x_value, x_type) = db_map
            .get(DEVICE_BINDING_KEY_X)
            .context("device binding has no x_1 value")?
        else {
            anyhow::bail!("device binding invalid x_1 value")
        };
        let x_term = Term::Literal(Literal::new_typed_literal(
            x_value,
            NamedNode::new_unchecked(x_type),
        ));
        let RdfValue::Typed(y_value, y_type) = db_map
            .get(DEVICE_BINDING_KEY_Y)
            .context("device binding has no x_1 value")?
        else {
            anyhow::bail!("device binding invalid x_1 value")
        };
        let y_term = Term::Literal(Literal::new_typed_literal(
            y_value,
            NamedNode::new_unchecked(y_type),
        ));

        let RdfValue::Typed(x_2_value, x_2_type) = db_map
            .get(DEVICE_BINDING_KEY_X_2)
            .context("device binding has no x_2 value")?
        else {
            anyhow::bail!("device binding invalid x_2 value")
        };
        let x2_term = Term::Literal(Literal::new_typed_literal(
            x_2_value,
            NamedNode::new_unchecked(x_2_type),
        ));

        vp_document[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X] =
            RdfValue::ObjectRef(ObjectId::BlankNode("d0".into()));
        vp_document[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_Y] =
            RdfValue::ObjectRef(ObjectId::BlankNode("d1".into()));
        vp_document[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X_1] =
            RdfValue::ObjectRef(ObjectId::BlankNode("d2".into()));
        vp_document[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X_2] =
            RdfValue::ObjectRef(ObjectId::BlankNode("d3".into()));

        deanon_map.insert(
            NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d2")),
            x1_term.clone(),
        );
        deanon_map.insert(
            NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d3")),
            x2_term.clone(),
        );
        deanon_map.insert(
            NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d0")),
            x_term.clone(),
        );
        deanon_map.insert(
            NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d1")),
            y_term.clone(),
        );

        let terms = rdf_proofs::signature::transform(&vc.document).unwrap();

        let x_index = index_of_vc(&vc, &x_term, &terms);
        let y_index = index_of_vc(&vc, &y_term, &terms);

        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, x_index), (1, 0)])));
        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, y_index), (2, 0)])));

        Some(db)
    } else {
        None
    };

    // Create the proof
    let issuer = KeyGraph::from(rdf_util::from_str_with_hint(format!(
        r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}"^^<https://w3id.org/security#multibase> .
        "#
    ), Subject::NamedNode(NamedNode::new_unchecked(issuer_id)))?.to_graph(None));

    let vc_pairs = vec![VcPair::new(
        vc.clone(),
        VerifiableCredential {
            document: vp_document.to_graph(None),
            proof: vc.proof.clone(),
        },
    )];

    let proof = rdf_proofs::derive_proof(
        rng,
        &vc_pairs,
        &deanon_map,
        &issuer,
        None,
        None,
        None,
        None,
        None,
        predicates,
        circuits,
        Some(statements),
        Some(meta_statements),
        Some(witnesses),
    )?;

    Ok(VerifiablePresentationSigma {
        proof: MultiGraph::new(&proof),
        device_binding: device_binding.map(|db| db.present()),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn present_native<R: RngCore>(
    rng: &mut R,
    vc: VerifiableCredential,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DeviceBindingRequirement>,
    proving_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
    setup: Option<PoPNativeNizk>,
) -> anyhow::Result<VerifiablePresentationNative> {
    let start = Instant::now();
    let mut deanon_map = HashMap::<NamedOrBlankNode, Term>::new();
    let mut predicates = Vec::<Graph>::new();
    let circuits = load_circuits(proving_keys);
    let end = Instant::now();
    println!("elapsed [Circuits loaded]: {}", (end - start).as_millis());

    let start = Instant::now();

    // Figure out what information needs to be disclosed and prepare the vp
    let vc_document = rdf_util::Value::from(&vc.document);

    let (body, id) = vc_document["https://www.w3.org/2018/credentials#credentialSubject"]
        .as_object()
        .context("Couldn't get the vc_document credentialSubject!")?;

    let mut generator = BlankGenerator::default();
    let mut disclosed = BTreeMap::<String, RdfValue>::new();

    for requirement in requirements {
        match requirement {
            ProofRequirement::Required(req) => {
                disclosed.insert(req.key.clone(), body[&req.key].clone());
            }
            ProofRequirement::Circuit {
                id,
                private_var,
                private_key,
                public_var,
                public_val,
                ..
            } => {
                let (_, value) = body.iter().find(|(k, _)| private_key == *k).unwrap();

                let value = match value {
                    RdfValue::String(s) => Term::Literal(Literal::new_simple_literal(s)),
                    RdfValue::Typed(v, t) => {
                        Term::Literal(Literal::new_typed_literal(v, NamedNode::new_unchecked(t)))
                    }
                    _ => anyhow::bail!("Invalid private value"),
                };

                let blank_id = generator.next("e");
                let blank = deanon_map
                    .iter()
                    .find_map(|(k, v)| (v == &value).then_some(k.clone()))
                    .unwrap_or_else(|| {
                        NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(blank_id.clone()))
                    });

                deanon_map.insert(blank.clone(), value);

                let public_val = match public_val {
                    RdfValue::String(s) => format!("\"{s}\""),
                    RdfValue::Typed(v, t) => format!("\"{v}\"^^<{t}>"),
                    _ => unimplemented!(),
                };

                let predicate = rdf_util::from_str(format!(
                    r#"
                    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#Predicate> .
                    _:b0 <https://zkp-ld.org/security#circuit> <{id}> .
                    _:b0 <https://zkp-ld.org/security#private> _:b1 .
                    _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b2 .
                    _:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PrivateVariable> .
                    _:b2 <https://zkp-ld.org/security#var> "{private_var}" .
                    _:b2 <https://zkp-ld.org/security#val> _:{blank_id} .
                    _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
                    _:b0 <https://zkp-ld.org/security#public> _:b3 .
                    _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b4 .
                    _:b4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PublicVariable> .
                    _:b4 <https://zkp-ld.org/security#var> "{public_var}" .
                    _:b4 <https://zkp-ld.org/security#val> {public_val} .
                    _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
                    "#
                )).unwrap().to_graph(None);

                predicates.push(predicate);

                disclosed.insert(
                    private_key.clone(),
                    RdfValue::ObjectRef(ObjectId::BlankNode(blank_id)),
                );
            }
            ProofRequirement::EqualClaims(_) => {
                return Err(anyhow::anyhow!(
                    "Equal claims should be handled in present_two!"
                ))
            }
        }
    }
    let end = Instant::now();
    println!(
        "elapsed [requirements added]: {}",
        (end - start).as_millis()
    );

    let start = Instant::now();

    let mut vp_document = vc_document.clone();

    vp_document["https://www.w3.org/2018/credentials#credentialSubject"] =
        RdfValue::Object(disclosed, id.clone());

    // Handle device binding
    let mut statements = Statements::<Bls12_381>::new();
    let mut meta_statements = MetaStatements::new();
    let mut witnesses = Witnesses::<Bls12_381>::new();

    let device_binding = if let Some(db_req) = device_binding {
        let start = Instant::now();
        let db = DeviceBindingNative::new(
            db_req.public_key,
            db_req.message,
            db_req.message_signature,
            "pop",
            setup,
        )?;
        let end = Instant::now();
        println!("elapsed [actual proof]: {}", (end - start).as_millis());
        let coms = vec![
            from_g1_to_arkg1(&db.params.ck_bls()),
            from_g1_to_arkg1(&db.params.ck_bls_blinding()),
        ];
        statements.add(PedersenCommitment::new_statement_from_params(
            coms.clone(),
            from_g1_to_arkg1(&db.bls_comm_pk_x1),
        ));

        statements.add(PedersenCommitment::new_statement_from_params(
            coms.clone(),
            from_g1_to_arkg1(&db.bls_comm_pk_x2),
        ));
        let scalars_x1 = vec![
            from_blsfr_to_arkblsfr(&db.bls_scalar_x1),
            from_blsfr_to_arkblsfr(&db.bls_scalar_x1_blinding),
        ];
        let scalars_x2 = vec![
            from_blsfr_to_arkblsfr(&db.bls_scalar_x2),
            from_blsfr_to_arkblsfr(&db.bls_scalar_x2_blinding),
        ];

        witnesses.add(Witness::PedersenCommitment(scalars_x1));
        witnesses.add(Witness::PedersenCommitment(scalars_x2));

        let (db_map, db_id) = vc_document[DEVICE_BINDING_KEY]
            .as_object()
            .context("verifiable credential has no device_binding")?;

        anyhow::ensure!(
            !matches!(db_id, ObjectId::None),
            "device binding object id can't be none!"
        );
        let RdfValue::Typed(x_1_value, x_1_type) = db_map
            .get(DEVICE_BINDING_KEY_X_1)
            .context("device binding has no x_1 value")?
        else {
            anyhow::bail!("device binding invalid x_1 value")
        };
        let x1_term = Term::Literal(Literal::new_typed_literal(
            x_1_value,
            NamedNode::new_unchecked(x_1_type),
        ));

        let RdfValue::Typed(x_value, x_type) = db_map
            .get(DEVICE_BINDING_KEY_X)
            .context("device binding has no x_1 value")?
        else {
            anyhow::bail!("device binding invalid x_1 value")
        };
        let x_term = Term::Literal(Literal::new_typed_literal(
            x_value,
            NamedNode::new_unchecked(x_type),
        ));
        let RdfValue::Typed(y_value, y_type) = db_map
            .get(DEVICE_BINDING_KEY_Y)
            .context("device binding has no x_1 value")?
        else {
            anyhow::bail!("device binding invalid x_1 value")
        };
        let y_term = Term::Literal(Literal::new_typed_literal(
            y_value,
            NamedNode::new_unchecked(y_type),
        ));

        let RdfValue::Typed(x_2_value, x_2_type) = db_map
            .get(DEVICE_BINDING_KEY_X_2)
            .context("device binding has no x_2 value")?
        else {
            anyhow::bail!("device binding invalid x_2 value")
        };
        let x2_term = Term::Literal(Literal::new_typed_literal(
            x_2_value,
            NamedNode::new_unchecked(x_2_type),
        ));

        vp_document[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X] =
            RdfValue::ObjectRef(ObjectId::BlankNode("d0".into()));
        vp_document[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_Y] =
            RdfValue::ObjectRef(ObjectId::BlankNode("d1".into()));
        vp_document[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X_1] =
            RdfValue::ObjectRef(ObjectId::BlankNode("d2".into()));
        vp_document[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X_2] =
            RdfValue::ObjectRef(ObjectId::BlankNode("d3".into()));

        deanon_map.insert(
            NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d2")),
            x1_term.clone(),
        );
        deanon_map.insert(
            NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d3")),
            x2_term.clone(),
        );
        deanon_map.insert(
            NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d0")),
            x_term.clone(),
        );
        deanon_map.insert(
            NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d1")),
            y_term.clone(),
        );

        let terms = rdf_proofs::signature::transform(&vc.document).unwrap();

        let x_index = index_of_vc(&vc, &x1_term, &terms);
        let y_index = index_of_vc(&vc, &x2_term, &terms);

        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, x_index), (1, 0)])));
        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, y_index), (2, 0)])));

        Some(db)
    } else {
        None
    };
    let end = Instant::now();
    println!(
        "elapsed [device binding proof]: {}",
        (end - start).as_millis()
    );

    let start = Instant::now();
    // Create the proof
    let issuer = KeyGraph::from(rdf_util::from_str_with_hint(format!(
        r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}"^^<https://w3id.org/security#multibase> .
        "#
    ), Subject::NamedNode(NamedNode::new_unchecked(issuer_id)))?.to_graph(None));

    let vc_pairs = vec![VcPair::new(
        vc.clone(),
        VerifiableCredential {
            document: vp_document.to_graph(None),
            proof: vc.proof.clone(),
        },
    )];

    let proof = rdf_proofs::derive_proof(
        rng,
        &vc_pairs,
        &deanon_map,
        &issuer,
        None,
        None,
        None,
        None,
        None,
        predicates,
        circuits,
        Some(statements),
        Some(meta_statements),
        Some(witnesses),
    )?;
    let end = Instant::now();
    println!(
        "elapsed [proof of knowledge]: {}",
        (end - start).as_millis()
    );

    Ok(VerifiablePresentationNative {
        proof: MultiGraph::new(&proof),
        device_binding: device_binding.map(|db| db.present()),
    })
}

pub fn present_two<R: RngCore>(
    rng: &mut R,

    // This is the identity VC
    vc1: VerifiableCredential,
    req1: &Vec<DiscloseRequirement>,
    db1: Option<DeviceBindingRequirement>,

    // This is the diploma VC
    vc2: VerifiableCredential,
    req2: &Vec<DiscloseRequirement>,

    claims_eq: &Vec<EqualClaimsRequirement>,

    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<VerifiablePresentationSigma> {
    let mut deanon_map = HashMap::<NamedOrBlankNode, Term>::new();

    let vc1_doc = rdf_util::Value::from(&vc1.document);
    let (body1, bid1) = vc1_doc["https://www.w3.org/2018/credentials#credentialSubject"]
        .as_object()
        .context("Couldn't get the vc_document credentialSubject!")?;

    let vc2_doc = rdf_util::Value::from(&vc2.document);
    let (body2, bid2) = vc2_doc["https://www.w3.org/2018/credentials#credentialSubject"]
        .as_object()
        .context("Couldn't get the vc_document credentialSubject!")?;

    let key_graph = KeyGraph::from(rdf_util::parse_triples(format!(
        r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}"^^<https://w3id.org/security#multibase> .
        "#
    ))?);

    let mut statements = Statements::<Bls12_381>::new();
    let mut meta_statements = MetaStatements::new();
    let mut witnesses = Witnesses::<Bls12_381>::new();

    let mut eq_idx_1 = Vec::<usize>::new();
    let (vc1_disclosed, db) = {
        let mut doc = vc1_doc.clone();
        doc["https://www.w3.org/2018/credentials#credentialSubject"] =
            RdfValue::Object(BTreeMap::new(), bid1.clone());

        for req in req1 {
            doc["https://www.w3.org/2018/credentials#credentialSubject"][req.key.clone()] =
                body1[&req.key].clone();
        }

        let terms = rdf_proofs::signature::transform(&vc1.document).unwrap();
        for eq in claims_eq {
            let v = body1
                .get(&eq.key1)
                .context("Couldn't find claim in vc1 for equality check")?;
            let blank_id = format!("eq{}", deanon_map.len());

            doc["https://www.w3.org/2018/credentials#credentialSubject"][eq.key1.clone()] =
                RdfValue::ObjectRef(ObjectId::BlankNode(blank_id.clone()));

            let term = v.to_term_value().unwrap();

            eq_idx_1.push(index_of_vc(&vc1, &term, &terms));
            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(blank_id.clone())),
                term,
            );
        }

        let device_binding = if let Some(db_req) = db1 {
            let db = DeviceBindingSigma::new(
                rng,
                db_req.public_key,
                db_req.message,
                db_req.message_signature,
                &db_req.comm_key_secp_label,
                &db_req.comm_key_tom_label,
                &db_req.comm_key_bls_label,
                &db_req.bpp_setup_label,
                MERLIN_TRANSCRIPT_LABEL,
                CHALLENGE_LABEL,
            )?;

            statements.add(PedersenCommitment::new_statement_from_params(
                db.bls_comm_key.clone(),
                db.bls_comm_pk_x,
            ));

            statements.add(PedersenCommitment::new_statement_from_params(
                db.bls_comm_key.clone(),
                db.bls_comm_pk_y,
            ));

            witnesses.add(Witness::PedersenCommitment(db.bls_scalars_x.clone()));
            witnesses.add(Witness::PedersenCommitment(db.bls_scalars_y.clone()));

            let (db_map, db_id) = vc1_doc[DEVICE_BINDING_KEY]
                .as_object()
                .context("verifiable credential has no device_binding")?;

            anyhow::ensure!(
                !matches!(db_id, ObjectId::None),
                "device binding object id can't be none!"
            );
            let RdfValue::Typed(x_1_value, x_1_type) = db_map
                .get(DEVICE_BINDING_KEY_X_1)
                .context("device binding has no x_1 value")?
            else {
                anyhow::bail!("device binding invalid x_1 value")
            };
            let x1_term = Term::Literal(Literal::new_typed_literal(
                x_1_value,
                NamedNode::new_unchecked(x_1_type),
            ));

            let RdfValue::Typed(x_value, x_type) = db_map
                .get(DEVICE_BINDING_KEY_X)
                .context("device binding has no x_1 value")?
            else {
                anyhow::bail!("device binding invalid x_1 value")
            };
            let x_term = Term::Literal(Literal::new_typed_literal(
                x_value,
                NamedNode::new_unchecked(x_type),
            ));
            let RdfValue::Typed(y_value, y_type) = db_map
                .get(DEVICE_BINDING_KEY_Y)
                .context("device binding has no x_1 value")?
            else {
                anyhow::bail!("device binding invalid x_1 value")
            };
            let y_term = Term::Literal(Literal::new_typed_literal(
                y_value,
                NamedNode::new_unchecked(y_type),
            ));

            let RdfValue::Typed(x_2_value, x_2_type) = db_map
                .get(DEVICE_BINDING_KEY_X_2)
                .context("device binding has no x_2 value")?
            else {
                anyhow::bail!("device binding invalid x_2 value")
            };
            let x2_term = Term::Literal(Literal::new_typed_literal(
                x_2_value,
                NamedNode::new_unchecked(x_2_type),
            ));

            doc[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X] =
                RdfValue::ObjectRef(ObjectId::BlankNode("d0".into()));
            doc[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_Y] =
                RdfValue::ObjectRef(ObjectId::BlankNode("d1".into()));
            doc[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X_1] =
                RdfValue::ObjectRef(ObjectId::BlankNode("d2".into()));
            doc[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X_2] =
                RdfValue::ObjectRef(ObjectId::BlankNode("d3".into()));

            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d2")),
                x1_term.clone(),
            );
            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d3")),
                x2_term.clone(),
            );
            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d0")),
                x_term.clone(),
            );
            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d1")),
                y_term.clone(),
            );
            let terms = rdf_proofs::signature::transform(&vc1.document).unwrap();

            let x_index = index_of_vc(&vc1, &x_term, &terms);
            let y_index = index_of_vc(&vc1, &y_term, &terms);

            meta_statements
                .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, x_index), (2, 0)])));
            meta_statements
                .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, y_index), (3, 0)])));

            Some(db)
        } else {
            None
        };

        (
            VerifiableCredential {
                document: doc.to_graph(None),
                proof: vc1.proof.clone(),
            },
            device_binding,
        )
    };

    let mut eq_idx_2 = Vec::<usize>::new();
    let vc2_disclosed = {
        let mut doc = vc2_doc.clone();
        doc["https://www.w3.org/2018/credentials#credentialSubject"] =
            RdfValue::Object(BTreeMap::new(), bid2.clone());

        for req in req2 {
            doc["https://www.w3.org/2018/credentials#credentialSubject"][req.key.clone()] =
                body2[&req.key].clone();
        }

        let terms = rdf_proofs::signature::transform(&vc2.document).unwrap();

        for eq in claims_eq {
            let v = body2
                .get(&eq.key2)
                .context("Couldn't find claim in vc2 for equality check")?;
            let blank_id = format!("eq{}", deanon_map.len());

            doc["https://www.w3.org/2018/credentials#credentialSubject"][eq.key2.clone()] =
                RdfValue::ObjectRef(ObjectId::BlankNode(blank_id.clone()));

            let term = v.to_term_value().unwrap();

            eq_idx_2.push(index_of_vc(&vc2, &term, &terms));
            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(blank_id.clone())),
                term,
            );
        }

        VerifiableCredential {
            document: doc.to_graph(None),
            proof: vc2.proof.clone(),
        }
    };

    for (i, eq) in claims_eq.iter().enumerate() {
        let v1 = body1
            .get(&eq.key1)
            .context("Couldn't find claim in vc1 for equality check")?;
        let v2 = body2
            .get(&eq.key2)
            .context("Couldn't find claim in vc2 for equality check")?;

        anyhow::ensure!(v1 == v2, "Claims to be equal are not equal!");
        meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
            (0, eq_idx_1[i]),
            (1, eq_idx_2[i]),
        ])));
    }

    let vc_pairs = vec![
        VcPair::new(vc1, vc1_disclosed),
        VcPair::new(vc2, vc2_disclosed),
    ];

    let proof = rdf_proofs::derive_proof(
        rng,
        &vc_pairs,
        &deanon_map,
        &key_graph,
        None,
        None,
        None,
        None,
        None,
        Vec::new(),
        HashMap::new(),
        Some(statements),
        Some(meta_statements),
        Some(witnesses),
    )?;

    Ok(VerifiablePresentationSigma {
        proof: MultiGraph::new(&proof),
        device_binding: db.map(|db| db.present()),
    })
}

pub fn present_two_native<R: RngCore>(
    rng: &mut R,

    // This is the identity VC
    vc1: VerifiableCredential,
    req1: &Vec<DiscloseRequirement>,
    db1: Option<(DeviceBindingRequirement, Option<PoPNativeNizk>)>,

    // This is the diploma VC
    vc2: VerifiableCredential,
    req2: &Vec<DiscloseRequirement>,

    claims_eq: &Vec<EqualClaimsRequirement>,

    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<VerifiablePresentationNative> {
    let mut deanon_map = HashMap::<NamedOrBlankNode, Term>::new();

    let vc1_doc = rdf_util::Value::from(&vc1.document);
    let (body1, bid1) = vc1_doc["https://www.w3.org/2018/credentials#credentialSubject"]
        .as_object()
        .context("Couldn't get the vc_document credentialSubject!")?;

    let vc2_doc = rdf_util::Value::from(&vc2.document);
    let (body2, bid2) = vc2_doc["https://www.w3.org/2018/credentials#credentialSubject"]
        .as_object()
        .context("Couldn't get the vc_document credentialSubject!")?;

    let key_graph = KeyGraph::from(rdf_util::parse_triples(format!(
        r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}"^^<https://w3id.org/security#multibase> .
        "#
    ))?);

    let mut statements = Statements::<Bls12_381>::new();
    let mut meta_statements = MetaStatements::new();
    let mut witnesses = Witnesses::<Bls12_381>::new();

    let mut eq_idx_1 = Vec::<usize>::new();
    let (vc1_disclosed, db) = {
        let mut doc = vc1_doc.clone();
        doc["https://www.w3.org/2018/credentials#credentialSubject"] =
            RdfValue::Object(BTreeMap::new(), bid1.clone());

        for req in req1 {
            doc["https://www.w3.org/2018/credentials#credentialSubject"][req.key.clone()] =
                body1[&req.key].clone();
        }

        let terms = rdf_proofs::signature::transform(&vc1.document).unwrap();
        for eq in claims_eq {
            let v = body1
                .get(&eq.key1)
                .context("Couldn't find claim in vc1 for equality check")?;
            let blank_id = format!("eq{}", deanon_map.len());

            doc["https://www.w3.org/2018/credentials#credentialSubject"][eq.key1.clone()] =
                RdfValue::ObjectRef(ObjectId::BlankNode(blank_id.clone()));

            let term = v.to_term_value().unwrap();

            eq_idx_1.push(index_of_vc(&vc1, &term, &terms));
            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(blank_id.clone())),
                term,
            );
        }

        let device_binding = if let Some((db_req, setup)) = db1 {
            let start = Instant::now();
            let db = DeviceBindingNative::new(
                db_req.public_key,
                db_req.message,
                db_req.message_signature,
                "pop",
                setup,
            )?;
            let end = Instant::now();
            println!("elapsed [actual proof]: {}", (end - start).as_millis());
            let coms = vec![
                from_g1_to_arkg1(&db.params.ck_bls()),
                from_g1_to_arkg1(&db.params.ck_bls_blinding()),
            ];
            statements.add(PedersenCommitment::new_statement_from_params(
                coms.clone(),
                from_g1_to_arkg1(&db.bls_comm_pk_x1),
            ));

            statements.add(PedersenCommitment::new_statement_from_params(
                coms.clone(),
                from_g1_to_arkg1(&db.bls_comm_pk_x2),
            ));
            let scalars_x1 = vec![
                from_blsfr_to_arkblsfr(&db.bls_scalar_x1),
                from_blsfr_to_arkblsfr(&db.bls_scalar_x1_blinding),
            ];
            let scalars_x2 = vec![
                from_blsfr_to_arkblsfr(&db.bls_scalar_x2),
                from_blsfr_to_arkblsfr(&db.bls_scalar_x2_blinding),
            ];

            witnesses.add(Witness::PedersenCommitment(scalars_x1));
            witnesses.add(Witness::PedersenCommitment(scalars_x2));

            let (db_map, db_id) = vc1_doc[DEVICE_BINDING_KEY]
                .as_object()
                .context("verifiable credential has no device_binding")?;

            anyhow::ensure!(
                !matches!(db_id, ObjectId::None),
                "device binding object id can't be none!"
            );
            let RdfValue::Typed(x_1_value, x_1_type) = db_map
                .get(DEVICE_BINDING_KEY_X_1)
                .context("device binding has no x_1 value")?
            else {
                anyhow::bail!("device binding invalid x_1 value")
            };
            let x1_term = Term::Literal(Literal::new_typed_literal(
                x_1_value,
                NamedNode::new_unchecked(x_1_type),
            ));

            let RdfValue::Typed(x_value, x_type) = db_map
                .get(DEVICE_BINDING_KEY_X)
                .context("device binding has no x_1 value")?
            else {
                anyhow::bail!("device binding invalid x_1 value")
            };
            let x_term = Term::Literal(Literal::new_typed_literal(
                x_value,
                NamedNode::new_unchecked(x_type),
            ));
            let RdfValue::Typed(y_value, y_type) = db_map
                .get(DEVICE_BINDING_KEY_Y)
                .context("device binding has no x_1 value")?
            else {
                anyhow::bail!("device binding invalid x_1 value")
            };
            let y_term = Term::Literal(Literal::new_typed_literal(
                y_value,
                NamedNode::new_unchecked(y_type),
            ));

            let RdfValue::Typed(x_2_value, x_2_type) = db_map
                .get(DEVICE_BINDING_KEY_X_2)
                .context("device binding has no x_2 value")?
            else {
                anyhow::bail!("device binding invalid x_2 value")
            };
            let x2_term = Term::Literal(Literal::new_typed_literal(
                x_2_value,
                NamedNode::new_unchecked(x_2_type),
            ));

            doc[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X] =
                RdfValue::ObjectRef(ObjectId::BlankNode("d0".into()));
            doc[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_Y] =
                RdfValue::ObjectRef(ObjectId::BlankNode("d1".into()));
            doc[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X_1] =
                RdfValue::ObjectRef(ObjectId::BlankNode("d2".into()));
            doc[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X_2] =
                RdfValue::ObjectRef(ObjectId::BlankNode("d3".into()));

            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d2")),
                x1_term.clone(),
            );
            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d3")),
                x2_term.clone(),
            );
            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d0")),
                x_term.clone(),
            );
            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d1")),
                y_term.clone(),
            );
            let terms = rdf_proofs::signature::transform(&vc1.document).unwrap();

            let x_index = index_of_vc(&vc1, &x_term, &terms);
            let y_index = index_of_vc(&vc1, &y_term, &terms);

            meta_statements
                .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, x_index), (2, 0)])));
            meta_statements
                .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, y_index), (3, 0)])));

            Some(db)
        } else {
            None
        };

        (
            VerifiableCredential {
                document: doc.to_graph(None),
                proof: vc1.proof.clone(),
            },
            device_binding,
        )
    };

    let mut eq_idx_2 = Vec::<usize>::new();
    let vc2_disclosed = {
        let mut doc = vc2_doc.clone();
        doc["https://www.w3.org/2018/credentials#credentialSubject"] =
            RdfValue::Object(BTreeMap::new(), bid2.clone());

        for req in req2 {
            doc["https://www.w3.org/2018/credentials#credentialSubject"][req.key.clone()] =
                body2[&req.key].clone();
        }

        let terms = rdf_proofs::signature::transform(&vc2.document).unwrap();

        for eq in claims_eq {
            let v = body2
                .get(&eq.key2)
                .context("Couldn't find claim in vc2 for equality check")?;
            let blank_id = format!("eq{}", deanon_map.len());

            doc["https://www.w3.org/2018/credentials#credentialSubject"][eq.key2.clone()] =
                RdfValue::ObjectRef(ObjectId::BlankNode(blank_id.clone()));

            let term = v.to_term_value().unwrap();

            eq_idx_2.push(index_of_vc(&vc2, &term, &terms));
            deanon_map.insert(
                NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(blank_id.clone())),
                term,
            );
        }

        VerifiableCredential {
            document: doc.to_graph(None),
            proof: vc2.proof.clone(),
        }
    };

    for (i, eq) in claims_eq.iter().enumerate() {
        let v1 = body1
            .get(&eq.key1)
            .context("Couldn't find claim in vc1 for equality check")?;
        let v2 = body2
            .get(&eq.key2)
            .context("Couldn't find claim in vc2 for equality check")?;

        anyhow::ensure!(v1 == v2, "Claims to be equal are not equal!");
        meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
            (0, eq_idx_1[i]),
            (1, eq_idx_2[i]),
        ])));
    }

    let vc_pairs = vec![
        VcPair::new(vc1, vc1_disclosed),
        VcPair::new(vc2, vc2_disclosed),
    ];

    let proof = rdf_proofs::derive_proof(
        rng,
        &vc_pairs,
        &deanon_map,
        &key_graph,
        None,
        None,
        None,
        None,
        None,
        Vec::new(),
        HashMap::new(),
        Some(statements),
        Some(meta_statements),
        Some(witnesses),
    )?;

    Ok(VerifiablePresentationNative {
        proof: MultiGraph::new(&proof),
        device_binding: db.map(|db| db.present()),
    })
}
