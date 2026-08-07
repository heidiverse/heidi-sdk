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

use ark_bls12_381::Bls12_381;
use legogroth16::circom::{r1cs::R1CSFile, CircomCircuit, R1CS as R1CSOrig};
use multibase::Base;
use rand_core::RngCore;
use rdf_proofs::{ark_to_base64url, Circuit};
use rdf_util::oxrdf::NamedNode;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Cursor};

use crate::vc::requirements::ProofRequirement;

type R1CS = R1CSOrig<Bls12_381>;

pub const LESS_THAN_PUBLIC_ID: &str = "https://zkp-ld.org/circuit/ubique/lessThanPublic";
const LESS_THAN_PUBLIC_R1CS: &[u8] = include_bytes!("../circom/bls12381/less_than_public_64.r1cs");
const LESS_THAN_PUBLIC_WASM: &[u8] = include_bytes!("../circom/bls12381/less_than_public_64.wasm");

pub const GREATER_THAN_PUBLIC_ID: &str = "https://zkp-ld.org/circuit/ubique/greaterThanPublic";
const GREATER_THAN_PUBLIC_R1CS: &[u8] =
    include_bytes!("../circom/bls12381/larger_than_public_64.r1cs");
const GREATER_THAN_PUBLIC_WASM: &[u8] =
    include_bytes!("../circom/bls12381/larger_than_public_64.wasm");

#[derive(Debug, Serialize, Deserialize)]
pub struct Circuits {
    pub verifying_keys: HashMap<String, String>,
    pub proving_keys: HashMap<String, String>,
}

pub fn get_circuit_defs() -> HashMap<String, (&'static [u8], &'static [u8])> {
    HashMap::from([
        (
            LESS_THAN_PUBLIC_ID.to_string(),
            (LESS_THAN_PUBLIC_R1CS, LESS_THAN_PUBLIC_WASM),
        ),
        (
            GREATER_THAN_PUBLIC_ID.to_string(),
            (GREATER_THAN_PUBLIC_R1CS, GREATER_THAN_PUBLIC_WASM),
        ),
    ])
}

pub fn generate_circuits<R: RngCore>(rng: &mut R, reqs: &Vec<ProofRequirement>) -> Circuits {
    let lookup = get_circuit_defs();

    let mut verifying_keys = HashMap::<String, String>::new();
    let mut proving_keys = HashMap::<String, String>::new();

    for req in reqs {
        if let ProofRequirement::Circuit { id, .. } = req {
            let (r1cs, _) = lookup.get(id).unwrap();
            let r1cs: R1CS = R1CSFile::new(Cursor::new(r1cs)).unwrap().into();

            let commit_witness_count = 1;
            let snark_proving_key = CircomCircuit::setup(r1cs)
                .generate_proving_key(commit_witness_count, rng)
                .unwrap();

            // serialize to multibase
            let snark_proving_key_string = ark_to_base64url(&snark_proving_key).unwrap();
            let snark_verifying_key_string = ark_to_base64url(&snark_proving_key.vk).unwrap();

            verifying_keys.insert(id.clone(), snark_verifying_key_string);
            proving_keys.insert(id.clone(), snark_proving_key_string);
        }
    }

    Circuits {
        verifying_keys,
        proving_keys,
    }
}

pub fn load_circuits(keys: &HashMap<String, String>) -> HashMap<NamedNode, Circuit> {
    type R1CS = R1CSOrig<Bls12_381>;

    let lookup = get_circuit_defs();
    let mut circuits = HashMap::<NamedNode, Circuit>::new();

    for (id, key) in keys {
        let (r1cs, wasm) = lookup.get(id).unwrap();
        let r1cs: R1CS = R1CSFile::new(Cursor::new(r1cs)).unwrap().into();

        let wasm = multibase::encode(Base::Base64Url, wasm);
        let r1cs = ark_to_base64url(&r1cs).unwrap();

        let circuit = Circuit::new(&r1cs, &wasm, key).unwrap();

        circuits.insert(NamedNode::new_unchecked(id.clone()), circuit);
    }

    circuits
}
