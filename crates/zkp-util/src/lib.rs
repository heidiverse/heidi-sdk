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

use ark_bls12_381::{Bls12_381, G1Affine as BlsG1Affine};
use ark_secp256r1::{Affine as SecpAffine, G_GENERATOR_X, G_GENERATOR_Y};
use bbs_plus::prelude::{KeypairG1, SignatureG1};
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use equality_across_groups::{
    eq_across_groups::ProofLargeWitness as ProofLargeWitnessOrig, tom256::Affine as Tom256Affine,
};

pub mod circuits;
pub mod constants;
pub mod device_binding;
pub mod keypair;
pub mod vc;

pub use ecdsa_pops;
pub use rok;

pub const SECP_GEN: SecpAffine = SecpAffine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

const WITNESS_BIT_SIZE: usize = 64;
const CHALLENGE_BIT_SIZE: usize = 180;
const ABORT_PARAM: usize = 8;
const RESPONSE_BYTE_SIZE: usize = 32;
const NUM_REPS: usize = 1;
const NUM_CHUNKS: usize = 4;

pub type PedersenCommitmentKeySecp = PedersenCommitmentKey<SecpAffine>;
pub type PedersenCommitmentKeyTom = PedersenCommitmentKey<Tom256Affine>;
pub type PedersenCommitmentKeyBls = PedersenCommitmentKey<BlsG1Affine>;

pub type EcdsaSignature = kvac::bbs_sharp::ecdsa::Signature;

pub type ProofLargeWitness = ProofLargeWitnessOrig<
    Tom256Affine,
    BlsG1Affine,
    NUM_CHUNKS,
    WITNESS_BIT_SIZE,
    CHALLENGE_BIT_SIZE,
    ABORT_PARAM,
    RESPONSE_BYTE_SIZE,
    NUM_REPS,
>;

pub type BBSKeypair = KeypairG1<Bls12_381>;
pub type BBSSignature = SignatureG1<Bls12_381>;
