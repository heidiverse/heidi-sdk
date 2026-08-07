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

use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::time::Instant;

use anyhow::{anyhow, Context};
use ark_bls12_381::G1Affine as BlsG1Affine;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use ark_secp256r1::Fq;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use base64::Engine;
use blake2::Blake2b512;
use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use dock_crypto_utils::{
    randomized_mult_checker::RandomizedMultChecker,
    transcript::{new_merlin_transcript, Transcript},
};
use ecdsa_pops::halo2curves::ff::derive::byteorder::{
    self, BigEndian, ReadBytesExt, WriteBytesExt,
};
use ecdsa_pops::halo2curves::secp256r1::Secp256r1Affine;
use ecdsa_pops::utils::ecdsa::{ECDSASignature, ECDSA};
use ecdsa_pops::utils::{arkfp_to_fp, arkfq_to_fq, arkp256_to_p256, fp_to_scalars};
use ecdsa_pops::{
    bincode, G1Affine, PoPNativeComposedRoK, PoPNativeNizk, RelECDSA, RelECDSAParams,
    RelECDSAStatement, RelECDSAWitness,
};
use equality_across_groups::{
    ec::commitments::{
        from_base_field_to_scalar_field, PointCommitment, PointCommitmentWithOpening,
    },
    pok_ecdsa_pubkey::{
        PoKEcdsaSigCommittedPublicKey, PoKEcdsaSigCommittedPublicKeyProtocol, TransformedEcdsaSig,
    },
};
use equality_across_groups::{
    eq_across_groups::ProofLargeWitness as ProofLargeWitnessOrig, tom256::Affine as Tom256Affine,
};

use ecdsa_pops::halo2curves::ff::{Field, PrimeField};
use kvac::bbs_sharp::ecdsa;
use num_bigint::BigUint;
use rand_core::{OsRng, RngCore};
use rok::{Nizk, Relation, RoK};

const WITNESS_BIT_SIZE: usize = 64;
const CHALLENGE_BIT_SIZE: usize = 180;
const ABORT_PARAM: usize = 8;
const RESPONSE_BYTE_SIZE: usize = 32;
const NUM_REPS: usize = 1;
const NUM_CHUNKS: usize = 4;

pub const DEVICE_BINDING_KEY: &str = "https://zkp-ld.org/deviceBinding";
pub const DEVICE_BINDING_KEY_X: &str = "https://zkp-ld.org/deviceBinding#x";
pub const DEVICE_BINDING_KEY_Y: &str = "https://zkp-ld.org/deviceBinding#y";
pub const DEVICE_BINDING_KEY_X_1: &str = "https://zkp-ld.org/deviceBinding#x1";
pub const DEVICE_BINDING_KEY_X_2: &str = "https://zkp-ld.org/deviceBinding#x2";

pub type SecpFr = ark_secp256r1::Fr;
pub type SecpFq = ark_secp256r1::Fq;
pub type SecpAffine = ark_secp256r1::Affine;
pub type BlsFr = ark_bls12_381::Fr;

type PedersenCommitmentKeySecp = PedersenCommitmentKey<SecpAffine>;
type PedersenCommitmentKeyTom = PedersenCommitmentKey<Tom256Affine>;
type PedersenCommitmentKeyBls = PedersenCommitmentKey<BlsG1Affine>;
type ProofLargeWitness = ProofLargeWitnessOrig<
    Tom256Affine,
    BlsG1Affine,
    NUM_CHUNKS,
    WITNESS_BIT_SIZE,
    CHALLENGE_BIT_SIZE,
    ABORT_PARAM,
    RESPONSE_BYTE_SIZE,
    NUM_REPS,
>;

#[derive(Debug, Clone)]
pub struct DeviceBindingSigma {
    pub proof: PoKEcdsaSigCommittedPublicKey,
    pub eq_x: ProofLargeWitness,
    pub eq_y: ProofLargeWitness,

    pub comm_pk: PointCommitment<Tom256Affine>,

    pub bls_comm_key: Vec<BlsG1Affine>,
    pub bls_comm_pk_x: BlsG1Affine,
    pub bls_comm_pk_y: BlsG1Affine,

    pub bls_scalars_x: Vec<BlsFr>,
    pub bls_scalars_y: Vec<BlsFr>,
}

#[allow(nonstandard_style)]
pub struct DeviceBindingNative {
    pub proof: <PoPNativeComposedRoK as RoK>::Proof,
    pub params: PoPNativeNizk,

    pub bls_comm_pk_x1: ecdsa_pops::G1Affine,
    pub bls_comm_pk_x2: ecdsa_pops::G1Affine,

    pub bls_scalar_x1: ecdsa_pops::halo2curves::bls12381::Fr,
    pub bls_scalar_x2: ecdsa_pops::halo2curves::bls12381::Fr,
    pub bls_scalar_x1_blinding: ecdsa_pops::halo2curves::bls12381::Fr,
    pub bls_scalar_x2_blinding: ecdsa_pops::halo2curves::bls12381::Fr,

    pub K: Secp256r1Affine,
}
impl std::fmt::Debug for DeviceBindingNative {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceBindingNative")
    }
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DeviceBindingPresentationSigma {
    pub proof: PoKEcdsaSigCommittedPublicKey,
    pub eq_x: ProofLargeWitness,
    pub eq_y: ProofLargeWitness,

    pub comm_pk: PointCommitment<Tom256Affine>,

    pub bls_comm_key: Vec<BlsG1Affine>,
    pub bls_comm_pk_x: BlsG1Affine,
    pub bls_comm_pk_y: BlsG1Affine,
}

#[derive(Clone)]
#[allow(nonstandard_style)]
pub struct DeviceBindingPresentationNative {
    pub proof: <PoPNativeComposedRoK as RoK>::Proof,
    pub params: PoPNativeNizk,
    pub bls_comm_pk_x1: BlsG1Affine,
    pub bls_comm_pk_x2: BlsG1Affine,
    pub K: Secp256r1Affine,
}

impl DeviceBindingPresentationNative {
    pub fn serialize(&self) -> Vec<u8> {
        let bytes = vec![];
        let mut w = BufWriter::new(bytes);
        let p = bincode::serialize(&self.proof).unwrap();
        w.write_u64::<byteorder::BigEndian>(p.len() as u64).unwrap();
        w.write_all(&p).unwrap();
        let p = bincode::serialize(&self.params).unwrap();
        w.write_u64::<byteorder::BigEndian>(p.len() as u64).unwrap();
        w.write_all(&p).unwrap();
        let compressed_size = self.bls_comm_pk_x1.compressed_size();
        w.write_u64::<byteorder::BigEndian>(compressed_size as u64)
            .unwrap();
        self.bls_comm_pk_x1.serialize_compressed(&mut w).unwrap();
        let compressed_size = self.bls_comm_pk_x2.compressed_size();
        w.write_u64::<byteorder::BigEndian>(compressed_size as u64)
            .unwrap();
        self.bls_comm_pk_x2.serialize_compressed(&mut w).unwrap();

        let k_bytes = bincode::serialize(&self.K).unwrap();
        w.write_u64::<byteorder::BigEndian>(k_bytes.len() as u64)
            .unwrap();
        w.write_all(&k_bytes).unwrap();
        w.into_inner().unwrap()
    }

    #[allow(nonstandard_style)]
    pub fn deserialize<T: Read + Seek>(bytes: T) -> Self {
        let mut reader = BufReader::new(bytes);

        let len_proof = reader.read_u64::<BigEndian>().unwrap();
        let mut proof_bytes = vec![0; len_proof as usize];
        reader.read_exact(&mut proof_bytes).unwrap();
        let proof = bincode::deserialize(&proof_bytes).unwrap();

        let len_params = reader.read_u64::<BigEndian>().unwrap();
        let mut params_bytes = vec![0; len_params as usize];
        reader.read_exact(&mut params_bytes).unwrap();
        let params = bincode::deserialize(&params_bytes).unwrap();

        let len_x1 = reader.read_u64::<BigEndian>().unwrap();
        let mut x1_bytes = vec![0; len_x1 as usize];
        reader.read_exact(&mut x1_bytes).unwrap();

        let len_x2 = reader.read_u64::<BigEndian>().unwrap();
        let mut x2_bytes = vec![0; len_x2 as usize];
        reader.read_exact(&mut x2_bytes).unwrap();
        let x1 = BlsG1Affine::deserialize_compressed(&x1_bytes[..]).unwrap();

        let x2 = BlsG1Affine::deserialize_compressed(&x2_bytes[..]).unwrap();

        let len_K = reader.read_u64::<BigEndian>().unwrap();
        let mut k_bytes = vec![0; len_K as usize];
        reader.read_exact(&mut k_bytes).unwrap();
        let K = bincode::deserialize(&k_bytes).unwrap();

        Self {
            proof,
            params,
            bls_comm_pk_x1: x1,
            bls_comm_pk_x2: x2,
            K,
        }
    }

    pub fn verify(&self, label: &'static [u8], message: SecpFr) -> anyhow::Result<()> {
        let mut transcript_verifier = ecdsa_pops::merlin::Transcript::new(label);
        let x = RelECDSAStatement::new(
            [
                from_arkg1_to_g1(&self.bls_comm_pk_x1),
                from_arkg1_to_g1(&self.bls_comm_pk_x2),
            ],
            None,
            arkfq_to_fq(&message).unwrap(),
            self.K,
        );
        let ecdsa = ECDSA {
            pp: Secp256r1Affine::generator(),
        };
        let nizk = self.params.clone();
        let gs = [*nizk.ck_bls(), *nizk.ck_bls()];
        let h = nizk.ck_bls_blinding();
        let pp = RelECDSAParams::<G1Affine, 2>::new(gs, *h, ecdsa);
        let r_verifier = RelECDSA::new(pp, x, None);
        let _ = self
            .params
            .verify(&mut transcript_verifier, &r_verifier, &self.proof)
            .unwrap();
        Ok(())
    }
}

pub fn from_ark_point_to_halo_point(p: &SecpAffine) -> Secp256r1Affine {
    arkp256_to_p256(p).unwrap()
}

use ark_bls12_381::Fq as BlsFq;

pub fn from_g1_to_arkg1(g: &ecdsa_pops::G1Affine) -> BlsG1Affine {
    let x_rep = g.x.to_repr();
    let y_rep = g.y.to_repr();
    let x = x_rep.as_ref();
    let y = y_rep.as_ref();
    let x = <BlsFq as ArkPrimeField>::from_le_bytes_mod_order(&x);
    let y = <BlsFq as ArkPrimeField>::from_le_bytes_mod_order(&y);
    BlsG1Affine::new(x, y)
}
pub fn from_arkg1_to_g1(g: &BlsG1Affine) -> ecdsa_pops::G1Affine {
    let x: BigUint = g.x.clone().into();
    let y: BigUint = g.y.clone().into();
    let xbs = x.to_bytes_le();
    let ybs = y.to_bytes_le();
    let mut xbytes = [0u8; 48];
    let mut ybytes = [0u8; 48];
    xbytes[..xbs.len()].copy_from_slice(&xbs);
    ybytes[..ybs.len()].copy_from_slice(&ybs);

    ecdsa_pops::G1Affine {
        x: ecdsa_pops::halo2curves::bls12381::Fq::from_repr(xbytes.into()).unwrap(),
        y: ecdsa_pops::halo2curves::bls12381::Fq::from_repr(ybytes.into()).unwrap(),
    }
}
pub fn from_blsfr_to_arkblsfr(a: &ecdsa_pops::halo2curves::bls12381::Fr) -> BlsFr {
    let a = a.to_repr();
    let aref = a.as_ref();
    <BlsFr as ArkPrimeField>::from_le_bytes_mod_order(aref)
}

impl DeviceBindingNative {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        public_key: SecpAffine,
        message: SecpFr,
        message_signature: ecdsa::Signature,
        label: &str,
        setup: Option<PoPNativeNizk>,
    ) -> anyhow::Result<Self> {
        let start = Instant::now();
        let nizk = if let Some(setup) = setup {
            setup
        } else {
            PoPNativeNizk::new(label)
        };
        let end = Instant::now();
        println!("elapsed [conversion]: {}", (end - start).as_millis());
        let ecdsa = ECDSA {
            pp: Secp256r1Affine::generator(),
        };
        let gs = [*nizk.ck_bls(), *nizk.ck_bls()];
        let h = nizk.ck_bls_blinding();

        let pp = RelECDSAParams::<G1Affine, 2>::new(gs, *h, ecdsa);

        let pk = arkp256_to_p256(&public_key).unwrap();
        println!("successfully converted point");

        let m = arkfq_to_fq(&message).unwrap();
        let sigma = ECDSASignature {
            Rx: arkfq_to_fq(&message_signature.rand_x_coord).unwrap(),
            response: arkfq_to_fq(&message_signature.response).unwrap(),
        };

        let start = Instant::now();

        let sigma_converted = ecdsa.convert(&pk, &m, &sigma);
        // sample randomness for the commitments
        let rho: [ecdsa_pops::halo2curves::bls12381::Fr; 2] = (0..2)
            .map(|_| <ecdsa_pops::halo2curves::bls12381::Fr>::random(OsRng))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        println!("everything ready start proofs");
        // create witness
        let w = RelECDSAWitness::new(pk, sigma_converted.z, rho, None);
        println!("witness ready");
        // create the commitment to the public key
        let coms = (0..2)
            .map(|i| {
                RelECDSA::<G1Affine, 2>::create_commitment(&pp, &w, i)
                    .unwrap()
                    .0
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        println!("commitments done");
        let x = RelECDSAStatement::new(coms, None, m, sigma_converted.K);

        let limbs = fp_to_scalars::<ecdsa_pops::G1Affine, 2>(&w.q().x).unwrap();

        let r_prover = RelECDSA::new(pp, x, Some(w));
        println!("elapsed [setup]: {}", (end - start).as_millis());
        let mut transcript_prover = ecdsa_pops::merlin::Transcript::new(b"pop native proof");
        println!("start proof");
        let start = Instant::now();
        let proof = nizk
            .prove(&mut transcript_prover, &r_prover, &mut OsRng)
            .unwrap();
        let end = Instant::now();
        println!("elapsed [actual proof]: {}", (end - start).as_millis());
        println!("proof finished");
        Ok(Self {
            proof: proof,
            params: nizk,
            bls_comm_pk_x1: coms[0],
            bls_comm_pk_x2: coms[1],
            bls_scalar_x1: limbs[0],
            bls_scalar_x2: limbs[1],
            bls_scalar_x1_blinding: rho[0],
            bls_scalar_x2_blinding: rho[1],
            K: sigma_converted.K,
        })
    }
    pub fn present(&self) -> DeviceBindingPresentationNative {
        DeviceBindingPresentationNative {
            proof: self.proof.clone(),
            params: self.params.clone(),
            bls_comm_pk_x1: from_g1_to_arkg1(&self.bls_comm_pk_x1),
            bls_comm_pk_x2: from_g1_to_arkg1(&self.bls_comm_pk_x2),
            K: self.K.clone(),
        }
    }
}

impl DeviceBindingSigma {
    #[allow(clippy::too_many_arguments)]
    pub fn new<R: RngCore>(
        rng: &mut R,
        public_key: SecpAffine,
        message: SecpFr,
        message_signature: ecdsa::Signature,
        comm_key_secp_label: &[u8],
        comm_key_tom_label: &[u8],
        comm_key_bls_label: &[u8],
        bpp_setup_label: &[u8],
        merlin_transcript_label: &'static [u8],
        challenge_label: &'static [u8],
    ) -> anyhow::Result<Self> {
        let comm_key_secp = PedersenCommitmentKeySecp::new::<Blake2b512>(comm_key_secp_label);
        let comm_key_tom = PedersenCommitmentKeyTom::new::<Blake2b512>(comm_key_tom_label);
        let comm_key_bls = PedersenCommitmentKeyBls::new::<Blake2b512>(comm_key_bls_label);

        let bls_comm_key = vec![comm_key_bls.g, comm_key_bls.h];

        let base = 2;
        let mut bpp_setup_params =
            BppSetupParams::<Tom256Affine>::new_for_perfect_range_proof::<Blake2b512>(
                bpp_setup_label,
                base,
                WITNESS_BIT_SIZE as u16,
                NUM_CHUNKS as u32,
            );
        bpp_setup_params.G = comm_key_tom.g;
        bpp_setup_params.H_vec[0] = comm_key_tom.h;

        // Commit to ECDSA public key on Tom-256 curve
        let comm_pk = PointCommitmentWithOpening::new(rng, &public_key, &comm_key_tom)
            .map_err(|e| anyhow!("Failed to create PointCommitmentWithOpening: {e:?}"))?;

        // Commit to ECDSA public key on BLS12-381 curve
        let pk_x = from_base_field_to_scalar_field::<Fq, BlsFr>(
            public_key
                .x()
                .context("Failed to get public_key x coordinate!")?,
        );
        let pk_y = from_base_field_to_scalar_field::<Fq, BlsFr>(
            public_key
                .y()
                .context("Failed to get public_key y coordinate!")?,
        );

        let bls_comm_pk_rx = BlsFr::rand(rng);
        let bls_comm_pk_ry = BlsFr::rand(rng);
        let bls_comm_pk_x = comm_key_bls.commit(&pk_x, &bls_comm_pk_rx);
        let bls_comm_pk_y = comm_key_bls.commit(&pk_y, &bls_comm_pk_ry);
        let bls_scalars_x = vec![pk_x, bls_comm_pk_rx];
        let bls_scalars_y = vec![pk_y, bls_comm_pk_ry];

        let transformed_sig =
            TransformedEcdsaSig::new(&message_signature, message, public_key).unwrap();
        transformed_sig
            .verify_prehashed(message, public_key)
            .unwrap();

        let mut prover_transcript = new_merlin_transcript(merlin_transcript_label);
        prover_transcript.append(b"comm_key_secp", &comm_key_secp);
        prover_transcript.append(b"comm_key_tom", &comm_key_tom);
        prover_transcript.append(b"comm_key_bls", &comm_key_bls);
        prover_transcript.append(b"bpp_setup_params", &bpp_setup_params);
        prover_transcript.append(b"comm_pk", &comm_pk.comm);
        prover_transcript.append(b"bls_comm_pk_x", &bls_comm_pk_x);
        prover_transcript.append(b"bls_comm_pk_y", &bls_comm_pk_y);
        prover_transcript.append(b"message", &message);

        let protocol = PoKEcdsaSigCommittedPublicKeyProtocol::<128>::init(
            rng,
            transformed_sig,
            message,
            public_key,
            comm_pk.clone(),
            &comm_key_secp,
            &comm_key_tom,
        )
        .map_err(|e| anyhow!("Failed to create the protocol: {e:?}"))?;
        protocol
            .challenge_contribution(&mut prover_transcript)
            .map_err(|e| anyhow!("Failed to challenge contribution of the protocol: {e:?}"))?;
        let challenge_prover = prover_transcript.challenge_scalar(challenge_label);
        let proof = protocol.gen_proof(&challenge_prover);

        // Proof that x coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_x = ProofLargeWitness::new(
            rng,
            &comm_pk.x,
            comm_pk.r_x,
            bls_comm_pk_rx,
            &comm_key_tom,
            &comm_key_bls,
            base,
            bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .map_err(|e| anyhow!("Failed to create proof_eq_pk_x: {e:?}"))?;

        // Proof that y coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_y = ProofLargeWitness::new(
            rng,
            &comm_pk.y,
            comm_pk.r_y,
            bls_comm_pk_ry,
            &comm_key_tom,
            &comm_key_bls,
            base,
            bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .map_err(|e| anyhow!("Failed to create proof_eq_pk_x: {e:?}"))?;

        Ok(Self {
            proof,
            eq_x: proof_eq_pk_x,
            eq_y: proof_eq_pk_y,
            comm_pk: comm_pk.comm,
            bls_comm_key,
            bls_comm_pk_x,
            bls_comm_pk_y,
            bls_scalars_x,
            bls_scalars_y,
        })
    }

    pub fn present(self) -> DeviceBindingPresentationSigma {
        DeviceBindingPresentationSigma {
            proof: self.proof,
            eq_x: self.eq_x,
            eq_y: self.eq_y,
            comm_pk: self.comm_pk,
            bls_comm_key: self.bls_comm_key,
            bls_comm_pk_x: self.bls_comm_pk_x,
            bls_comm_pk_y: self.bls_comm_pk_y,
        }
    }
}

impl DeviceBindingPresentationSigma {
    #[allow(clippy::too_many_arguments)]
    pub fn verify<R: RngCore>(
        &self,
        rng: &mut R,
        message: SecpFr,
        comm_key_secp_label: &[u8],
        comm_key_tom_label: &[u8],
        comm_key_bls_label: &[u8],
        bpp_setup_label: &[u8],
        merlin_transcript_label: &'static [u8],
        challenge_label: &'static [u8],
    ) -> anyhow::Result<()> {
        let comm_key_secp = PedersenCommitmentKeySecp::new::<Blake2b512>(comm_key_secp_label);
        let comm_key_tom = PedersenCommitmentKeyTom::new::<Blake2b512>(comm_key_tom_label);
        let comm_key_bls = PedersenCommitmentKeyBls::new::<Blake2b512>(comm_key_bls_label);

        let base = 2;
        let mut bpp_setup_params =
            BppSetupParams::<Tom256Affine>::new_for_perfect_range_proof::<Blake2b512>(
                bpp_setup_label,
                base,
                WITNESS_BIT_SIZE as u16,
                NUM_CHUNKS as u32,
            );
        bpp_setup_params.G = comm_key_tom.g;
        bpp_setup_params.H_vec[0] = comm_key_tom.h;

        let mut verifier_transcript = new_merlin_transcript(merlin_transcript_label);
        verifier_transcript.append(b"comm_key_secp", &comm_key_secp);
        verifier_transcript.append(b"comm_key_tom", &comm_key_tom);
        verifier_transcript.append(b"comm_key_bls", &comm_key_bls);
        verifier_transcript.append(b"bpp_setup_params", &bpp_setup_params);
        verifier_transcript.append(b"comm_pk", &self.comm_pk);
        verifier_transcript.append(b"bls_comm_pk_x", &self.bls_comm_pk_x);
        verifier_transcript.append(b"bls_comm_pk_y", &self.bls_comm_pk_y);
        verifier_transcript.append(b"message", &message);
        self.proof
            .challenge_contribution(&mut verifier_transcript)
            .map_err(|e| anyhow!("Failed to challenge contribution: {e:?}"))?;

        let challenge_verifier = verifier_transcript.challenge_scalar(challenge_label);

        self.proof
            .verify_using_randomized_mult_checker(
                message,
                self.comm_pk,
                &challenge_verifier,
                comm_key_secp,
                comm_key_tom,
                &mut RandomizedMultChecker::<SecpAffine>::new_using_rng(rng),
                &mut RandomizedMultChecker::<Tom256Affine>::new_using_rng(rng),
            )
            .map_err(|e| anyhow!("Failed to verify proof: {e:?}"))?;

        self.eq_x
            .verify(
                &self.comm_pk.x,
                &self.bls_comm_pk_x,
                &comm_key_tom,
                &comm_key_bls,
                &bpp_setup_params,
                &mut verifier_transcript,
            )
            .map_err(|e| anyhow!("Failed to verify eq_x: {e:?}"))?;

        self.eq_y
            .verify(
                &self.comm_pk.y,
                &self.bls_comm_pk_y,
                &comm_key_tom,
                &comm_key_bls,
                &bpp_setup_params,
                &mut verifier_transcript,
            )
            .map_err(|e| anyhow!("Failed to verify eq_y: {e:?}"))?;

        Ok(())
    }
}

pub fn change_field(p: &SecpFq) -> BlsFr {
    from_base_field_to_scalar_field::<Fq, BlsFr>(p)
}
pub fn limbs_from_public_key(x: &str) -> (String, String) {
    use base64::prelude::BASE64_STANDARD;
    let x = BASE64_STANDARD.decode(x).unwrap();
    let x = SecpFq::from(BigUint::from_bytes_be(&x));
    let limbs = fp_to_scalars::<ecdsa_pops::G1Affine, 2>(&arkfp_to_fp(&x).unwrap()).unwrap();
    let x: BlsFr = from_blsfr_to_arkblsfr(&limbs[0]);
    let y: BlsFr = from_blsfr_to_arkblsfr(&limbs[1]);

    let x_bytes = x.into_bigint().to_bytes_be();
    let y_bytes = y.into_bigint().to_bytes_be();

    (
        BASE64_STANDARD.encode(x_bytes),
        BASE64_STANDARD.encode(y_bytes),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    pub fn test_device_binding() {
        use std::io::Cursor;

        use ark_ec::CurveGroup;
        use ark_secp256r1::{G_GENERATOR_X, G_GENERATOR_Y};

        const SECP_GEN: SecpAffine = SecpAffine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

        let mut rng = rand_core::OsRng;

        let secret_key = SecpFr::rand(&mut rng);
        let public_key = (SECP_GEN * secret_key).into_affine();

        let message = SecpFr::rand(&mut rng);
        let message_signature = ecdsa::Signature::new_prehashed(&mut rng, message, secret_key);

        let db = DeviceBindingSigma::new(
            &mut rng,
            public_key,
            message,
            message_signature,
            b"comm-key-secp",
            b"comm-key-tom",
            b"comm-key-bls",
            b"bpp-setup",
            b"transcript",
            b"challenge",
        )
        .unwrap();

        let presentation = db.present();

        let mut bytes = Vec::<u8>::new();
        presentation.serialize_compressed(&mut bytes).unwrap();

        println!("{}", bytes.len());

        let presentation =
            DeviceBindingPresentationSigma::deserialize_compressed(Cursor::new(bytes)).unwrap();

        presentation
            .verify(
                &mut rng,
                message,
                b"comm-key-secp",
                b"comm-key-tom",
                b"comm-key-bls",
                b"bpp-setup",
                b"transcript",
                b"challenge",
            )
            .unwrap();
    }

    #[test]
    pub fn test_device_binding_native() {
        use ark_ec::CurveGroup;
        use ark_secp256r1::{G_GENERATOR_X, G_GENERATOR_Y};

        const SECP_GEN: SecpAffine = SecpAffine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

        let mut rng = rand_core::OsRng;

        let secret_key = SecpFr::rand(&mut rng);
        let public_key = (SECP_GEN * secret_key).into_affine();

        let message = SecpFr::rand(&mut rng);
        let message_signature = ecdsa::Signature::new_prehashed(&mut rng, message, secret_key);

        let db = DeviceBindingNative::new(
            public_key,
            message,
            message_signature,
            "comm-key-secp",
            None,
        )
        .unwrap();

        let presentation = db.present();

        let bytes = presentation.serialize();
        println!("{}", bytes.len());
        let proof = DeviceBindingPresentationNative::deserialize(Cursor::new(bytes.clone()));

        proof.verify(b"pop native proof", message).unwrap();

        let mut transcript_verifier = ecdsa_pops::merlin::Transcript::new(b"pop native proof");
        let x = RelECDSAStatement::new(
            [
                from_arkg1_to_g1(&proof.bls_comm_pk_x1),
                from_arkg1_to_g1(&proof.bls_comm_pk_x2),
            ],
            None,
            arkfq_to_fq(&message).unwrap(),
            proof.K,
        );
        let ecdsa = ECDSA {
            pp: Secp256r1Affine::generator(),
        };
        let nizk = proof.params;
        let gs = [*nizk.ck_bls(), *nizk.ck_bls()];
        let h = nizk.ck_bls_blinding();
        let pp = RelECDSAParams::<G1Affine, 2>::new(gs, *h, ecdsa);
        let r_verifier = RelECDSA::new(pp, x, None);
        let _ = nizk
            .verify(&mut transcript_verifier, &r_verifier, &proof.proof)
            .unwrap();
    }
}
