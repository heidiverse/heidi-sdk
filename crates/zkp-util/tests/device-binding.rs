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

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{biginteger::BigInteger, PrimeField};
use ark_secp256r1::Fq;
use ark_std::UniformRand;
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::DateTime;
use ecdsa_pops::utils::{arkfp_to_fp, fp_to_scalars};
use equality_across_groups::ec::commitments::from_base_field_to_scalar_field;
use kvac::bbs_sharp::ecdsa;
use rdf_util::oxrdf::vocab::xsd;
use rdf_util::{ObjectId, Value as RdfValue};
use std::{collections::BTreeMap, str::FromStr, time::Instant};
use zkp_util::device_binding::{from_blsfr_to_arkblsfr, limbs_from_public_key};
use zkp_util::vc::presentation::present_native;
use zkp_util::vc::verification::verify_native;
use zkp_util::{
    circuits,
    device_binding::{BlsFr, SecpFr},
    vc::{
        issuance::issue,
        presentation::present,
        requirements::{
            self, DeviceBindingRequirement, DeviceBindingVerificationParams, DiscloseRequirement,
        },
        verification::verify,
    },
    SECP_GEN,
};

#[test]
fn device_binding_with_both_and_special() {
    const STACK_SIZE: usize = 50 * 1024 * 1024;
    fn run() {
        let mut rng = rand_core::OsRng;

        const ISSUER_ID: &str = "did:example:issuer0";
        const ISSUER_KEY_ID: &str = "did:example:issuer0#key01";
        const ISSUER_SK: &str = "z489BikWV616m6F5ayUNDnLxWpHVmw3tG6hSgCVE9ZxDEXz3";
        const ISSUER_PK: &str = "zUC77roR12AzeB1bjwU6eK86NBBpJf5Rxvyqh8QcaEK6BxRTDoQucp2DSARoAABMWchDk4zxXmwfpHUeaWBg7T4q3Pne9YfnZBhStoGBmCzQcdj8pY3joRbr37w4TMcU1Pipqdp";

        let claims = RdfValue::Object(
            BTreeMap::from([
                (
                    "https://schema.org/name".into(),
                    RdfValue::String("John Doe".into()),
                ),
                (
                    "https://schema.org/telephone".into(),
                    RdfValue::String("+1 634 535 1587".into()),
                ),
                (
                    "https://schema.org/birthDate".into(),
                    RdfValue::Typed(
                        "1990-01-01T00:00:00Z".into(),
                        "http://www.w3.org/2001/XMLSchema#dateTime".into(),
                    ),
                ),
                (
                    "https://example.org/coolness".into(),
                    RdfValue::Typed("10000".into(), xsd::INTEGER.as_str().into()),
                ),
            ]),
            ObjectId::None,
        );

        // Device binding
        let secret_key = SecpFr::rand(&mut rng);
        let public_key = (SECP_GEN * secret_key).into_affine();

        let db = {
            let x_bytes = public_key.x.into_bigint().to_bytes_be();

            let x_encoded = BASE64_STANDARD.encode(x_bytes);
            let y_encoded = BASE64_STANDARD.encode(public_key.y.into_bigint().to_bytes_be());
            let (x_1, x_2) = limbs_from_public_key(&x_encoded);

            (x_encoded, y_encoded, x_1, x_2)
        };

        let message = SecpFr::rand(&mut rng);
        let message_signature = ecdsa::Signature::new_prehashed(&mut rng, message, secret_key);

        let comm_key_secp = b"comm-key-secp";
        let comm_key_tom = b"comm-key-tom";
        let comm_key_bls = b"comm-key-bls";
        let bpp_setup_label = b"bpp-setup";

        let vc = issue(
            &mut rng,
            claims,
            ISSUER_PK,
            ISSUER_SK,
            ISSUER_ID,
            ISSUER_KEY_ID,
            Some(DateTime::from_str("2020-01-01T00:00:00Z").unwrap()),
            Some(DateTime::from_str("2025-01-01T00:00:00Z").unwrap()),
            Some(DateTime::from_str("2030-01-01T00:00:00Z").unwrap()),
            Some(db),
            None,
        )
        .unwrap();

        // println!("issuance done! {vc}");

        let requirements = vec![requirements::ProofRequirement::Required(
            DiscloseRequirement {
                key: "https://schema.org/name".into(),
            },
        )];

        let db_requirement = DeviceBindingRequirement {
            public_key,
            message,
            message_signature,
            comm_key_secp_label: comm_key_secp.to_vec(),
            comm_key_tom_label: comm_key_tom.to_vec(),
            comm_key_bls_label: comm_key_bls.to_vec(),
            bpp_setup_label: bpp_setup_label.to_vec(),
        };

        let circuits = circuits::generate_circuits(&mut rng, &requirements);

        let start = Instant::now();

        let vp = present(
            &mut rng,
            vc,
            &requirements,
            Some(db_requirement),
            &circuits.proving_keys,
            ISSUER_PK,
            ISSUER_ID,
            ISSUER_KEY_ID,
        )
        .unwrap();

        let end = Instant::now();

        println!("elapsed: {}", (end - start).as_millis());

        let db_verification = DeviceBindingVerificationParams {
            message,
            comm_key_secp_label: comm_key_secp.to_vec(),
            comm_key_tom_label: comm_key_tom.to_vec(),
            comm_key_bls_label: comm_key_bls.to_vec(),
            bpp_setup_label: bpp_setup_label.to_vec(),
        };

        // if let Some(db) = vp.device_binding.as_mut() {
        //     db.eq_x = db.eq_y.clone();
        //     db.bls_comm_pk_x = db.bls_comm_pk_y;
        // }

        let start = Instant::now();

        let body = verify(
            &mut rng,
            vp,
            &requirements,
            Some(db_verification),
            &circuits.verifying_keys,
            ISSUER_PK,
            ISSUER_ID,
            ISSUER_KEY_ID,
            1,
        )
        .unwrap();

        let end = Instant::now();

        println!("elapsed (verify): {}", (end - start).as_millis());

        println!("{body:#}")
    }
    let child = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(run)
        .unwrap();
    child.join().unwrap();
}

#[test]
fn device_binding_native_with_special() {
    const STACK_SIZE: usize = 50 * 1024 * 1024;
    fn run() {
        let mut rng = rand_core::OsRng;

        const ISSUER_ID: &str = "did:example:issuer0";
        const ISSUER_KEY_ID: &str = "did:example:issuer0#key01";
        const ISSUER_SK: &str = "z489BikWV616m6F5ayUNDnLxWpHVmw3tG6hSgCVE9ZxDEXz3";
        const ISSUER_PK: &str = "zUC77roR12AzeB1bjwU6eK86NBBpJf5Rxvyqh8QcaEK6BxRTDoQucp2DSARoAABMWchDk4zxXmwfpHUeaWBg7T4q3Pne9YfnZBhStoGBmCzQcdj8pY3joRbr37w4TMcU1Pipqdp";

        let claims = RdfValue::Object(
            BTreeMap::from([
                (
                    "https://schema.org/name".into(),
                    RdfValue::String("John Doe".into()),
                ),
                (
                    "https://schema.org/telephone".into(),
                    RdfValue::String("+1 634 535 1587".into()),
                ),
                (
                    "https://schema.org/birthDate".into(),
                    RdfValue::Typed(
                        "1990-01-01T00:00:00Z".into(),
                        "http://www.w3.org/2001/XMLSchema#dateTime".into(),
                    ),
                ),
                (
                    "https://example.org/coolness".into(),
                    RdfValue::Typed("10000".into(), xsd::INTEGER.as_str().into()),
                ),
            ]),
            ObjectId::None,
        );

        // Device binding
        let secret_key = SecpFr::rand(&mut rng);
        let public_key = (SECP_GEN * secret_key).into_affine();

        let db = {
            println!("before");
            let limbs =
                fp_to_scalars::<ecdsa_pops::G1Affine, 2>(&arkfp_to_fp(&public_key.x).unwrap())
                    .unwrap();
            println!("after");
            let x1: BlsFr = from_blsfr_to_arkblsfr(&limbs[0]);
            println!("after2");
            let x1_bytes = x1.into_bigint().to_bytes_be();
            println!("after3");
            let x2: BlsFr = from_blsfr_to_arkblsfr(&limbs[1]);
            println!("after4");
            let x2_bytes = x2.into_bigint().to_bytes_be();
            println!("after5");

            let x_encoded = BASE64_STANDARD.encode(public_key.x.into_bigint().to_bytes_be());
            println!("after6");
            let y_encoded = BASE64_STANDARD.encode(public_key.y.into_bigint().to_bytes_be());
            println!("after7");

            (
                x_encoded,
                y_encoded,
                BASE64_STANDARD.encode(x1_bytes),
                BASE64_STANDARD.encode(x2_bytes),
            )
        };

        let message = SecpFr::rand(&mut rng);
        let message_signature = ecdsa::Signature::new_prehashed(&mut rng, message, secret_key);

        let comm_key_secp = b"comm-key-secp";
        let comm_key_tom = b"comm-key-tom";
        let comm_key_bls = b"comm-key-bls";
        let bpp_setup_label = b"bpp-setup";

        let vc = issue(
            &mut rng,
            claims,
            ISSUER_PK,
            ISSUER_SK,
            ISSUER_ID,
            ISSUER_KEY_ID,
            Some(DateTime::from_str("2020-01-01T00:00:00Z").unwrap()),
            Some(DateTime::from_str("2025-01-01T00:00:00Z").unwrap()),
            Some(DateTime::from_str("2030-01-01T00:00:00Z").unwrap()),
            Some(db),
            None,
        )
        .unwrap();

        println!("issuance done! {vc}");

        let requirements = vec![requirements::ProofRequirement::Required(
            DiscloseRequirement {
                key: "https://schema.org/name".into(),
            },
        )];

        let db_requirement = DeviceBindingRequirement {
            public_key,
            message,
            message_signature,
            comm_key_secp_label: comm_key_secp.to_vec(),
            comm_key_tom_label: comm_key_tom.to_vec(),
            comm_key_bls_label: comm_key_bls.to_vec(),
            bpp_setup_label: bpp_setup_label.to_vec(),
        };

        let circuits = circuits::generate_circuits(&mut rng, &requirements);

        let start = Instant::now();

        let vp = present_native(
            &mut rng,
            vc,
            &requirements,
            Some(db_requirement),
            &circuits.proving_keys,
            ISSUER_PK,
            ISSUER_ID,
            ISSUER_KEY_ID,
            None,
        )
        .unwrap();

        let end = Instant::now();

        println!("elapsed: {}", (end - start).as_millis());

        let db_verification = DeviceBindingVerificationParams {
            message,
            comm_key_secp_label: comm_key_secp.to_vec(),
            comm_key_tom_label: comm_key_tom.to_vec(),
            comm_key_bls_label: comm_key_bls.to_vec(),
            bpp_setup_label: bpp_setup_label.to_vec(),
        };

        // if let Some(db) = vp.device_binding.as_mut() {
        //     db.eq_x = db.eq_y.clone();
        //     db.bls_comm_pk_x = db.bls_comm_pk_y;
        // }

        let start = Instant::now();

        let body = verify_native(
            &mut rng,
            vp,
            &requirements,
            Some(db_verification),
            &circuits.verifying_keys,
            ISSUER_PK,
            ISSUER_ID,
            ISSUER_KEY_ID,
            1,
        )
        .unwrap();

        let end = Instant::now();

        println!("elapsed (verify): {}", (end - start).as_millis());

        println!("{body:#}")
    }

    let child = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(run)
        .unwrap();
    child.join().unwrap();
}
