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
use equality_across_groups::ec::commitments::from_base_field_to_scalar_field;
use kvac::bbs_sharp::ecdsa;
use rdf_util::oxrdf::vocab::xsd;
use rdf_util::{ObjectId, Value as RdfValue};
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};
use zkp_util::device_binding::limbs_from_public_key;
use zkp_util::{
    device_binding::{BlsFr, SecpFr},
    vc::{
        issuance::issue,
        presentation::present_two,
        requirements::{
            DeviceBindingRequirement, DeviceBindingVerificationParams, DiscloseRequirement,
            EqualClaimsRequirement, ProofRequirement,
        },
        verification::verify,
    },
    SECP_GEN,
};

const ISSUER_ID: &str = "did:example:issuer0";
const ISSUER_KEY_ID: &str = "did:example:issuer0#key01";
const ISSUER_SK: &str = "z489BikWV616m6F5ayUNDnLxWpHVmw3tG6hSgCVE9ZxDEXz3";
const ISSUER_PK: &str = "zUC77roR12AzeB1bjwU6eK86NBBpJf5Rxvyqh8QcaEK6BxRTDoQucp2DSARoAABMWchDk4zxXmwfpHUeaWBg7T4q3Pne9YfnZBhStoGBmCzQcdj8pY3joRbr37w4TMcU1Pipqdp";

/// The goal of this test is to demonstrate the following scenario:
///
/// An identity holder has two VCs:
/// 1. A VC containing their idenity information (name, birthdate, etc.)
/// 2. A VC containing a diploma with their gpa
///
/// The identity holder wants to disclose their gpa and prove that the
/// identity information indeed belongs to them (device binding).
///
/// This is done by disclosing the gpa from the diploma VC and proving
/// equality of the name and birthdate attributes from the identity VC
/// without disclosing them.
#[test]
fn claim_based() {
    let mut rng = rand_core::OsRng;

    let secret_key = SecpFr::rand(&mut rng);
    let public_key = (SECP_GEN * secret_key).into_affine();

    let db = {
        let x_bytes = public_key.x.into_bigint().to_bytes_be();
        let y_bytes = public_key.y.into_bigint().to_bytes_be();

        let x_encoded = BASE64_STANDARD.encode(x_bytes);
        let y_encoded = BASE64_STANDARD.encode(y_bytes);
        let (x_1, x_2) = limbs_from_public_key(&x_encoded);

        (x_encoded, y_encoded, x_1, x_2)
    };

    // This is done on the issuer side
    let identity_vc = {
        let claims = RdfValue::Object(
            BTreeMap::from([
                (
                    "https://schema.org/givenName".into(),
                    RdfValue::String("John".into()),
                ),
                (
                    "https://schema.org/familyName".into(),
                    RdfValue::String("Doe".into()),
                ),
                (
                    "https://schema.org/birthDate".into(),
                    RdfValue::Typed(
                        "1990-01-01T00:00:00Z".into(),
                        "http://www.w3.org/2001/XMLSchema#dateTime".into(),
                    ),
                ),
                (
                    "https://schema.org/telephone".into(),
                    RdfValue::String("+1 634 535 1587".into()),
                ),
            ]),
            ObjectId::None,
        );

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
        vc
    };

    // This is done on the issuer side
    let diploma_vc = {
        let claims = RdfValue::Object(
            BTreeMap::from([
                (
                    "https://schema.org/firstName".into(),
                    RdfValue::String("John".into()),
                ),
                (
                    "https://schema.org/familyName".into(),
                    RdfValue::String("Doe".into()),
                ),
                (
                    "https://schema.org/birthDate".into(),
                    RdfValue::Typed(
                        "1990-01-01T00:00:00Z".into(),
                        "http://www.w3.org/2001/XMLSchema#dateTime".into(),
                    ),
                ),
                (
                    "https://example.org/gpaScore".into(),
                    RdfValue::Typed("5.5".into(), xsd::DECIMAL.as_str().into()),
                ),
            ]),
            ObjectId::None,
        );

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
            None,
            None,
        )
        .unwrap();

        // println!("issuance done! {vc}");
        vc
    };

    // The verifier generates the requirements and the circuits
    let equal_claim_reqs = vec![
        EqualClaimsRequirement {
            key1: "https://schema.org/givenName".into(),
            key2: "https://schema.org/firstName".into(),
        },
        EqualClaimsRequirement {
            key1: "https://schema.org/familyName".into(),
            key2: "https://schema.org/familyName".into(),
        },
        EqualClaimsRequirement {
            key1: "https://schema.org/birthDate".into(),
            key2: "https://schema.org/birthDate".into(),
        },
    ];
    let mut requirements = vec![ProofRequirement::Required(DiscloseRequirement {
        key: "https://example.org/gpaScore".into(),
    })];
    requirements.extend(
        equal_claim_reqs
            .iter()
            .cloned()
            .map(ProofRequirement::EqualClaims),
    );

    let message = SecpFr::rand(&mut rng);
    let message_signature = ecdsa::Signature::new_prehashed(&mut rng, message, secret_key);

    let db_req = DeviceBindingRequirement {
        public_key,
        message,
        message_signature,
        comm_key_secp_label: b"comm-key-secp".to_vec(),
        comm_key_tom_label: b"comm-key-tom".to_vec(),
        comm_key_bls_label: b"comm-key-bls".to_vec(),
        bpp_setup_label: b"bpp-setup".to_vec(),
    };

    let vp = present_two(
        &mut rng,
        identity_vc,
        &Vec::new(),
        Some(db_req),
        diploma_vc,
        &vec![DiscloseRequirement {
            key: "https://example.org/gpaScore".into(),
        }],
        &equal_claim_reqs,
        ISSUER_PK,
        ISSUER_ID,
        ISSUER_KEY_ID,
    )
    .unwrap();

    let db_verify_params = DeviceBindingVerificationParams {
        message,
        comm_key_secp_label: b"comm-key-secp".to_vec(),
        comm_key_tom_label: b"comm-key-tom".to_vec(),
        comm_key_bls_label: b"comm-key-bls".to_vec(),
        bpp_setup_label: b"bpp-setup".to_vec(),
    };

    let body = verify(
        &mut rng,
        vp,
        &requirements,
        Some(db_verify_params),
        &HashMap::new(),
        ISSUER_PK,
        ISSUER_ID,
        ISSUER_KEY_ID,
        2,
    )
    .unwrap();

    println!("{body:#}")
}
