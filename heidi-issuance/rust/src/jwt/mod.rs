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

use heidi_crypto_rust::jwt::{DidVerificationDocument, SimpleVerifier};
use heidi_jwt::chrono::{DateTime, Utc};
use heidi_jwt::jwt::verifier_for_jwk;
use heidi_jwt::jwt::{Jwt, JwtVerifier};
use heidi_jwt::models::errors::{JwsError, JwtError};
use heidi_util_rust::{log_error, log_warn};
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;
use std::sync::Arc;

// const PUBLIC_KEY: &str =
//     "BB5YD+gnv9Nt34RiVpy3SC7vN7vhbnYuDAXrIuna1XtjVM1E+9/iPeuv0HLh1OFFKdBUTUOv1nBOO++UDfzGGjY=";

#[derive(uniffi::Object, Clone)]
pub struct StatusListVerifier {
    token: Jwt<StatusListToken>,
    valid_at: Option<heidi_jwt::chrono::DateTime<Utc>>,
}

#[derive(uniffi::Record, Serialize, Deserialize, Clone)]
pub struct StatusListToken {
    pub status_list: StatusList,
    pub sub: String,
    pub ttl: Option<u64>,
}

#[derive(uniffi::Record, Serialize, Deserialize, Clone)]
pub struct StatusList {
    pub bits: u8,
    pub lst: String,
}
#[derive(uniffi::Error, Debug)]
pub enum StatusListError {
    InvalidJwt,
    TypeError,
    Expired,
    InvalidSignature,
}
impl std::fmt::Display for StatusListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatusListError::InvalidJwt => write!(f, "Invalid JWT"),
            StatusListError::TypeError => write!(f, "Type Error"),
            StatusListError::Expired => write!(f, "Expired"),
            StatusListError::InvalidSignature => write!(f, "Invalid Signature"),
        }
    }
}
#[uniffi::export]
impl StatusListVerifier {
    #[uniffi::constructor]
    pub fn new(status_list: &str) -> Result<Arc<Self>, StatusListError> {
        let Ok(token) = Jwt::<StatusListToken>::from_str(status_list) else {
            return Err(StatusListError::InvalidJwt);
        };
        Ok(Arc::new(Self {
            token,
            valid_at: None,
        }))
    }
    pub fn get_payload(&self) -> StatusList {
        self.token
            .payload_unverified()
            .insecure()
            .status_list
            .clone()
    }
    pub fn valid_at(&self, time: i64) -> Result<(), StatusListError> {
        let mut clone = self.clone();
        let time = DateTime::from_timestamp(time, 0).unwrap_or(Utc::now());
        clone.valid_at = Some(time.clone());
        clone.valid()
    }
    pub fn valid_for_did_doc(
        &self,
        did_doc: &DidVerificationDocument,
    ) -> Result<(), StatusListError> {
        let header = match self.token.header() {
            Ok(header) => header,
            Err(_) => return Err(StatusListError::InvalidJwt),
        };
        let Some(kid) = header.claim("kid").and_then(|a| a.as_str()) else {
            log_error!("VALIDATER", "no kid");
            return Err(StatusListError::InvalidJwt);
        };
        log_warn!("VALIDATER", &format!("kid: {}", kid));

        let Some(key) = did_doc.verification_method.iter().find(|vm| vm.id == kid) else {
            log_error!("VALIDATER", "no matching key found");
            return Err(StatusListError::InvalidSignature);
        };

        let Some(jwk) = key.public_key_jwk.transform() else {
            log_error!("VALIDATER", "failed to transform to jwk");
            return Err(StatusListError::InvalidSignature);
        };
        let Some(verifier) = verifier_for_jwk(jwk) else {
            log_error!("VALIDATER", "could not parse jwk into key");
            return Err(StatusListError::InvalidSignature);
        };
        let v: Box<dyn JwtVerifier<StatusListToken>> = Box::new(SimpleVerifier);

        self.token
            .verify_signature_with_verifier(verifier.as_ref())
            .map_err(|_| StatusListError::InvalidSignature)?;
        self.token
            .verify(v.as_ref())
            .map_err(|_| StatusListError::InvalidSignature)
    }
    pub fn valid(&self) -> Result<(), StatusListError> {
        // check if we have a key in the header (e.g. x5c or jwk)
        let _can_header_verify_jwt = match self.token.payload_with_verifier_from_header(self) {
            Ok(_) => return Ok(()),
            Err(JwtError::Jws(JwsError::Expired(_))) => return Err(StatusListError::Expired),
            Err(JwtError::Jws(JwsError::TypeError(_))) => return Err(StatusListError::TypeError),
            _ => false,
        };
        println!("{:?}", self.token.verifier_from_embedded_jwk());
        // check for keys in the jwk
        if let Ok(verifiers) = self.token.verifier_from_embedded_jwk() {
            let h = self
                .jws_header(&self.token)
                .map_err(|_| StatusListError::InvalidJwt)?;
            println!("Verifiers: {:?} [{:?}]", verifiers, h.key_id());
            // only check for keys in the jwk if the header has a key id
            if let Some(key_id) = h.key_id() {
                // check if the header maps to a key in the jwks
                if let Some(key) = verifiers.iter().find(|k| k.0 == key_id) {
                    println!("Found key with ID: {}", key_id);
                    return match self.token.payload_with_verifier(key.1.as_ref(), self) {
                        Ok(_) => Ok(()),
                        Err(JwtError::Jws(JwsError::Expired(_))) => {
                            return Err(StatusListError::Expired)
                        }
                        Err(JwtError::Jws(JwsError::TypeError(_))) => {
                            return Err(StatusListError::TypeError)
                        }
                        _ => Err(StatusListError::InvalidSignature),
                    };
                }
            }
        }

        Err(StatusListError::InvalidSignature)
    }
}

impl JwtVerifier<StatusListToken> for StatusListVerifier {
    /// Allow to check the validity at specific times
    fn verify_time(&self, jwt: &Jwt<StatusListToken>) -> Result<(), JwtError> {
        let time = if let Some(valid_at) = self.valid_at {
            valid_at
        } else {
            Utc::now()
        };
        println!("Verifiying time at: {time}");
        self.verify_time_at(jwt, time)
    }
    fn verify_header(
        &self,
        jwt: &Jwt<StatusListToken>,
    ) -> Result<(), heidi_jwt::models::errors::JwtError> {
        self.assert_type(jwt, "statuslist+jwt")
    }

    fn verify_body(
        &self,
        _jwt: &Jwt<StatusListToken>,
    ) -> Result<(), heidi_jwt::models::errors::JwtError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use heidi_jwt::chrono::DateTime;

    use crate::jwt::StatusListVerifier;

    #[test]
    fn test_status_list() {
        let jwt = StatusListVerifier::new("eyJ4NWMiOlsiTUlJQ2REQ0NBaHVnQXdJQkFnSUJBekFLQmdncWhrak9QUVFEQWpDQmlERUxNQWtHQTFVRUJoTUNSRVV4RHpBTkJnTlZCQWNNQmtKbGNteHBiakVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneEVUQVBCZ05WQkFzTUNGUWdRMU1nU1VSRk1UWXdOQVlEVlFRRERDMVRVRkpKVGtRZ1JuVnVhMlVnUlZWRVNTQlhZV3hzWlhRZ1VISnZkRzkwZVhCbElFbHpjM1ZwYm1jZ1EwRXdIaGNOTWpVd056QXpNVEl5TkRFeFdoY05Nall3T0RBM01USXlOREV4V2pCc01Rc3dDUVlEVlFRR0V3SkVSVEVkTUJzR0ExVUVDZ3dVUW5WdVpHVnpaSEoxWTJ0bGNtVnBJRWR0WWtneENqQUlCZ05WQkFzTUFVa3hNakF3QmdOVkJBTU1LVk5RVWtsT1JDQkdkVzVyWlNCRlZVUkpJRmRoYkd4bGRDQlFjbTkwYjNSNWNHVWdTWE56ZFdWeU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWxCRVBFTW4xR3Q1ektuUkNKQWl6a08rOEtLcVRCK2JsWFZNM1V4MWw3OFBHdURmaXdwS29tUnRPc1E2V1hNL1VjMVp5akg4clBLQTJFL1h3anJGTk02T0JrRENCalRBZEJnTlZIUTRFRmdRVXlNZXBoV0lxSlhWZ245OEJTeGd2Y1JhSXdZTXdEQVlEVlIwVEFRSC9CQUl3QURBT0JnTlZIUThCQWY4RUJBTUNCNEF3TFFZRFZSMFJCQ1l3SklJaVpHVnRieTV3YVdRdGFYTnpkV1Z5TG1KMWJtUmxjMlJ5ZFdOclpYSmxhUzVrWlRBZkJnTlZIU01FR0RBV2dCVFVWaGpBaVRqb0RsaUVHTWwyWXIrcnU4V1F2akFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUJSZUpoS3FTdkg2S0lhZDRzY3g1VGFtTUh3dzBzWWhoUDhjbTZIOGhtaXJRSWdLaEovVHR5L3p5RXQ5MDU1T1BmdWFQQzlzQ3lCVVI3eTZOa3N1R0RPTGk0PSIsIk1JSUNlVENDQWlDZ0F3SUJBZ0lVQjVFOVFWWnRtVVljRHRDaktCL0gzVlF2NzJnd0NnWUlLb1pJemowRUF3SXdnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUI0WERUSTBNRFV6TVRBMk5EZ3dPVm9YRFRNME1EVXlPVEEyTkRnd09Wb3dnWWd4Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSERBWkNaWEpzYVc0eEhUQWJCZ05WQkFvTUZFSjFibVJsYzJSeWRXTnJaWEpsYVNCSGJXSklNUkV3RHdZRFZRUUxEQWhVSUVOVElFbEVSVEUyTURRR0ExVUVBd3d0VTFCU1NVNUVJRVoxYm10bElFVlZSRWtnVjJGc2JHVjBJRkJ5YjNSdmRIbHdaU0JKYzNOMWFXNW5JRU5CTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWUd6ZHdGRG5jNytLbjVpYkF2Q09NOGtlNzdWUXhxZk1jd1pMOElhSUErV0NST2NDZm1ZL2dpSDkycU1ydTVwL2t5T2l2RTBSQy9JYmRNT052RG9VeWFObU1HUXdIUVlEVlIwT0JCWUVGTlJXR01DSk9PZ09XSVFZeVhaaXY2dTd4WkMrTUI4R0ExVWRJd1FZTUJhQUZOUldHTUNKT09nT1dJUVl5WFppdjZ1N3haQytNQklHQTFVZEV3RUIvd1FJTUFZQkFmOENBUUF3RGdZRFZSMFBBUUgvQkFRREFnR0dNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJR0VtN3drWktIdC9hdGI0TWRGblhXNnlybndNVVQydTEzNmdkdGwxMFk2aEFpQnVURnF2Vll0aDFyYnh6Q1AweFdaSG1RSzlrVnl4bjhHUGZYMjdFSXp6c3c9PSJdLCJraWQiOiJNSUdVTUlHT3BJR0xNSUdJTVFzd0NRWURWUVFHRXdKRVJURVBNQTBHQTFVRUJ3d0dRbVZ5YkdsdU1SMHdHd1lEVlFRS0RCUkNkVzVrWlhOa2NuVmphMlZ5WldrZ1IyMWlTREVSTUE4R0ExVUVDd3dJVkNCRFV5QkpSRVV4TmpBMEJnTlZCQU1NTFZOUVVrbE9SQ0JHZFc1clpTQkZWVVJKSUZkaGJHeGxkQ0JRY205MGIzUjVjR1VnU1hOemRXbHVaeUJEUVFJQkF3PT0iLCJ0eXAiOiJzdGF0dXNsaXN0K2p3dCIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJodHRwczovL2RlbW8ucGlkLWlzc3Vlci5idW5kZXNkcnVja2VyZWkuZGUvYzEiLCJzdWIiOiJodHRwczovL2RlbW8ucGlkLWlzc3Vlci5idW5kZXNkcnVja2VyZWkuZGUvc3RhdHVzLzRlZGMwNTE5LWE1NjgtNDMwZC04ZjdmLTk3ZmQ2MDQ5YjI3YyIsImV4cCI6MTc1NDQ4OTQ0NSwiaWF0IjoxNzU0NDg5NDMwLCJ0dGwiOjEwLCJzdGF0dXNfbGlzdCI6eyJiaXRzIjoxLCJsc3QiOiJlTnBqWUVBRkFBQVFBQUUiLCJhZ2dyZWdhdGlvbl91cmkiOiJodHRwczovL2RlbW8ucGlkLWlzc3Vlci5idW5kZXNkcnVja2VyZWkuZGUvc3RhdHVzL2FnZ3JlZ2F0aW9uL2MxIn19.XWG9nKAY7Cx6gqEg1tlFW23bLp3Amm64tevidewXHdPIWvC8zzj3_-pzfZrwiu1bjKGTqtWYX-5P8aqT9h5FVA").unwrap();
        let sixth_of_august_2025 = DateTime::parse_from_rfc3339("2025-08-06T16:10:40+02:00")
            .unwrap()
            .to_utc()
            .timestamp();

        println!("{:?}", jwt.valid_at(sixth_of_august_2025));
        assert!(jwt.valid_at(sixth_of_august_2025).is_ok());
    }
}
