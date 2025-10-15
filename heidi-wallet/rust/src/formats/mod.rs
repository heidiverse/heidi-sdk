/* Copyright 2024 Ubique Innovation AG

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

//! Format agnostic structs for credential handling
use crate::error::{GenericError, InnerError};
use crate::formats::mdoc::{device_signature, helper};
use crate::signing::NativeSigner;
use crate::vc::VerifiableCredential;
use crate::{log::log, ApiError};
use base64::Engine;
use mdoc::helper as mdoc_helper;
use mdoc::helper::CBorHelper;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::UNIX_EPOCH};

pub mod bbs;
pub mod mdoc;
pub mod sdjwt;

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Credential {
    pub credential: CredentialFormat,
}
#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Deferred {
    pub transaction_code: String,
    pub credential_configuration_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CredentialResult {
    CredentialType(Credential),
    DeferredType(Deferred),
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
/// Try getting the mdoc/cbor content as a JSON, to share SD-JWT parsing and deserializing functions
pub fn mdoc_as_json_representation(m: String) -> Option<String> {
    let decoder = if m.contains("=") {
        base64::prelude::BASE64_URL_SAFE
    } else {
        base64::prelude::BASE64_URL_SAFE_NO_PAD
    };
    let Ok(decoded) = decoder.decode(&m) else {
        log(crate::log::LogPriority::ERROR, "MDOC", "invalid encoding");
        return None;
    };
    let Ok(deserialized) = mdoc_helper::deserialize(&decoded) else {
        log(crate::log::LogPriority::ERROR, "MDOC", "no cbor?");
        return None;
    };
    let Ok(namespaces) = deserialized.get("nameSpaces") else {
        return None;
    };
    let Ok(mut json_map) = mdoc::namespaces_to_json_map(&namespaces, false) else {
        log(
            crate::log::LogPriority::ERROR,
            "MDOC",
            "could not map namespaces",
        );
        return None;
    };
    let Ok(valid_until) = mdoc::get_valid_until(&deserialized) else {
        log(
            crate::log::LogPriority::ERROR,
            "MDOC",
            "could not get valid until",
        );
        return None;
    };
    json_map["exp"] = serde_json::Value::Number(
        valid_until
            .duration_since(UNIX_EPOCH)
            .expect("Tachyonic behaviour")
            .as_secs()
            .into(),
    );
    return serde_json::to_string(&json_map).ok();
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
/// Get the issuerAuth value of a mdoc credential
pub fn get_mdoc_issuer_auth(credential: VerifiableCredential) -> Result<Vec<u8>, ApiError> {
    let payload = credential.payload;
    let decoder = if payload.contains("=") {
        base64::prelude::BASE64_URL_SAFE
    } else {
        base64::prelude::BASE64_URL_SAFE_NO_PAD
    };
    let decoded = match decoder.decode(&payload) {
        Ok(decoded) => decoded,
        Err(e) => {
            log(crate::log::LogPriority::ERROR, "MDOC", "invalid encoding");
            return Err(ApiError::Generic(GenericError::Parse {
                reason: "Failed to decode credential payload".to_string(),
                error: InnerError::Anyhow(anyhow::anyhow!(e)),
            }));
        }
    };
    let deserialized = match mdoc_helper::deserialize(&decoded) {
        Ok(deserialized) => deserialized,
        Err(e) => {
            log(crate::log::LogPriority::ERROR, "MDOC", "no cbor?");
            return Err(ApiError::Generic(GenericError::Parse {
                reason: "Failed to deserialize decoded credential".to_string(),
                error: InnerError::Anyhow(anyhow::anyhow!(e)),
            }));
        }
    };

    let issuer_auth_bytes = mdoc_helper::serialize(deserialized.clone().get("issuerAuth")?)?;
    Ok(issuer_auth_bytes)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
/// Get the device signature
pub fn get_device_signature(
    signer: Arc<dyn NativeSigner>,
    doc_type: String,
    transcript: &[u8],
) -> Result<Vec<u8>, ApiError> {
    let session_transcript = mdoc_helper::deserialize(transcript)?;
    let device_signature = device_signature(signer, doc_type, session_transcript)?;
    let device_signature_bytes = helper::serialize(&device_signature)?;
    Ok(device_signature_bytes)
}

#[cfg(test)]
mod test_mdoc_namespace {
    use base64::Engine;

    use crate::log;

    use super::mdoc::{self, helper::CBorHelper};

    #[test]
    fn test_mdoc() {
        let m = "omppc3N1ZXJBdXRohEOhASahGCFZAugwggLkMIICaqADAgECAhRyMm32Ywiae1APjD8mpoXLwsLSyjAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjMwOTAyMTc0MjUxWhcNMjQxMTI1MTc0MjUwWjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQR81BwtG6ZqjrWQYWWw5pPeGxzlr3ptXIr3ftI93rJ_KvC9TAgqJTakJAj2nV4yQGLJl0tw-PhwfbHDrIYsWKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBSB7_ScXIMKUKZGvvdQeFpTPj_YmzAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNoADBlAjBF-tqi7y2VU-u0iETYZBrQKp46jkord9ri9B55Xy8tkJsD8oEJlGtOLZKDrX_BoYUCMQCbnk7tUBCfXw63ACzPmLP-5BFAfmXuMPsBBL7Wc4Lqg94fXMSI5hAXZAEyJ0NATQpZAh3YGFkCGKZnZG9jVHlwZXgbZXUuZXVyb3BhLmVjLmV1ZGkubG95YWx0eS4xZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTA5LTIwVDEyOjQ3OjM5Wml2YWxpZEZyb23AdDIwMjQtMDktMjBUMTI6NDc6MzlaanZhbGlkVW50aWzAdDIwMjQtMTItMTlUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6F4G2V1LmV1cm9wYS5lYy5ldWRpLmxveWFsdHkuMaYAWCDHHhXrAuGS8sASwaj8VYFovhA52ebPqvHmiGketazyFgFYINJuOkjZweO-J4bpTEcI9mh6LhwbDpKrP5zvguea7qVDAlggcHq1-b9rczZR1x8OojBe5rBVUznSxqi82RH59IMWAhwDWCAp22CArLhUzNnJwFB746Q7qDDQfSlZOOUUb-zxnrvyoQRYIOxQxGvuLn3radJ7c54sPNuSo3rt-IPQnjhK-xSarVi_BVggsXWRZrVOJjQ69bEIGvYFxgFcmrmVa1ZrcVsA9tqfypFtZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCBOkUvzZbZglSVkpvHgI-DItlLN81xPXsxOx-vSwk6YhCJYIGdbpUyCN43_uwbHSFzXVx9MTX2zOjSDYGCTQvmbFiIDb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2WEDUtjd79sFcGUEBuPOocua_LtpD3wRbQ5t2IgzaINkMeaL4y28yLhd6QhVZtMtm_xxtKcjC40BBabFNl0u5MVjUam5hbWVTcGFjZXOheBtldS5ldXJvcGEuZWMuZXVkaS5sb3lhbHR5LjGG2BhYZKRmcmFuZG9tWCD7A-91DZEMxZvJw-V_x6rgTfpKlo72w9PFz36KQw3fgmhkaWdlc3RJRABsZWxlbWVudFZhbHVlZHRlc3RxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhtpGZyYW5kb21YIMN9QeRtbfswZd5nrNWuOLzu5jsZPhNPmWuuTXfyzwgbaGRpZ2VzdElEAWxlbGVtZW50VmFsdWXZA-xqMjAyNC0xMi0xOXFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZdgYWG-kZnJhbmRvbVggCTyy3HyQtejRH1PMFi6HKcU7J0aSZbVVr_a8SEAO0JJoZGlnZXN0SUQCbGVsZW1lbnRWYWx1ZdkD7GoyMDI0LTA5LTIwcWVsZW1lbnRJZGVudGlmaWVybWlzc3VhbmNlX2RhdGXYGFhgpGZyYW5kb21YINqyyJ2Qco5SnC2w8E8PvrPkT2eUcEd2xNmkpvX5RkaLaGRpZ2VzdElEA2xlbGVtZW50VmFsdWVkdGVzdHFlbGVtZW50SWRlbnRpZmllcmdjb21wYW552BhYYqRmcmFuZG9tWCAggN8oiqY0zTbfSXD7VKLdvH89TKET1tLFadiDkgMiPmhkaWdlc3RJRARsZWxlbWVudFZhbHVlZHRzZXRxZWxlbWVudElkZW50aWZpZXJpY2xpZW50X2lk2BhYY6RmcmFuZG9tWCCPeLiffdt0c0J4r9cR4zQRbNflliQSHVK33b1_zTS5hGhkaWdlc3RJRAVsZWxlbWVudFZhbHVlZHRlc3RxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZQ==";
        let decoder = if m.contains("=") {
            base64::prelude::BASE64_URL_SAFE
        } else {
            base64::prelude::BASE64_URL_SAFE_NO_PAD
        };
        let Ok(decoded) = decoder.decode(&m) else {
            log::log(crate::log::LogPriority::ERROR, "MDOC", "invalid encoding");
            panic!()
        };
        let Ok(deserialized) = mdoc::helper::deserialize(&decoded) else {
            log::log(crate::log::LogPriority::ERROR, "MDOC", "no cbor?");
            panic!()
        };
        mdoc::namespaces_to_json_map(&deserialized.get("nameSpaces").unwrap(), true).unwrap();
    }
}

// #[uniffi::export]
// impl Credential {
//     pub fn serialize(&self) -> String {
//         serde_json::to_string(self).unwrap_or_default()
//     }
//     pub fn tokens(&self) -> DeviceBoundTokens {
//         self.metadata.clone()
//     }
//     pub fn credential(&self) -> CredentialFormat {
//         self.credential.clone()
//     }
//     pub fn as_sd_jwt(&self) -> Result<Arc<SdJwt>, CredentialError> {
//         let CredentialFormat::SdJwt(ref jwt) = self.credential else {
//             return Err(CredentialError::FormatError);
//         };
//         Ok(Arc::new(SdJwt { jwt: jwt.clone() }))
//     }
//     pub fn json_representation(&self) -> String {
//         match self.credential() {
//             CredentialFormat::SdJwt(s) => s.to_string(),
//             CredentialFormat::Mdoc(m) => {
//                 let Ok(decoded) = base64_decode_bytes(&m) else {
//                     return "{}".to_string();
//                 };
//                 let Ok(deserialized) = mdoc::helper::deserialize(&decoded) else {
//                     return "{}".to_string();
//                 };
//                 let Ok(json_map) = mdoc::namespaces_to_json_map(&deserialized, false) else {
//                     return "{}".to_string();
//                 };
//                 return serde_json::to_string(&json_map).unwrap();
//             }
//         }
//     }
// }

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
/// Device bound tokens represent the OID part of the issuance.
/// They hold information needed to use the refresh token/access token
/// using the respective dpop key.
pub struct DeviceBoundTokens {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub c_nonce: Option<String>,
    pub dpop_key_reference: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
/// A wrapper over the credential format
pub enum CredentialFormat {
    SdJwt(String),
    Mdoc(String),
    BbsTermWise(String),
    W3C(String),
}
