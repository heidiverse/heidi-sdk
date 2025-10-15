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

use crate::crypto::{base64_url_decode, base64_url_encode, SignatureCreator};
use oid_registry::{OidEntry, OidRegistry};
use p256::pkcs8::der::Encode;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::NistP256;
use simple_x509::X509Builder;
use std::sync::Arc;
use x509_parser::der_parser::oid;
use x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY;

#[derive(uniffi::Record, Clone, Debug)]
pub struct X509Certificate {
    serial: String,
    subject: String,
    pub public_key: X509PublicKey,
    algo_oid: String,
    san: Vec<SanType>,
    original_cert: Vec<u8>,
    issuer: String,
}
#[derive(uniffi::Enum, Clone, Debug)]
pub enum X509PublicKey {
    P256 { x: String, y: String },
    Other { data: Vec<u8> },
}
#[derive(uniffi::Enum, Clone, Debug)]
pub enum SanType {
    DNS(String),
    URI(String),
}

#[derive(uniffi::Record)]
pub struct CertificateData {
    subject: SubjectIdentifier,
    issuer: SubjectIdentifier,
    not_before: i64,
    not_after: i64,
}
#[derive(uniffi::Record)]
pub struct SubjectIdentifier {
    country: Option<String>,
    state: Option<String>,
    organization: Option<String>,
    locality: Option<String>,
    common_name: String,
}

#[uniffi::export]
/// Create certificate signed by signing key
/// currently we only support p256 keys
pub fn create_cert(
    certificate_data: CertificateData,
    pubkey: X509PublicKey,
    signer: Arc<dyn SignatureCreator>,
) -> Option<Vec<u8>> {
    let X509PublicKey::P256 { x, y } = pubkey else {
        return None;
    };
    let mut public_key_bytes = vec![0x04];
    public_key_bytes.extend(base64_url_decode(x));
    public_key_bytes.extend(base64_url_decode(y));
    let public_key = p256::PublicKey::from_sec1_bytes(&public_key_bytes).unwrap();
    let der_bytes = public_key.to_public_key_der().unwrap().to_der().unwrap();
    let serial: [u8; 32] = rand::random();
    let mut builder = X509Builder::new(serial.to_vec()) /* SerialNumber */
        .version(2);
    let issuer = certificate_data.issuer;
    let subject = certificate_data.subject;
    builder = builder.issuer_utf8(vec![2, 5, 4, 3], &issuer.common_name);
    if let Some(country) = &issuer.country {
        builder = builder.issuer_prstr(vec![2, 5, 4, 6], &country); /* countryName */
    }
    if let Some(state) = &issuer.state {
        builder = builder.issuer_utf8(vec![2, 5, 4, 8], state); /* stateOrProvinceName */
    }
    if let Some(organization) = &issuer.organization {
        builder = builder.issuer_utf8(vec![2, 5, 4, 10], &organization); /* organizationName */
    }
    if let Some(country) = subject.country {
        builder = builder.subject_prstr(vec![2, 5, 4, 6], &country); /* countryName */
    }
    if let Some(state) = &subject.state {
        builder = builder.subject_utf8(vec![2, 5, 4, 8], state); /* stateOrProvinceName */
    }
    if let Some(organization) = &subject.organization {
        builder = builder.subject_utf8(vec![2, 5, 4, 10], organization); /* organizationName */
    }
    if let Some(locality) = &subject.locality {
        builder = builder.subject_utf8(vec![2, 5, 4, 7], locality);
    }
    builder = builder.subject_utf8(vec![2, 5, 4, 3], &subject.common_name); /* common name */
    let cert = builder
        .not_before_utc(certificate_data.not_before)
        .not_after_utc(certificate_data.not_after)
        .pub_key_der(&der_bytes)
        .sign_oid(vec![1, 2, 840, 10045, 4, 3, 2]) /* sha256 with secp256r1  */
        .build();
    let cert = cert.sign(|d, _| signer.sign(d.to_vec()).ok(), &[]).unwrap();
    cert.x509_enc().ok()
}

#[uniffi::export]
pub fn extract_certs(buf: Vec<u8>) -> Vec<X509Certificate> {
    let mut oid_registry = OidRegistry::default().with_x509();
    let entry = OidEntry::new("organizationIdentifier", "organizationIdentifier");
    oid_registry.insert(oid!(2.5.4 .97), entry);
    let mut certificates = vec![];
    let mut remaining_buf = buf.as_slice();
    loop {
        let (rest, cert) = x509_parser::parse_x509_certificate(remaining_buf).unwrap();
        remaining_buf = rest;
        let mut sans = vec![];
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for san in &san.value.general_names {
                match san {
                    x509_parser::prelude::GeneralName::DNSName(dns) => {
                        sans.push(SanType::DNS(dns.to_string()))
                    }
                    x509_parser::prelude::GeneralName::URI(uri) => {
                        sans.push(SanType::URI(uri.to_string()))
                    }
                    _ => continue,
                }
            }
        }
        certificates.push(X509Certificate {
            original_cert: buf.clone(),
            algo_oid: cert.public_key().algorithm.oid().to_string(),
            serial: cert.serial.to_str_radix(16),
            subject: cert
                .subject
                .to_string_with_registry(&oid_registry)
                .unwrap_or(cert.subject().to_string()),
            issuer: cert
                .issuer()
                .to_string_with_registry(&oid_registry)
                .unwrap_or(cert.issuer().to_string()),
            public_key: if *cert.public_key().algorithm.oid() == OID_KEY_TYPE_EC_PUBLIC_KEY {
                try_extract_p256_key(&cert)
            } else {
                X509PublicKey::Other {
                    data: cert.public_key().subject_public_key.data.to_vec(),
                }
            },
            san: sans,
        });
        if rest.is_empty() {
            break;
        }
    }
    certificates
}
/// Extract a p256 key if it is p256 only. Otherwise return the der encoded data directly
fn try_extract_p256_key(cert: &x509_parser::certificate::X509Certificate) -> X509PublicKey {
    let Ok(pub_key) = p256::PublicKey::from_public_key_der(cert.public_key().raw) else {
        return X509PublicKey::Other {
            data: cert.public_key().subject_public_key.data.to_vec(),
        };
    };
    let Ok(key) = pub_key.to_jwk().to_encoded_point::<NistP256>() else {
        return X509PublicKey::Other {
            data: cert.public_key().subject_public_key.data.to_vec(),
        };
    };
    X509PublicKey::P256 {
        x: base64_url_encode(key.x().unwrap().to_vec()),
        y: base64_url_encode(key.y().unwrap().to_vec()),
    }
}

#[uniffi::export]
fn verify_chain(certs: Vec<X509Certificate>) -> bool {
    // first certificate is the leaf certificate
    let mut certs = certs;
    let mut prev_cert = certs.pop();
    while let Some(child_cert) = prev_cert {
        prev_cert = certs.pop();
        if let Some(parent_cert) = prev_cert.as_ref() {
            let (_, child_cert) =
                x509_parser::parse_x509_certificate(child_cert.original_cert.as_ref()).unwrap();
            let (_, parent_cert) =
                x509_parser::parse_x509_certificate(parent_cert.original_cert.as_ref()).unwrap();
            let is_valid = parent_cert
                .verify_signature(Some(child_cert.public_key()))
                .is_ok();
            if !is_valid {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use crate::{base64_decode, jwt::get_x509_from_jwt};

    use super::{extract_certs, verify_chain};

    #[test]
    fn test_san() {
        let cert = "MIIB5TCCAYugAwIBAgIQGUdF0kBiQGDawp+0dBSS5jAKBggqhkjOPQQDAjAdMQ4wDAYDVQQDEwVBbmltbzELMAkGA1UEBhMCTkwwHhcNMjUwNDEyMTQyMzMwWhcNMjYwNTAyMTQyMzMwWjAhMRIwEAYDVQQDEwljcmVkbyBkY3MxCzAJBgNVBAYTAk5MMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFXVNA0laa+5P2nk5PJFov8xhBFNz5UOJBIVsyk0SKSfqTfKMB6R+cFDNijdmBYyuEaUgMguUc8hOVnnreW9thKOBqDCBpTAdBgNVHQ4EFgQUYR8vFQTlkjf1/NnKeZxvY0Zz3aAwDgYDVR0PAQH/BAQDAgeAMBUGA1UdJQEB/wQLMAkGByiBjF0FAQIwHwYDVR0jBBgwFoAUL98waNYv9QnxIHb5CFgxjvZUtUswIQYDVR0SBBowGIYWaHR0cHM6Ly9mdW5rZS5hbmltby5pZDAZBgNVHREEEjAQgg5mdW5rZS5hbmltby5pZDAKBggqhkjOPQQDAgNIADBFAiBBwdS/cFBs3awtfP9GFVkgSOITQdPBMLhsJByjg7l2LQIhAPQJWy7qQsfq2GrdpcGXHrDVK0w/XnPF2XAT6rTX8uCP";
        let result = base64_decode(cert).unwrap();
        let certs = extract_certs(result);
        println!("{:?}", certs);
    }
    #[test]
    fn test_x509_chain() {
        let jwt = "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk4VWw4ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBTQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il0sInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X3Nhbl9kbnM6ZnVua2UuYW5pbW8uaWQiLCJyZXNwb25zZV91cmkiOiJodHRwczovL2Z1bmtlLmFuaW1vLmlkL29pZDR2cC8wMTkzNjkwMS0yMzkwLTcyMmUtYjlmMS1iZjQyZGI0ZGI3Y2EvYXV0aG9yaXplP3Nlc3Npb249MDAyZGMwNzQtZDhhYi00MmQ4LWJmNWMtOTg3NWRhYTVjNzZkIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsIm5vbmNlIjoiNzAzNTAxNjY1OTM0NzMwMDQ5NzQyMTAwIiwiZGNxbF9xdWVyeSI6eyJjcmVkZW50aWFscyI6W3siaWQiOiIwIiwiZm9ybWF0IjoiZGMrc2Qtand0IiwibWV0YSI6eyJ2Y3RfdmFsdWVzIjpbImV1LmV1cm9wYS5lYy5ldWRpLmhpaWQuMSJdfSwiY2xhaW1zIjpbeyJwYXRoIjpbImhlYWx0aF9pbnN1cmFuY2VfaWQiXSwiaWQiOiJoZWFsdGhfaW5zdXJhbmNlX2lkIn0seyJwYXRoIjpbImFmZmlsaWF0aW9uX2NvdW50cnkiXSwiaWQiOiJhZmZpbGlhdGlvbl9jb3VudHJ5In1dfV0sImNyZWRlbnRpYWxfc2V0cyI6W3sib3B0aW9ucyI6W1siMCJdXSwicHVycG9zZSI6IlRvIHJlY2VpdmUgeW91ciBwcmVzY3JpcHRpb24gYW5kIGZpbmFsaXplIHRoZSB0cmFuc2FjdGlvbiwgd2UgcmVxdWlyZSB0aGUgZm9sbG93aW5nIGF0dHJpYnV0ZXMifV19LCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InAwdDhKVmsxanctR3lsUjc3emNxUUp2Q05lODB2TERfUC1CYUZueklndmsiLCJ5IjoiMmV5eF9QcUFTTlFVaEhhQUZQRUdfei0wRE1yTlM5WWVXb0VQNFZva21PdyIsImtpZCI6InpEbmFlYmgxdGRWblBpa1BMaXg5TDRtTWh4Tll3aENNc3ZtR0x0OWk0TmlCcHFncW4iLCJ1c2UiOiJlbmMifV19LCJ2cF9mb3JtYXRzIjp7Im1zb19tZG9jIjp7ImFsZyI6WyJFZERTQSIsIkVTMjU2IiwiRVMzODQiXX0sImp3dF92YyI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiIsIkVTMzg0IiwiRVMyNTZLIl19LCJqd3RfdmNfanNvbiI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiIsIkVTMzg0IiwiRVMyNTZLIl19LCJqd3RfdnBfanNvbiI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiIsIkVTMzg0IiwiRVMyNTZLIl19LCJqd3RfdnAiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiLCJFUzM4NCIsIkVTMjU2SyJdfSwibGRwX3ZjIjp7InByb29mX3R5cGUiOlsiRWQyNTUxOVNpZ25hdHVyZTIwMjAiXX0sImxkcF92cCI6eyJwcm9vZl90eXBlIjpbIkVkMjU1MTlTaWduYXR1cmUyMDIwIl19LCJ2YytzZC1qd3QiOnsia2Itand0X2FsZ192YWx1ZXMiOlsiRWREU0EiLCJFUzI1NiIsIkVTMzg0IiwiRVMyNTZLIl0sInNkLWp3dF9hbGdfdmFsdWVzIjpbIkVkRFNBIiwiRVMyNTYiLCJFUzM4NCIsIkVTMjU2SyJdfSwiZGMrc2Qtand0Ijp7ImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVkRFNBIiwiRVMyNTYiLCJFUzM4NCIsIkVTMjU2SyJdLCJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFZERTQSIsIkVTMjU2IiwiRVMzODQiLCJFUzI1NksiXX19LCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiJFQ0RILUVTIiwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTEyOEdDTSIsImxvZ29fdXJpIjoiaHR0cHM6Ly9mdW5rZS5hbmltby5pZC9hc3NldHMvdmVyaWZpZXJzL3JlZGNhcmUucG5nIiwiY2xpZW50X25hbWUiOiJSZWRjYXJlIFBoYXJtYWN5IiwicmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkIjpbInZwX3Rva2VuIl19LCJzdGF0ZSI6IjU4NDY0NDg5OTA4NTk1NDkwMzA5MzQ1NSIsImF1ZCI6Imh0dHBzOi8vZnVua2UuYW5pbW8uaWQvb2lkNHZwLzAxOTM2OTAxLTIzOTAtNzIyZS1iOWYxLWJmNDJkYjRkYjdjYS9hdXRob3JpemF0aW9uLXJlcXVlc3RzLzAwMmRjMDc0LWQ4YWItNDJkOC1iZjVjLTk4NzVkYWE1Yzc2ZCIsImV4cCI6MTc0NjUyNTI2MywiaWF0IjoxNzQ2NTI0OTYzfQ.zGuAMwA8eOaRx83lpD8OuWEDyOrXSaqWFpH5iwZKQ9l7As6XLYfWOAuTUeSa38RppjNxlRNM2VL7eN7t8KiHFQ";
        let certs = get_x509_from_jwt(jwt.to_string()).unwrap();
        println!(
            "{}",
            base64::prelude::BASE64_STANDARD.encode(&certs[1].original_cert)
        );
        assert!(verify_chain(certs));
    }
}
