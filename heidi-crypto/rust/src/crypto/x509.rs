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

use crate::crypto::{SignatureCreator, base64_url_decode, base64_url_encode};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
#[cfg(feature = "crl")]
use heidi_util_rust::log_debug;
use heidi_util_rust::log_error;
use oid_registry::{OidEntry, OidRegistry};
use p256::NistP256;
use p256::pkcs8::der::Encode;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use simple_x509::X509Builder;
use std::sync::Arc;
use whitespace_sifter::WhitespaceSifter;
use x509_parser::der_parser::oid;
use x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY;
#[cfg(feature = "crl")]
use x509_parser::prelude::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::prelude::{
    TbsCertificateStructureValidator, Validator, VecLogger, X509ExtensionsValidator,
};
use x509_parser::time::ASN1Time;
use x509_parser::x509::X509Name;

#[derive(uniffi::Record, Clone, Debug)]
pub struct X509Certificate {
    serial: String,
    subject: String,
    authority_key_identifier: Option<String>,
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
    oid_registry.insert(oid!(2.5.4.97), entry);
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
        let aki = if let Ok(Some(extension)) = cert.get_extension_unique(&oid!(2.5.29.35)) {
            Some(BASE64_URL_SAFE_NO_PAD.encode(extension.value))
        } else {
            None
        };
        certificates.push(X509Certificate {
            original_cert: buf.clone(),
            algo_oid: cert.public_key().algorithm.oid().to_string(),
            serial: cert.serial.to_str_radix(16),
            authority_key_identifier: aki,
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

fn verify_chain_at(
    certs: Vec<X509Certificate>,
    time: ASN1Time,
    #[cfg(feature = "crl")] check_crl: bool,
) -> bool {
    // a valid chain requires at least two certificates (leaf + issuer)
    if certs.len() < 2 {
        log_error!("X509", "chain must contain at least two certificates");
        return false;
    }
    // first certificate is the leaf certificate
    let mut certs = certs;
    // the last (or rather first) certificate is not an intermediate and is not counted towards the path len
    let total_path_len = certs.len() - 1;
    let mut prev_cert = certs.pop();
    let mut current_position = 1;
    while let Some(issuer_cert) = prev_cert {
        prev_cert = certs.pop();
        if let Some(subject_cert) = prev_cert.as_ref() {
            let (_, issuer_cert) =
                x509_parser::parse_x509_certificate(issuer_cert.original_cert.as_ref()).unwrap();
            let mut logger = VecLogger::default();
            let structure_validity =
                TbsCertificateStructureValidator.validate(&issuer_cert, &mut logger);
            let x509_extensions_validity =
                X509ExtensionsValidator.validate(&issuer_cert.extensions(), &mut logger);
            if !(structure_validity && x509_extensions_validity) {
                log_error!("X509", "subject cert has invalid structure");
                return false;
            }
            let (_, subject_cert) =
                x509_parser::parse_x509_certificate(subject_cert.original_cert.as_ref()).unwrap();
            let structure_validity =
                TbsCertificateStructureValidator.validate(&subject_cert, &mut logger);
            let x509_extensions_validity =
                X509ExtensionsValidator.validate(&subject_cert.extensions(), &mut logger);
            if !(structure_validity && x509_extensions_validity) {
                log_error!("X509", "issuer cert has invalid structure");
                return false;
            }
            if !is_key_usage_correct(&issuer_cert) {
                log_error!("X509", "issuer cert has incorrect key usage");
                return false;
            }
            match is_basic_constraint_fulfilled(&issuer_cert, current_position, total_path_len) {
                Ok(false) | Err(_) => {
                    log_error!("X509", "basic constraint not fullfileld");
                    return false;
                }
                _ => {}
            }

            let is_valid = subject_cert
                .verify_signature(Some(issuer_cert.public_key()))
                .is_ok();
            if !is_valid {
                log_error!("X509", "signature invalid");
                return false;
            }
            if !are_x509_name_equal(&subject_cert.issuer, &issuer_cert.subject) {
                log_error!("X509", "issuer name and subject name missmatch");
                return false;
            }

            let issuer_validity = issuer_cert.validity();
            if !issuer_validity.is_valid_at(time) {
                log_error!("X509", "subject certificate is not valid");
                return false;
            }
            let subject_validity = subject_cert.validity();
            if !subject_validity.is_valid_at(time) {
                log_error!("X509", "issuer certificate is not valid");
                return false;
            }
            #[cfg(feature = "crl")]
            if check_crl {
                match check_revocation(&subject_cert) {
                    // certificate is revoked (on the CRL)
                    Ok(true) => return false,
                    // something went wrong
                    Err(_) => return false,
                    // network error or not on the list
                    _ => {}
                }
                #[cfg(feature = "crl")]
                match check_revocation(&issuer_cert) {
                    // certificate is revoked (on the CRL)
                    Ok(true) => return false,
                    // something went wrong
                    Err(_) => return false,
                    // network error or not on the list
                    _ => {}
                }
            }
            current_position += 1;
        }
    }
    true
}

#[uniffi::export]
fn verify_chain(certs: Vec<X509Certificate>) -> bool {
    verify_chain_at(
        certs,
        ASN1Time::now(),
        #[cfg(feature = "crl")]
        true,
    )
}
// key usage should be parsable and if present be certSign
fn is_key_usage_correct(cert: &x509_parser::prelude::X509Certificate) -> bool {
    let Ok(key_usage) = cert.key_usage() else {
        log_error!("X509", "Failed to parse keyusage");
        return false;
    };
    let Some(key_usage) = key_usage else {
        // no key usage, everything fine
        return true;
    };
    key_usage.value.key_cert_sign()
}

/// Make sure signing certificates have cA true
fn is_basic_constraint_fulfilled(
    cert: &x509_parser::prelude::X509Certificate,
    current_path_len: usize,
    total_path_len: usize,
) -> Result<bool, ()> {
    let Ok(basic_constraints) = cert.get_extension_unique(&oid!(2.5.29.19)) else {
        return Err(());
    };
    // It was parsed successfully but no CRL found
    let Some(basic_constraints) = basic_constraints else {
        return Ok(false);
    };
    let ParsedExtension::BasicConstraints(basic_constraints) = basic_constraints.parsed_extension()
    else {
        return Err(());
    };
    // all intermediate have to have ca = true
    if !basic_constraints.ca {
        return Ok(false);
    }
    let remaining_path_len = total_path_len.saturating_sub(current_path_len);
    if let Some(path_constraint) = basic_constraints.path_len_constraint {
        if remaining_path_len > path_constraint as usize {
            return Ok(false);
        }
    }
    Ok(true)
}

/// compare x509 name removing trailing/leading bits and lowercasing
fn are_x509_name_equal(left: &X509Name, right: &X509Name) -> bool {
    let mut equal = true;
    for (left_part, right_part) in left.iter().zip(right.iter()) {
        for (left_component, right_component) in left_part.iter().zip(right_part.iter()) {
            match (left_component.as_str(), right_component.as_str()) {
                (Ok(left_str), Ok(right_str)) => {
                    equal &= left_str.sift().to_lowercase() == right_str.sift().to_lowercase()
                }
                _ => equal &= left_component.as_slice() == right_component.as_slice(),
            }
        }
    }
    equal
}

#[cfg(feature = "crl")]
/// Simplified function for checking and fetching a CRL over URL
///
/// Note: *Network errors are ignored!*
fn check_revocation(cert: &x509_parser::prelude::X509Certificate) -> Result<bool, ()> {
    // log_debug!("X509", "checking revocation");
    // We have a parse error, return err
    let Ok(maybe_dist_points) = cert.get_extension_unique(&oid!(2.5.29.31)) else {
        return Err(());
    };
    // It was parsed successfully but no CRL found
    let Some(crl_distribution_points) = maybe_dist_points else {
        return Ok(false);
    };
    // Something is terribly wrong, as we should have matched to the OID before
    let ParsedExtension::CRLDistributionPoints(dist_points) =
        crl_distribution_points.parsed_extension()
    else {
        return Err(());
    };
    // We only look at the first point
    let Some(point) = dist_points.points.first() else {
        return Err(());
    };
    // The URL CRL must be in the distribution_point field
    let Some(pt) = point.distribution_point.as_ref() else {
        return Err(());
    };
    // If it is not a full name we don't know what to do
    let DistributionPointName::FullName(full_name) = pt else {
        return Err(());
    };
    // again look at the first name only
    let Some(full_name) = full_name.first() else {
        return Err(());
    };
    // we don't know how to handle CLRs that do not point towards an URL
    let GeneralName::URI(uri) = full_name else {
        return Err(());
    };
    // fetch the revocation list
    let Ok(mut response) = ureq::get(*uri).call() else {
        // failed network requests are ignored
        return Ok(false);
    };
    let b = response.body_mut();
    let Ok(list) = b.read_to_vec() else {
        // if the stream is somewhat broken, ignore!
        return Ok(false);
    };
    // we fetched something, but it fails to parse, error out
    let Ok((_, crl)) = x509_parser::parse_x509_crl(&list) else {
        return Err(());
    };
    let result = crl
        .iter_revoked_certificates()
        .find(|a| *a.serial() == cert.serial);
    log_debug!(
        "X509",
        &format!("successfully loaded CRL, revoked: {}", result.is_some())
    );
    Ok(result.is_some())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        io::{Cursor, Read},
    };

    use base64::Engine;
    use flate2::read::GzDecoder;

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
    #[test]
    fn test_x509_with_aki() {
        let aki = "-----BEGIN CERTIFICATE-----
MIIEWjCCA0KgAwIBAgIQC/2k+ogVBpMJ409phBMnDzANBgkqhkiG9w0BAQsFADA7
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMQww
CgYDVQQDEwNXUjIwHhcNMjYwMTI2MDg0MjAxWhcNMjYwNDIwMDg0MjAwWjAWMRQw
EgYDVQQDDAsqLmdvb2dsZS5jaDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHQx
wYSi27+sZRyI/AGI0L1Z6CvizfNfnarZoVI4QAT8YduwMgoQ/33WkW7ItekFtCJF
eU1dIx15o03FAhIw2LijggJIMIICRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
CgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU9/mNOJXx8ARmzVOn
ZuJjFzvW0A8wHwYDVR0jBBgwFoAU3hse7XkV1D43JMMhu+w0OW1CsjAwWAYIKwYB
BQUHAQEETDBKMCEGCCsGAQUFBzABhhVodHRwOi8vby5wa2kuZ29vZy93cjIwJQYI
KwYBBQUHMAKGGWh0dHA6Ly9pLnBraS5nb29nL3dyMi5jcnQwIQYDVR0RBBowGIIL
Ki5nb29nbGUuY2iCCWdvb2dsZS5jaDATBgNVHSAEDDAKMAgGBmeBDAECATA2BgNV
HR8ELzAtMCugKaAnhiVodHRwOi8vYy5wa2kuZ29vZy93cjIvb0JGWVlhaHpnVkku
Y3JsMIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDvAHUA0W6ppWgHfmY1oD83pd28A6U8
QRIU1IgY9ekxsyPLlQQAAAGb+a6DVQAABAMARjBEAiBEySufKvVNB3o8zjnF4WDa
FOpB2KEGq7Gc0ky8UgFZWAIgVtZfbHKQDSR8+S1a979PpSt3s8WogGxi+5DFtyD+
bX0AdgAOV5S8866pPjMbLJkHs/eQ35vCPXEyJd0hqSWsYcVOIQAAAZv5roJ+AAAE
AwBHMEUCIQDSXZ6+nIrq2tOlc6nxZmnwo3k1J4xlk9s3VGa4gk42ugIgSEoQ831i
nvNinxJCCn4EUNBAEQZZ83mn47F4TJoWc94wDQYJKoZIhvcNAQELBQADggEBAETx
h2jqQoFB7fz9mGyHxbmbSfPwAjO3J8zSrqVWQXfAgyTlaL38XlQpmv/r5gQ7btGN
wx5e4a3tj2QmP7PiWlSavedf01J9NsOyL9QEYEEFLYhrPp25NPXKh5XFUvbPIwVA
8PM5mperE+9XYVlRfLmv9iGME1GnFgSYjB1jQcXXbe/+nHY3M5UPSDWgVYH8vAVI
b5MVq6xm0SL7cGvK7HG9Vp9fcROjozkeoB1zIoB3j2Nrjw5rGhPZTBgnJVnc72s9
Gne7v8ihgDj51jzj6AhXdVUwrQ4vOVAWWwZCZxvpJ+VAUVXcTxXj3g+DNuHZcJOy
nnW2WuEYWxYBKIHcotA=
-----END CERTIFICATE-----";
        let (_, cert) = x509_parser::pem::parse_x509_pem(aki.as_bytes()).unwrap();
        let certs = extract_certs(cert.contents);
        println!("{:?}", certs);
    }
    #[test]
    fn test_x509_path_validation() {
        let truth_table: HashMap<&str, bool> = [
            ("test1", true),
            ("test2", false),
            ("test3", false),
            ("test4", true),
            ("test5", false),
            ("test6", false),
            ("test7", true),
            ("test8", false),
            ("test9", false),
            ("test10", false),
            ("test11", false),
            ("test12", true),
            ("test13", false),
            ("test14", false),
            ("test15", true),
            ("test16", true),
            ("test17", true),
            ("test18", true),
            // revocation is not part of the cert
            // ("test19", false),
            // ("test20", false),
            // ("test21", false),
            ("test22", false),
            ("test23", false),
            ("test24", true),
            ("test25", false),
            ("test26", true),
            ("test27", true),
            ("test28", false),
            ("test29", false),
            ("test30", true),
            ("test31", false),
            ("test32", false),
            ("test33", true),
            ("test54", false),
            ("test55", false),
            ("test56", true),
            ("test57", true),
            ("test58", false),
            ("test59", false),
            ("test60", false),
            ("test61", false),
            ("test62", true),
            ("test63", true),
        ]
        .into_iter()
        .collect();
        let test_suite_bytes = include_bytes!("../../x509tests.tgz");
        let test_suite_bytes = GzDecoder::new(Cursor::new(test_suite_bytes));
        let mut test_suite_archive = tar::Archive::new(test_suite_bytes);
        let mut test_map = BTreeMap::<String, Vec<(String, Vec<u8>)>>::new();
        let mut test_vec = Vec::new();
        for entry in test_suite_archive.entries().unwrap() {
            let Ok(mut entry) = entry else {
                continue;
            };
            let path = entry.path().unwrap();
            if path.extension().is_some() {
                let testfile = path.strip_prefix("X509tests").unwrap();
                let test_name = testfile.parent().unwrap().to_str().unwrap().to_string();
                let file_name = testfile.file_name().unwrap().to_str().unwrap().to_string();
                if !test_vec.contains(&test_name) {
                    test_vec.push(test_name.clone());
                }
                let directory = test_map.entry(test_name).or_default();
                let mut file_bytes = Vec::with_capacity(entry.size() as usize);
                entry.read_to_end(&mut file_bytes).unwrap();
                directory.push((file_name, file_bytes));
            }
        }
        for test in test_vec {
            let test_files = &test_map[&test];
            let mut certs = test_files
                .iter()
                .filter(|a| a.0.ends_with(".crt"))
                .map(|a| extract_certs(a.1.clone()).first().unwrap().to_owned())
                .collect::<Vec<_>>();
            certs.reverse();
            let result = verify_chain(certs);
            let matches = if let Some(expected) = truth_table.get(&test.as_str()) {
                if expected == &result { "✅" } else { "❌" }
            } else {
                "-"
            };
            println!(
                "{}: {} [{}] -> {matches}",
                test,
                result,
                truth_table
                    .get(&test.as_str())
                    .map(|a| a.to_string())
                    .unwrap_or("N/A".to_string())
            );
        }
    }
}
