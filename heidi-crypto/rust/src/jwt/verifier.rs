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

use heidi_jwt::JwsHeader;

/// Get a [jsonwebtoken::DecodingKey] from [key] which is the SubjectPublicKeyInfo
/// (probably taken from the x509)
///
/// It also returns the correct validation struct, indicating the correct algorithm to use
pub(crate) fn decoding_key_from_header(
    key: &[u8],
    header: &JwsHeader,
) -> (jsonwebtoken::DecodingKey, jsonwebtoken::Validation) {
    let mut validation = jsonwebtoken::Validation::default();
    validation.required_spec_claims = Default::default();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let (key, validation) = match header.alg {
        jsonwebtoken::Algorithm::ES256 => {
            validation.algorithms = vec![Algorithm::ES256];
            // jsonwebtoken uses ring and ring can only handle uncompressed keys
            // so we use [p256] crate to parse a compressed (or uncompressed) key
            // and serialize it again in its uncompressed form
            match p256::PublicKey::from_sec1_bytes(key) {
                Ok(pubkey) => {
                    println!("proper bytes");
                    let proper_sec1_bytes = pubkey.to_sec1_bytes();
                    (
                        jsonwebtoken::DecodingKey::from_ec_der(&proper_sec1_bytes),
                        validation,
                    )
                }
                _ => (jsonwebtoken::DecodingKey::from_ec_der(key), validation),
            }
        }
        jsonwebtoken::Algorithm::ES384 => {
            validation.algorithms = vec![Algorithm::ES384];
            // jsonwebtoken uses ring and ring can only handle uncompressed keys
            // so we use [p384] crate to parse a compressed (or uncompressed) key
            // and serialize it again in its uncompressed form
            match p384::PublicKey::from_sec1_bytes(key) {
                Ok(pubkey) => {
                    let proper_sec1_bytes = pubkey.to_sec1_bytes();
                    (
                        jsonwebtoken::DecodingKey::from_ec_der(&proper_sec1_bytes),
                        validation,
                    )
                }
                _ => (jsonwebtoken::DecodingKey::from_ec_der(key), validation),
            }
        }
        Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512 => {
            validation.algorithms = vec![
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::PS512,
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::RS512,
            ];
            (jsonwebtoken::DecodingKey::from_rsa_der(key), validation)
        }
        Algorithm::EdDSA => {
            validation.algorithms = vec![Algorithm::EdDSA];
            (jsonwebtoken::DecodingKey::from_ed_der(key), validation)
        }
        _ => panic!("{:?} not supported", header.alg),
    };

    (key, validation)
}

#[cfg(test)]
mod tests {
    use crate::jwt::{get_x509_from_jwt, validate_jwt_with_pub_key};

    #[test]
    fn test_ecdsa() {
        let jwt = "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk4VWw4ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBTQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il0sInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X3Nhbl9kbnM6ZnVua2UuYW5pbW8uaWQiLCJyZXNwb25zZV91cmkiOiJodHRwczovL2Z1bmtlLmFuaW1vLmlkL29pZDR2cC8wMTkzNjkwMS0yMzkwLTcyMmUtYjlmMS1iZjQyZGI0ZGI3Y2EvYXV0aG9yaXplP3Nlc3Npb249OTlkNjNjNzktNmU5MC00MDJhLWE4ZGEtM2FiODVjYThhYjIyIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsIm5vbmNlIjoiNzcyMDQxMzIxODA4MDQzMDMwODc4MjU2IiwiZGNxbF9xdWVyeSI6eyJjcmVkZW50aWFscyI6W3siaWQiOiIwIiwiZm9ybWF0IjoiZGMrc2Qtand0IiwibWV0YSI6eyJ2Y3RfdmFsdWVzIjpbImV1LmV1cm9wYS5lYy5ldWRpLmhpaWQuMSJdfSwiY2xhaW1zIjpbeyJwYXRoIjpbImhlYWx0aF9pbnN1cmFuY2VfaWQiXSwiaWQiOiJoZWFsdGhfaW5zdXJhbmNlX2lkIn0seyJwYXRoIjpbImFmZmlsaWF0aW9uX2NvdW50cnkiXSwiaWQiOiJhZmZpbGlhdGlvbl9jb3VudHJ5In1dfV0sImNyZWRlbnRpYWxfc2V0cyI6W3sib3B0aW9ucyI6W1siMCJdXSwicHVycG9zZSI6IlRvIHJlY2VpdmUgeW91ciBwcmVzY3JpcHRpb24gYW5kIGZpbmFsaXplIHRoZSB0cmFuc2FjdGlvbiwgd2UgcmVxdWlyZSB0aGUgZm9sbG93aW5nIGF0dHJpYnV0ZXMifV19LCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IllQd3JYN3BUU25RWWpMeHBGY0V1ZGRGelZaazI2ME9aU3QzWktGUm0taVUiLCJ5IjoiWG52cUJMa3lGUjdCZms0SW5QNDJ0NzJTWTdtQUhTNkV3MFpQYmJWRWswSSIsImtpZCI6InpEbmFlV3haQ3JBeEc0R0VOQzJIN0VjaGE4QldHeDFUTXZzVHZic0RFeTc0WWFQUmUiLCJ1c2UiOiJlbmMifV19LCJ2cF9mb3JtYXRzIjp7Im1zb19tZG9jIjp7ImFsZyI6WyJFZERTQSIsIkVTMjU2IiwiRVMzODQiXX0sImp3dF92YyI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiIsIkVTMzg0IiwiRVMyNTZLIl19LCJqd3RfdmNfanNvbiI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiIsIkVTMzg0IiwiRVMyNTZLIl19LCJqd3RfdnBfanNvbiI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiIsIkVTMzg0IiwiRVMyNTZLIl19LCJqd3RfdnAiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiLCJFUzM4NCIsIkVTMjU2SyJdfSwibGRwX3ZjIjp7InByb29mX3R5cGUiOlsiRWQyNTUxOVNpZ25hdHVyZTIwMjAiXX0sImxkcF92cCI6eyJwcm9vZl90eXBlIjpbIkVkMjU1MTlTaWduYXR1cmUyMDIwIl19LCJ2YytzZC1qd3QiOnsia2Itand0X2FsZ192YWx1ZXMiOlsiRWREU0EiLCJFUzI1NiIsIkVTMzg0IiwiRVMyNTZLIl0sInNkLWp3dF9hbGdfdmFsdWVzIjpbIkVkRFNBIiwiRVMyNTYiLCJFUzM4NCIsIkVTMjU2SyJdfSwiZGMrc2Qtand0Ijp7ImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVkRFNBIiwiRVMyNTYiLCJFUzM4NCIsIkVTMjU2SyJdLCJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFZERTQSIsIkVTMjU2IiwiRVMzODQiLCJFUzI1NksiXX19LCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiJFQ0RILUVTIiwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTEyOEdDTSIsImxvZ29fdXJpIjoiaHR0cHM6Ly9mdW5rZS5hbmltby5pZC9hc3NldHMvdmVyaWZpZXJzL3JlZGNhcmUucG5nIiwiY2xpZW50X25hbWUiOiJSZWRjYXJlIFBoYXJtYWN5IiwicmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkIjpbInZwX3Rva2VuIl19LCJzdGF0ZSI6IjEwMDgzMDYwMzcwMTQxNTMwNTU5OTc4ODUiLCJhdWQiOiJodHRwczovL2Z1bmtlLmFuaW1vLmlkL29pZDR2cC8wMTkzNjkwMS0yMzkwLTcyMmUtYjlmMS1iZjQyZGI0ZGI3Y2EvYXV0aG9yaXphdGlvbi1yZXF1ZXN0cy85OWQ2M2M3OS02ZTkwLTQwMmEtYThkYS0zYWI4NWNhOGFiMjIiLCJleHAiOjE3NDY0NTQ2OTAsImlhdCI6MTc0NjQ1NDM5MH0.eCGNo4gPvO5cwcD7yaw8IvTEeTh8beIrWOd9Ca43bfSsQQGq9xlq-rlmbtm7M0NYyutQh6I99xB47F3jUvKQvQ";
        let certs = get_x509_from_jwt(jwt.to_string()).unwrap();
        println!("{:?}", certs[0].public_key);
        assert!(validate_jwt_with_pub_key(jwt, certs[0].public_key.clone()));
    }
}
