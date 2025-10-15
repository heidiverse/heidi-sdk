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
use p256::PublicKey;

#[cfg_attr(feature = "uniffi", uniffi::export)]
/// Convert P256 SEC1 Public key bytes (compressed or uncompressed) into JWK
pub fn bytes_to_ec_jwk(bytes: Vec<u8>) -> Option<String> {
    let public_key = PublicKey::from_sec1_bytes(&bytes).ok()?;
    Some(public_key.to_jwk_string())
}
