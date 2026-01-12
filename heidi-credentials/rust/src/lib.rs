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

use chrono::SecondsFormat;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::ops::Add;

#[cfg(feature = "bbs")]
pub mod bbs;
pub mod claims_pointer;
pub mod json_ld;
pub mod ldp;
pub mod mdoc;
pub mod models;
pub mod sdjwt;
pub mod sdjwt_util;
pub mod w3c;

#[uniffi::export]
pub fn current_date_time_string() -> String {
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}
#[uniffi::export]
pub fn date_time_string_in_days(days: u64) -> String {
    chrono::Utc::now()
        .add(chrono::Days::new(days))
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}
#[uniffi::export]
pub fn generate_nonce(length: u64) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length as usize)
        .map(char::from)
        .collect()
}

uniffi::setup_scaffolding!();
