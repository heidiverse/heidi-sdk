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

use wasm_bindgen::JsValue;

use super::{create_backup, reconstruct, Backup};

#[wasm_bindgen::prelude::wasm_bindgen]
pub fn create_backup_wasm(file: Vec<u8>, number_of_shares: u16) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    create_backup(file, number_of_shares, None)
        .map(|e| serde_json::to_string(&e).unwrap().into())
        .map_err(|e| format!("{e}").into())
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub fn reconstruct_wasm(shares: &str) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();

    let shares: Backup = serde_json::from_str(shares).map_err(|e| format!("{e}"))?;
    reconstruct(shares.shares)
        .map(|e| serde_json::to_string(&e).unwrap().into())
        .map_err(|e| format!("{e}").into())
}
