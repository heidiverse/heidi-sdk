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

use std::collections::BTreeSet;

use crate::Value;

#[derive(Debug, Clone, Default)]
pub struct BlankGenerator {
    used_ids: BTreeSet<String>,
}

impl BlankGenerator {
    pub fn init(value: &Value) -> Self {
        Self {
            used_ids: value.taken_blank_ids(),
        }
    }

    pub fn next<S: AsRef<str>>(&mut self, prefix: S) -> String {
        let prefix = prefix.as_ref();
        let mut count = 0;

        let mut id = format!("{prefix}{count}");
        count += 1;

        while self.used_ids.contains(&id) {
            id = format!("{prefix}{count}");
            count += 1;
        }

        self.used_ids.insert(id.clone());

        id
    }
}
