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

/// Compares two rdf strings, independent of the order of the triples
pub fn assert_rdf_string_eq<S1: AsRef<str>, S2: AsRef<str>>(lhs: S1, rhs: S2) {
    let lhs = lhs
        .as_ref()
        .trim()
        .split("\n")
        .map(|it| it.trim())
        .collect::<BTreeSet<&str>>();
    let rhs = rhs
        .as_ref()
        .trim()
        .split("\n")
        .map(|it| it.trim())
        .collect::<BTreeSet<&str>>();
    assert_eq!(lhs, rhs);
}
