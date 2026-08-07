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

use std::collections::BTreeMap;

use rdf_util::{test::assert_rdf_string_eq, ObjectId, Value};

#[test]
fn rdf_array() {
    let source = r#"
        _:b0 <https://example.org/value> "Hello" .
        _:b0 <https://example.org/value> "World" .
        "#;

    let rdf = rdf_util::from_str(source).unwrap();

    assert_eq!(
        rdf["https://example.org/value"],
        Value::Array(vec![
            Value::String("Hello".into()),
            Value::String("World".into())
        ])
    );
}

#[test]
fn rdf_nested_array() {
    // There is no such thing as "nested arrays" in rdf
    // thus they will be flattened when serializing.

    let rdf = Value::Object(
        BTreeMap::from([(
            "https://example.org/value".into(),
            Value::Array(vec![Value::Array(vec![
                Value::String("Hello".into()),
                Value::String("World".into()),
            ])]),
        )]),
        ObjectId::None,
    );

    assert_rdf_string_eq(
        rdf.to_string_with_prefix("b".into()),
        r#"
        _:b0 <https://example.org/value> "Hello" .
        _:b0 <https://example.org/value> "World" .
        "#,
    );
}
