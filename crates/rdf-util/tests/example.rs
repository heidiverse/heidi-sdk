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
pub fn rdf_example() {
    use oxttl::NTriplesParser;

    let source = r#"
<did:example:john> <https://example.org/coolNumber> "1337"^^<http://www.w3.org/2001/XMLSchema#integer> .
<did:example:john> <https://example.org/name> "John Doe" .
<did:example:john> <https://example.org/nested> _:b1 .
_:b1 <https://example.org/test> "John Doe" .
    "#;

    let mut rdf = Value::from(
        NTriplesParser::new()
            .for_reader(source.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    );

    assert_eq!(rdf["https://example.org/name"], "John Doe");

    rdf["https://example.org/birthDate"] = Value::String("2000-01-01".to_string());

    rdf["https://example.org/nested"]["https://example.org/value"] = Value::Object(
        BTreeMap::from([(
            "https://example.org/another".to_string(),
            Value::Typed("one".to_string(), "https://example.org/myType".to_string()),
        )]),
        ObjectId::NamedNode("https://example.org/resource/123".to_string()),
    );

    assert_eq!(rdf["https://example.org/birthDate"], "2000-01-01");

    assert_rdf_string_eq(
        rdf.to_string_with_prefix("a".to_string()),
        r#"<did:example:john> <https://example.org/birthDate> "2000-01-01" .
<did:example:john> <https://example.org/coolNumber> "1337"^^<http://www.w3.org/2001/XMLSchema#integer> .
<did:example:john> <https://example.org/name> "John Doe" .
<did:example:john> <https://example.org/nested> _:b1 .
_:b1 <https://example.org/test> "John Doe" .
_:b1 <https://example.org/value> <https://example.org/resource/123> .
<https://example.org/resource/123> <https://example.org/another> "one"^^<https://example.org/myType> .
"#,
    );

    // Make sure the produced string is parsable
    NTriplesParser::new()
        .for_reader(rdf.to_string().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
}
