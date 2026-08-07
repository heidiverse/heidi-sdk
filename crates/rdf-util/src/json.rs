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

use crate::{ObjectId, Value};

use serde_json::{json, Value as JsonValue};

impl Value {
    pub fn to_json(&self) -> JsonValue {
        match self {
            Value::String(s) => json!(s),
            Value::Typed(v, t) => json!({ "@value": v, "@type": t }),
            Value::Object(map, id) => {
                let mut body = json!({});

                for (key, value) in map {
                    body[key] = value.to_json();
                }

                if let ObjectId::NamedNode(id) = id {
                    body["@id"] = json!(id);
                }

                if let ObjectId::BlankNode(id) = id {
                    if map.is_empty() {
                        body["@id"] = json!(id)
                    }
                }

                body
            }
            Value::ObjectRef(id) => match id {
                ObjectId::None => json!({}),
                ObjectId::NamedNode(id) | ObjectId::BlankNode(id) => json!({ "@id": id }),
            },
            Value::Array(arr) => json!(arr.iter().map(|v| v.to_json()).collect::<Vec<_>>()),
        }
    }
}
