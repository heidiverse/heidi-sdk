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

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use oxrdf::{BlankNode, Graph, Literal, NamedNode, NamedOrBlankNode, Subject, Term, Triple};
use serde::{Deserialize, Serialize};

use crate::{index::Index, BlankGenerator};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectId {
    /// No explicit id set.
    ///
    /// The expected behaviour of `ObjectId::None` is that generally
    /// the exact blank id that the object will get doesn't matter,
    /// the only thing that matters is that the object will be placed
    /// at the correct spot.
    None,

    /// Set a specific blank id. For example, `"b0"`.
    BlankNode(String),

    /// Set a specific named node.
    /// For example, `"https://example.org/credentials/0"`.
    NamedNode(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    String(String),
    Typed(String, String),
    Object(BTreeMap<String, Value>, ObjectId),
    ObjectRef(ObjectId),
    Array(Vec<Value>),
}

impl Value {
    pub fn get<I: Index>(&self, index: I) -> Option<&Value> {
        index.index_into(self)
    }

    pub fn get_mut<I: Index>(&mut self, index: I) -> Option<&mut Value> {
        index.index_or_insert(self)
    }

    pub fn as_string(&self) -> Option<&String> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_string_mut(&mut self) -> Option<&mut String> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_typed(&self) -> Option<(&String, &String)> {
        match self {
            Self::Typed(value, datatype) => Some((value, datatype)),
            _ => None,
        }
    }

    pub fn as_typed_mut(&mut self) -> Option<(&mut String, &mut String)> {
        match self {
            Self::Typed(value, datatype) => Some((value, datatype)),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<(&BTreeMap<String, Value>, &ObjectId)> {
        match self {
            Value::Object(m, id) => Some((m, id)),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<(&mut BTreeMap<String, Value>, &mut ObjectId)> {
        match self {
            Value::Object(m, id) => Some((m, id)),
            _ => None,
        }
    }

    pub fn as_object_ref(&self) -> Option<&ObjectId> {
        match self {
            Self::ObjectRef(id) => Some(id),
            _ => None,
        }
    }

    pub fn as_object_ref_mut(&mut self) -> Option<&mut ObjectId> {
        match self {
            Self::ObjectRef(id) => Some(id),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Self::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Self::Array(arr) => Some(arr),
            _ => None,
        }
    }

    pub fn id(&self) -> Option<&ObjectId> {
        match self {
            Self::Object(_, id) | Self::ObjectRef(id) => Some(id),
            _ => None,
        }
    }

    pub fn id_mut(&mut self) -> Option<&mut ObjectId> {
        match self {
            Self::Object(_, id) | Self::ObjectRef(id) => Some(id),
            _ => None,
        }
    }

    pub fn to_string_with_prefix(&self, prefix: String) -> String {
        self.to_graph(Some(prefix)).to_string()
    }

    pub fn to_graph(&self, prefix: Option<String>) -> Graph {
        fn transform_id(
            id: &ObjectId,
            gen: &mut BlankGenerator,
            prefix: &String,
        ) -> NamedOrBlankNode {
            match id {
                ObjectId::None => {
                    NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(gen.next(prefix)))
                }
                ObjectId::BlankNode(b) => NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(b)),
                ObjectId::NamedNode(n) => NamedOrBlankNode::NamedNode(NamedNode::new_unchecked(n)),
            }
        }

        fn process<'a>(
            value: &'a Value,
            next: &mut Vec<(NamedOrBlankNode, &'a BTreeMap<String, Value>)>,
            gen: &mut BlankGenerator,
            prefix: &String,
        ) -> Vec<Term> {
            match value {
                Value::String(s) => vec![Term::Literal(Literal::new_simple_literal(s))],
                Value::Typed(v, t) => vec![Term::Literal(Literal::new_typed_literal(
                    v,
                    NamedNode::new_unchecked(t),
                ))],
                Value::Object(m, id) => {
                    let id = transform_id(id, gen, prefix);

                    next.push((id.clone(), m));

                    vec![match id {
                        NamedOrBlankNode::BlankNode(b) => Term::BlankNode(b),
                        NamedOrBlankNode::NamedNode(n) => Term::NamedNode(n),
                    }]
                }
                Value::ObjectRef(id) => {
                    let id = transform_id(id, gen, prefix);
                    vec![match id {
                        NamedOrBlankNode::BlankNode(b) => Term::BlankNode(b),
                        NamedOrBlankNode::NamedNode(n) => Term::NamedNode(n),
                    }]
                }
                Value::Array(arr) => arr
                    .iter()
                    .flat_map(|v| process(v, next, gen, prefix))
                    .collect::<Vec<_>>(),
            }
        }

        let prefix = prefix.unwrap_or("b".to_string());
        let mut gen = BlankGenerator::init(self);

        let mut maps = match self {
            Value::Object(m, id) => {
                vec![(transform_id(id, &mut gen, &prefix), m)]
            }
            _ => Vec::new(),
        };
        let mut triples = Vec::<Triple>::new();

        while !maps.is_empty() {
            let mut next = Vec::new();

            for (id, map) in maps {
                for (k, v) in map {
                    let subject = match id.clone() {
                        NamedOrBlankNode::BlankNode(b) => Subject::BlankNode(b),
                        NamedOrBlankNode::NamedNode(n) => Subject::NamedNode(n),
                    };
                    let predicate = NamedNode::new_unchecked(k);

                    for object in process(v, &mut next, &mut gen, &prefix) {
                        triples.push(Triple {
                            subject: subject.clone(),
                            predicate: predicate.clone(),
                            object,
                        });
                    }
                }
            }

            maps = next;
        }

        Graph::from_iter(triples)
    }

    pub(crate) fn taken_blank_ids(&self) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();

        match self {
            Value::Array(arr) => {
                for value in arr {
                    ids.extend(value.taken_blank_ids());
                }
            }
            Value::Object(m, ObjectId::BlankNode(id)) => {
                ids.insert(id.clone());

                for value in m.values() {
                    ids.extend(value.taken_blank_ids());
                }
            }
            Value::Object(m, _) => {
                for value in m.values() {
                    ids.extend(value.taken_blank_ids());
                }
            }
            Value::ObjectRef(ObjectId::BlankNode(id)) => {
                ids.insert(id.clone());
            }
            Value::ObjectRef(_) => (),
            Value::String(_) => (),
            Value::Typed(_, _) => (),
        }

        ids
    }

    pub fn to_term_value(&self) -> Option<Term> {
        match self {
            Value::String(s) => Some(Term::Literal(Literal::new_simple_literal(s))),
            Value::Typed(v, t) => Some(Term::Literal(Literal::new_typed_literal(
                v,
                NamedNode::new_unchecked(t),
            ))),
            _ => None,
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_with_prefix("b".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::{ObjectId, Value};

    #[test]
    fn test_used_ids() {
        assert_eq!(
            Value::String("".into()).taken_blank_ids(),
            BTreeSet::from([])
        );

        assert_eq!(
            Value::Typed("".into(), "".into()).taken_blank_ids(),
            BTreeSet::from([])
        );

        assert_eq!(
            Value::Object(BTreeMap::from([]), ObjectId::None).taken_blank_ids(),
            BTreeSet::from([])
        );

        assert_eq!(
            Value::Object(BTreeMap::from([]), ObjectId::BlankNode("b0".into())).taken_blank_ids(),
            BTreeSet::from(["b0".into()])
        );

        assert_eq!(
            Value::Object(BTreeMap::from([]), ObjectId::NamedNode("asdf".into())).taken_blank_ids(),
            BTreeSet::from([])
        );

        assert_eq!(
            Value::ObjectRef(ObjectId::None).taken_blank_ids(),
            BTreeSet::from([])
        );

        assert_eq!(
            Value::ObjectRef(ObjectId::BlankNode("b0".into())).taken_blank_ids(),
            BTreeSet::from(["b0".into()])
        );

        assert_eq!(
            Value::ObjectRef(ObjectId::NamedNode("asdf".into())).taken_blank_ids(),
            BTreeSet::from([])
        );
    }
}
