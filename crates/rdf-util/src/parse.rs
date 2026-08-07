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
    collections::{BTreeMap, HashSet},
    str::FromStr,
};

use oxrdf::{vocab::xsd, Dataset, Graph, Subject, Term, Triple};
use oxttl::{NQuadsParser, NTriplesParser, TurtleParseError};

use crate::{value::ObjectId, MultiGraph, Value};

pub fn parse_triples<S: AsRef<str>>(str: S) -> Result<Vec<Triple>, TurtleParseError> {
    NTriplesParser::new()
        .for_reader(str.as_ref().as_bytes())
        .collect::<Result<Vec<_>, _>>()
}

pub fn from_str<S: AsRef<str>>(str: S) -> Result<Value, TurtleParseError> {
    Ok(Value::from(parse_triples(str)?))
}

pub fn from_str_with_hint<S: AsRef<str>>(str: S, hint: Subject) -> Result<Value, TurtleParseError> {
    Ok(Value::from((parse_triples(str)?, hint)))
}

pub fn dataset_from_str<S: AsRef<str>>(str: S) -> Result<Dataset, TurtleParseError> {
    Ok(Dataset::from_iter(
        NQuadsParser::new()
            .for_reader(str.as_ref().as_bytes())
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

fn to_value(subject: Subject, triples: &Vec<Triple>, processed: &mut HashSet<Subject>) -> Value {
    if processed.contains(&subject) {
        return Value::ObjectRef(match subject {
            Subject::NamedNode(n) => ObjectId::NamedNode(n.as_str().to_owned()),
            Subject::BlankNode(b) => ObjectId::BlankNode(b.as_str().to_owned()),
        });
    }
    processed.insert(subject.clone());

    let mut map = BTreeMap::<String, Value>::new();

    for triple in triples {
        if triple.subject != subject {
            continue;
        }

        let key = triple.predicate.as_str().to_owned();
        let value = match &triple.object {
            Term::Literal(l) => {
                if l.datatype() == xsd::STRING {
                    Value::String(l.value().to_owned())
                } else {
                    Value::Typed(l.value().to_owned(), l.datatype().as_str().to_owned())
                }
            }
            Term::BlankNode(b) => to_value(Subject::BlankNode(b.clone()), triples, processed),
            Term::NamedNode(n) => to_value(Subject::NamedNode(n.clone()), triples, processed),
        };

        if let Some(old) = map.remove(&key) {
            let mut array = match old {
                Value::Array(arr) => arr,
                _ => vec![old],
            };
            array.push(value);

            map.insert(key, Value::Array(array));
        } else {
            map.insert(key, value);
        }
    }

    let id = match subject {
        Subject::NamedNode(n) => ObjectId::NamedNode(n.as_str().to_owned()),
        Subject::BlankNode(b) => ObjectId::BlankNode(b.as_str().to_owned()),
    };

    Value::Object(map, id)
}

fn from_triples(triples: Vec<Triple>, root_hint: Option<Subject>) -> anyhow::Result<Value> {
    let roots = if let Some(root) = root_hint {
        triples
            .iter()
            .filter(|t| t.subject == root)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        let mut roots = triples.clone();
        for object in &triples {
            match &object.object {
                Term::Literal(_) => continue,
                Term::BlankNode(b1) => roots.retain(|r| match &r.subject {
                    Subject::BlankNode(b2) => b1 != b2,
                    _ => true,
                }),
                Term::NamedNode(n1) => roots.retain(|r| match &r.subject {
                    Subject::NamedNode(n2) => n1 != n2,
                    _ => true,
                }),
            }
        }
        roots
    };

    anyhow::ensure!(!roots.is_empty(), "No roots found!");

    let root_id = roots
        .iter()
        .map(|t| t.subject.clone())
        .collect::<HashSet<_>>();

    anyhow::ensure!(root_id.len() == 1, "Multiple possible roots!");

    let root_id = root_id.into_iter().next().unwrap();

    Ok(to_value(root_id, &triples, &mut HashSet::new()))
}

impl From<Vec<Triple>> for Value {
    fn from(triples: Vec<Triple>) -> Self {
        from_triples(triples, None).unwrap()
    }
}

impl From<(Vec<Triple>, Subject)> for Value {
    fn from(value: (Vec<Triple>, Subject)) -> Self {
        let (triples, hint) = value;
        from_triples(triples, Some(hint)).unwrap()
    }
}

impl From<Graph> for Value {
    fn from(value: Graph) -> Self {
        let triples = value
            .iter()
            .map(|t| t.into_owned())
            .collect::<Vec<Triple>>();
        Self::from(triples)
    }
}

impl From<&Graph> for Value {
    fn from(value: &Graph) -> Self {
        let triples = value
            .iter()
            .map(|t| t.into_owned())
            .collect::<Vec<Triple>>();
        Self::from(triples)
    }
}

impl FromStr for MultiGraph {
    type Err = TurtleParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let quads = NQuadsParser::new()
            .for_reader(s.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { quads })
    }
}
