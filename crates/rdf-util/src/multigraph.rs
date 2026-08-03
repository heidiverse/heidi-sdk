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

use std::collections::{HashMap, HashSet};

use oxrdf::{Dataset, GraphName, Quad, Subject, Term, Triple};

use crate::Value;

#[derive(Debug, Clone)]
pub struct MultiGraph {
    pub(crate) quads: Vec<Quad>,
}

impl MultiGraph {
    pub fn new(dataset: &Dataset) -> Self {
        let quads = dataset
            .into_iter()
            .map(|q| q.into_owned())
            .collect::<Vec<_>>();
        Self { quads }
    }

    pub fn graphs(&self) -> HashMap<GraphName, Vec<Quad>> {
        let graph_names = self
            .quads
            .iter()
            .map(|quad| quad.graph_name.clone())
            .collect::<HashSet<_>>();

        let mut graphs = HashMap::<GraphName, Vec<Quad>>::new();

        for name in graph_names {
            let quads = self
                .quads
                .iter()
                .filter_map(|q| (q.graph_name == name).then_some(q.clone()))
                .collect::<Vec<_>>();
            graphs.insert(name, quads);
        }

        for (name, quads) in &graphs {
            println!("{name}:");
            for quad in quads {
                println!("{quad}");
            }
            println!()
        }

        graphs
    }

    pub fn to_value(&self, root: GraphName) -> Value {
        let graphs = self.graphs();

        let root = graphs.get(&root).unwrap()[0].subject.clone();

        let mut map = HashMap::<GraphName, Subject>::new();
        for (n, q) in &graphs {
            let root = get_root(q).unwrap();
            map.insert(n.clone(), root.subject);
        }
        let map = &map;

        let triplets = self
            .quads
            .iter()
            .cloned()
            .map(move |q| Triple {
                subject: q.subject,
                predicate: q.predicate,
                object: match &q.object {
                    Term::Literal(_) => q.object,
                    Term::BlankNode(b) => {
                        if let Some(s) = map.get(&GraphName::BlankNode(b.clone())) {
                            match s.clone() {
                                Subject::BlankNode(b) => Term::BlankNode(b),
                                Subject::NamedNode(n) => Term::NamedNode(n),
                            }
                        } else {
                            q.object
                        }
                    }
                    Term::NamedNode(n) => {
                        if let Some(s) = map.get(&GraphName::NamedNode(n.clone())) {
                            match s.clone() {
                                Subject::BlankNode(b) => Term::BlankNode(b),
                                Subject::NamedNode(n) => Term::NamedNode(n),
                            }
                        } else {
                            q.object
                        }
                    }
                },
            })
            .collect::<Vec<_>>();

        Value::from((triplets, root))
    }

    pub fn dataset(&self) -> Dataset {
        Dataset::from_iter(&self.quads)
    }
}

fn get_root(quads: &Vec<Quad>) -> Option<Quad> {
    let mut roots = quads.clone();
    for object in quads {
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
    roots.first().cloned()
}
