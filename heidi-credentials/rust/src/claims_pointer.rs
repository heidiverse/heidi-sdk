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

use std::fmt::{Display, Formatter};

use crate::models::{Pointer, PointerPart};
use heidi_util_rust::value::Value;

#[derive(Debug, uniffi::Error)]
pub enum QueryError {
    InvalidType,
    InvalidIndex,
    NoElementsFound,
}
impl Display for QueryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("{self:?}")
    }
}
#[uniffi::export(with_foreign)]
pub trait Selector: Send + Sync {
    fn select(&self, v: Value) -> Result<Vec<Value>, QueryError>;
    fn resolve_ptr(&self, v: Value) -> Result<Vec<Pointer>, QueryError>;
}

impl Selector for Pointer {
    fn select(&self, v: Value) -> Result<Vec<Value>, QueryError> {
        let s = selector(self);
        s(&v)
    }

    fn resolve_ptr(&self, v: Value) -> Result<Vec<Pointer>, QueryError> {
        let mut current_pointers = vec![vec![]];
        let mut the_pointer = vec![];
        for p in self {
            match p {
                PointerPart::Null(_) => {
                    let element = the_pointer.select(v.clone())?;
                    if element.len() > 1 || element.is_empty() {
                        return Ok(vec![]);
                    }
                    if !element[0].is_array() {
                        return Ok(vec![]);
                    }
                    let element_size = element[0].as_array().unwrap().len();
                    let mut new_pointers = vec![];
                    for ptrs in &current_pointers {
                        for i in 0..element_size {
                            let mut p = ptrs.clone();
                            p.push(PointerPart::Index(i as u64));
                            new_pointers.push(p)
                        }
                    }
                    current_pointers = new_pointers;
                }
                _ => {
                    for ptr in &mut current_pointers {
                        ptr.push(p.clone())
                    }
                }
            }
            the_pointer.push(p.clone());
            let _ = the_pointer.select(v.clone())?;
        }
        Ok(current_pointers)
    }
}

pub fn selector(path: &Pointer) -> impl Fn(&Value) -> Result<Vec<Value>, QueryError> + '_ {
    move |input| {
        let mut currently_selected = vec![input.clone()];
        for part in path {
            match part {
                crate::models::PointerPart::String(key)
                    if currently_selected
                        .iter()
                        .all(|a| a.is_object() || a.is_ordered_object()) =>
                {
                    currently_selected = currently_selected
                        .iter()
                        .flat_map(|a| a.get(key))
                        .cloned()
                        .collect()
                }
                crate::models::PointerPart::Index(i)
                    if currently_selected.iter().all(|a| a.is_array()) =>
                {
                    currently_selected = currently_selected
                        .iter()
                        .flat_map(|a| a.get(*i as usize))
                        .cloned()
                        .collect()
                }
                crate::models::PointerPart::Null(_)
                    if currently_selected.iter().all(|a| a.is_array()) =>
                {
                    currently_selected = currently_selected
                        .iter()
                        .filter_map(|a| a.as_array())
                        .flatten()
                        .cloned()
                        .collect()
                }
                _ => return Err(QueryError::InvalidType),
            }
            if currently_selected.is_empty() {
                return Err(QueryError::NoElementsFound);
            }
        }
        Ok(currently_selected)
    }
}

#[macro_export]
macro_rules! pointer {
    ($($e:expr),+) => {
        vec![$(
            $crate::models::PointerPart::from($e),
        )*
        ]
    };
}

#[cfg(test)]
mod tests {
    use crate::{claims_pointer::QueryError, models::PointerPart};

    use super::selector;

    #[test]
    pub fn test_empty() {
        let data = serde_json::json!({
            "test" : [{
                "name" : ["a", "c"]
            },{
                "name" : ["b", "d"]
            }]
        });
        let query0: Vec<PointerPart> =
            serde_json::from_str(r#"["test", null, "name", 4, "a"]"#).unwrap();
        let s1 = selector(&query0);
        let err = s1(&data.into()).unwrap_err();
        assert!(matches!(dbg!(err), QueryError::NoElementsFound))
    }
    #[test]
    pub fn test_invalid_type() {
        let data = serde_json::json!({
            "test" : [{
                "name" : ["a", "c"]
            },{
                "name" : ["b", "d"]
            }]
        });
        let query0: Vec<PointerPart> =
            serde_json::from_str(r#"["test", null, 0, 1, "a"]"#).unwrap();
        let s1 = selector(&query0);
        let err = s1(&data.into()).unwrap_err();
        assert!(matches!(dbg!(err), QueryError::InvalidType))
    }
    #[test]
    pub fn test_null_only_array() {
        let data = serde_json::json!({
            "test" : [{
                "name" : ["a", "c"]
            },{
                "name" : ["b", "d"]
            }]
        });
        let query0: Vec<PointerPart> =
            serde_json::from_str(r#"["test", null, null, 1, "a"]"#).unwrap();
        let s1 = selector(&query0);
        let err = s1(&data.into()).unwrap_err();
        assert!(matches!(dbg!(err), QueryError::InvalidType))
    }

    #[test]
    fn simple_test() {
        let data = serde_json::json!({
            "test" : [{
                "name" : ["a", "c"]
            },{
                "name" : ["b", "d"]
            }]
        });
        let pointer = vec![
            PointerPart::String("test".to_string()),
            PointerPart::Null(None),
            PointerPart::String("name".to_string()),
            PointerPart::Index(0),
        ];
        let s = selector(&pointer);
        let result = s(&data.into()).unwrap();
        let a = result[0].as_str().unwrap();
        let b = result[1].as_str().unwrap();
        assert_eq!(a, "a");
        assert_eq!(b, "b");
    }

    #[test]
    pub fn test_from_string() {
        let query: Vec<PointerPart> = serde_json::from_str(r#"["test", null, "name", 0]"#).unwrap();
        let pointer = vec![
            PointerPart::String("test".to_string()),
            PointerPart::Null(None),
            PointerPart::String("name".to_string()),
            PointerPart::Index(0),
        ];
        assert_eq!(query, pointer);
    }

    #[test]
    pub fn nested_arrays() {
        let query0: Vec<PointerPart> =
            serde_json::from_str(r#"["test", null, 0, null, "a"]"#).unwrap();
        let query1: Vec<PointerPart> =
            serde_json::from_str(r#"["test", null, 1, null, "a"]"#).unwrap();
        let data = serde_json::json!({
            "test" : [
                [
                    [
                        {"a": "test1"},
                        {"a": "test2"}
                    ],
                    [
                        {"a": "test3"},
                        {"a": "test4"}
                    ]
                ],[
                    [
                        {"a": "test1"},
                        {"a": "test2"}
                    ],
                    [
                        {"a": "test3"},
                        {"a": "test4"}
                    ]
                ]
            ]
        });

        let s1 = selector(&query0);
        let s2 = selector(&query1);

        let result1 = s1(&data.clone().into()).unwrap();
        let result2 = s2(&data.into()).unwrap();

        assert_eq!(result1[0].as_str().unwrap(), "test1");
        assert_eq!(result1[1].as_str().unwrap(), "test2");
        assert_eq!(result1[2].as_str().unwrap(), "test1");
        assert_eq!(result1[3].as_str().unwrap(), "test2");

        println!("{result2:?}");
        assert_eq!(result2[0].as_str().unwrap(), "test3");
        assert_eq!(result2[1].as_str().unwrap(), "test4");
        assert_eq!(result2[2].as_str().unwrap(), "test3");
        assert_eq!(result2[3].as_str().unwrap(), "test4");

        assert_eq!(result1.len(), 4);
        assert_eq!(result2.len(), 4);
    }
}
