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

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::fmt::Display;

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Record, PartialEq, Eq)]
pub struct OrderedMap {
    entries: Vec<MapEntry>,
}

impl OrderedMap {
    pub fn new() -> OrderedMap {
        Self {
            entries: Vec::new(),
        }
    }
    pub fn insert(&mut self, key: Value, value: Value) {
        self.entries.push(MapEntry { key, value });
    }
    pub fn get(&self, key: &Value) -> Option<&MapEntry> {
        self.entries.iter().find(|a| &a.key == key)
    }
    pub fn get_mut(&mut self, key: &Value) -> Option<&mut MapEntry> {
        self.entries.iter_mut().find(|a| &a.key == key)
    }
    pub fn contains_key(&self, key: &Value) -> bool {
        self.entries.iter().any(|a| &a.key == key)
    }
    pub fn remove(&mut self, key: &Value) -> Option<MapEntry> {
        let index = self.entries.iter().position(|a| &a.key == key)?;
        Some(self.entries.remove(index))
    }
}
impl Default for OrderedMap {
    fn default() -> Self {
        OrderedMap::new()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Record, PartialEq, Eq)]
pub struct MapEntry {
    key: Value,
    value: Value,
}

#[derive(Deserialize, Serialize, Debug, Clone, uniffi::Enum, PartialEq, Eq)]
#[serde(untagged)]
pub enum Value {
    Object(HashMap<String, Value>),
    Array(Vec<Value>),
    String(String),
    Number(JsonNumber),
    Boolean(bool),
    Tag { tag: u64, value: Vec<Value> },
    Bytes(Vec<u8>),
    Null,
    OrderedObject(OrderedMap),
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, uniffi::Enum, PartialEq)]
#[serde(untagged)]
pub enum JsonNumber {
    Integer(i64),
    Float(f64),
}
impl Eq for JsonNumber {}

impl Value {
    pub fn transform<To: for<'a> Deserialize<'a>>(&self) -> Option<To> {
        let val = serde_json::to_value(self).expect("to value failed");
        serde_json::from_value(val).unwrap()
    }
    pub fn from_serialize<From: Serialize>(obj: &From) -> Option<Self> {
        let val = serde_json::to_value(obj).ok()?;
        serde_json::from_value(val).ok()?
    }
    pub fn to_json(&self) -> Option<String> {
        let json_val: serde_json::Value = (self).into();
        serde_json::to_string(&json_val).ok()
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
    pub fn as_i64(&self) -> Option<&i64> {
        match self {
            Value::Number(JsonNumber::Integer(i)) => Some(i),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Self>> {
        match self {
            Value::Array(vec) => Some(vec),
            _ => None,
        }
    }
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Self>> {
        match self {
            Value::Array(vec) => Some(vec),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&HashMap<String, Self>> {
        match self {
            Value::Object(obj) => Some(obj),
            _ => None,
        }
    }
    pub fn as_object_mut(&mut self) -> Option<&mut HashMap<String, Self>> {
        match self {
            Value::Object(obj) => Some(obj),
            _ => None,
        }
    }
    pub fn is_object(&self) -> bool {
        matches!(self, Value::Object(..))
    }
    pub fn is_ordered_object(&self) -> bool {
        matches!(self, Value::OrderedObject(..))
    }
    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(..))
    }
    pub fn get<I: Index>(&self, i: I) -> Option<&Value> {
        i.resolve_ref(self)
    }
    pub fn get_mut<I: Index>(&mut self, i: I) -> Option<&mut Value> {
        i.resolve_mut(self)
    }
}

pub trait Index {
    fn resolve_ref<'obj_lifetime>(&self, val: &'obj_lifetime Value)
        -> Option<&'obj_lifetime Value>;
    fn resolve_mut<'obj_lifetime>(
        &self,
        val: &'obj_lifetime mut Value,
    ) -> Option<&'obj_lifetime mut Value>;
}

impl Index for usize {
    fn resolve_ref<'obj_lifetime>(
        &self,
        val: &'obj_lifetime Value,
    ) -> Option<&'obj_lifetime Value> {
        match val {
            Value::Array(arr) => match arr.get(*self) {
                Some(ele) => Some(ele),
                None => None,
            },
            _ => None,
        }
    }

    fn resolve_mut<'obj_lifetime>(
        &self,
        val: &'obj_lifetime mut Value,
    ) -> Option<&'obj_lifetime mut Value> {
        if let Value::Array(arr) = val {
            match arr.get_mut(*self) {
                Some(ele) => Some(ele),
                None => None,
            }
        } else {
            None
        }
    }
}
impl Index for &String {
    fn resolve_ref<'obj_lifetime>(
        &self,
        val: &'obj_lifetime Value,
    ) -> Option<&'obj_lifetime Value> {
        self.as_str().resolve_ref(val)
    }

    fn resolve_mut<'obj_lifetime>(
        &self,
        val: &'obj_lifetime mut Value,
    ) -> Option<&'obj_lifetime mut Value> {
        self.as_str().resolve_mut(val)
    }
}
impl Index for &str {
    fn resolve_ref<'obj_lifetime>(
        &self,
        val: &'obj_lifetime Value,
    ) -> Option<&'obj_lifetime Value> {
        match val {
            Value::Object(map) => match map.get(&self.to_string()) {
                Some(ele) => Some(ele),
                None => None,
            },
            Value::OrderedObject(map) => match map.get(&Value::String(self.to_string())) {
                Some(ele) => Some(&ele.value),
                None => None,
            },
            _ => None,
        }
    }

    fn resolve_mut<'obj_lifetime>(
        &self,
        val: &'obj_lifetime mut Value,
    ) -> Option<&'obj_lifetime mut Value> {
        match val {
            Value::Object(map) => match map.get_mut(&self.to_string()) {
                Some(ele) => Some(ele),
                None => None,
            },
            Value::OrderedObject(map) => match map.get_mut(&Value::String(self.to_string())) {
                Some(ele) => Some(&mut ele.value),
                None => None,
            },
            _ => None,
        }
    }
}

impl From<JsonValue> for Value {
    fn from(value: JsonValue) -> Self {
        serde_json::from_value(value).unwrap_or(Value::Null)
    }
}
impl From<&JsonValue> for Value {
    fn from(value: &JsonValue) -> Self {
        serde_json::from_value(value.clone()).unwrap_or(Value::Null)
    }
}

impl From<&Value> for JsonValue {
    fn from(value: &Value) -> Self {
        serde_json::to_value(value).unwrap_or_else(|_| JsonValue::Null)
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            serde_json::to_string(self)
                .map_err(|_| std::fmt::Error)?
                .as_str(),
        )
    }
}
use ciborium::Value as CborValue;

impl From<Value> for CborValue {
    fn from(value: Value) -> Self {
        match value {
            Value::Object(inner) => CborValue::Map(
                inner
                    .into_iter()
                    .map(|(key, value)| (CborValue::Text(key), CborValue::from(value)))
                    .collect::<Vec<_>>(),
            ),
            Value::Array(inner) => {
                CborValue::Array(inner.into_iter().map(CborValue::from).collect())
            }
            Value::String(t) => CborValue::Text(t),
            Value::Number(JsonNumber::Integer(i)) => CborValue::Integer(i.into()),
            Value::Number(JsonNumber::Float(f)) => CborValue::Float(f),
            Value::Boolean(b) => CborValue::Bool(b),
            Value::Tag { tag, value } if value.len() == 1 => {
                CborValue::Tag(tag, Box::new(CborValue::from(value[0].clone())))
            }
            Value::Bytes(b) => CborValue::Bytes(b),
            Value::Null => CborValue::Null,
            Value::OrderedObject(inner) => CborValue::Map(
                inner
                    .entries
                    .into_iter()
                    .map(|MapEntry { key, value }| (CborValue::from(key), CborValue::from(value)))
                    .collect(),
            ),
            _ => CborValue::Null,
        }
    }
}

impl From<CborValue> for Value {
    fn from(value: CborValue) -> Self {
        match value {
            CborValue::Integer(i) => {
                let i: i128 = i.into();
                Value::Number(JsonNumber::Integer(i as i64))
            }
            CborValue::Bytes(b) => Value::Bytes(b.clone()),
            CborValue::Float(f) => Value::Number(JsonNumber::Float(f)),
            CborValue::Text(t) => Value::String(t),
            CborValue::Bool(b) => Value::Boolean(b),
            CborValue::Null => Value::Null,
            CborValue::Tag(t, v) => Value::Tag {
                tag: t,
                value: vec![Value::from(*v)],
            },
            CborValue::Array(a) => {
                Value::Array(a.into_iter().map(|inner| inner.into()).collect::<Vec<_>>())
            }
            CborValue::Map(m) => Value::OrderedObject(OrderedMap {
                entries: m
                    .into_iter()
                    .map(|(k, v)| MapEntry {
                        key: k.into(),
                        value: v.into(),
                    })
                    .collect::<Vec<_>>(),
            }),
            _ => Value::Null,
        }
    }
}
impl AsRef<Value> for Value {
    fn as_ref(&self) -> &Value {
        self
    }
}
