/* Copyright 2024 Ubique Innovation AG

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

//! Helper functions for the mdoc format
use anyhow::{ensure, Context};
use ciborium::Value;

use crate::ApiError;

pub trait CBorHelper {
    /// Treats this object as a map, returns the corresponding value to: Value::Text(key)
    fn get(&self, key: &str) -> anyhow::Result<&Value>;

    /// Treats this object as a tag, verifies if the found tag matches the expected one
    fn as_expect_tag(&self, expected: u64) -> anyhow::Result<&Value>;

    fn to_json_value(&self) -> Option<serde_json::Value>;
}

impl CBorHelper for Value {
    fn get(&self, key: &str) -> anyhow::Result<&Value> {
        let key_value = Value::Text(key.to_owned());

        let Value::Map(map) = self else {
            anyhow::bail!("Is not a map!")
        };

        map.iter()
            .find_map(|(k, v)| (k == &key_value).then_some(v))
            .context(format!("Does not contain key: {key}"))
    }

    fn as_expect_tag(&self, expected: u64) -> anyhow::Result<&Value> {
        let Value::Tag(tag, value) = self else {
            anyhow::bail!("");
        };
        ensure!(*tag == expected, "Doesn't match expected tag");

        Ok(value)
    }

    fn to_json_value(&self) -> Option<serde_json::Value> {
        use serde_json::Number;
        use serde_json::Value as JsonValue;

        match self {
            Value::Integer(i) => {
                let value: i128 = (*i).into();
                // f64 hold bigger ranges that i128, so should be safe
                Some(JsonValue::Number(Number::from_f64(value as f64)?))
            }
            Value::Bytes(arr) => Some(JsonValue::Array(
                arr.iter()
                    .map(|x| JsonValue::Number(Number::from(*x)))
                    .collect(),
            )),
            Value::Float(f) => Some(JsonValue::Number(Number::from_f64(*f)?)),
            Value::Text(str) => Some(JsonValue::String(str.clone())),
            Value::Bool(bool) => Some(JsonValue::Bool(*bool)),
            Value::Null => Some(JsonValue::Null),
            Value::Tag(tag, value) => match *tag {
                24 => {
                    let bytes = (*value).as_bytes()?;
                    deserialize(bytes).ok()?.to_json_value()
                }
                _ => (*value).to_json_value(),
            },
            Value::Array(arr) => Some(JsonValue::Array(
                arr.iter()
                    .map(|v| v.to_json_value())
                    .collect::<Option<Vec<JsonValue>>>()?,
            )),
            Value::Map(map) => Some(JsonValue::Object(
                map.iter()
                    .map(|(k, v)| Some((k.clone().as_text()?.to_owned(), v.to_json_value()?)))
                    .collect::<Option<serde_json::Map<String, JsonValue>>>()?,
            )),
            _ => unreachable!(),
        }
    }
}

pub fn deserialize(bytes: &[u8]) -> Result<Value, ApiError> {
    ciborium::from_reader(bytes).map_err(|e| e.into())
}

pub fn serialize(value: &Value) -> Result<Vec<u8>, ApiError> {
    let mut bytes = Vec::<u8>::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}
