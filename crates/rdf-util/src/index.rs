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

use crate::Value;

pub trait Index {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value>;
    fn index_or_insert<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value>;
}

impl Index for str {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        match v {
            Value::Object(map, _) => map.get(self),
            _ => None,
        }
    }

    fn index_or_insert<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value> {
        match v {
            Value::Object(map, _) => Some(
                map.entry(self.to_owned())
                    .or_insert(Value::String(String::new())),
            ),
            _ => None,
        }
    }
}

impl<S> Index for S
where
    S: AsRef<str>,
{
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        self.as_ref().index_into(v)
    }

    fn index_or_insert<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value> {
        self.as_ref().index_or_insert(v)
    }
}

impl<I> std::ops::Index<I> for Value
where
    I: Index,
{
    type Output = Value;

    fn index(&self, index: I) -> &Self::Output {
        index.index_into(self).unwrap()
    }
}

impl<I> std::ops::IndexMut<I> for Value
where
    I: Index,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        index.index_or_insert(self).unwrap()
    }
}
