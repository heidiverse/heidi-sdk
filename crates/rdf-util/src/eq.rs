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

impl<S> PartialEq<S> for Value
where
    S: AsRef<str>,
{
    fn eq(&self, other: &S) -> bool {
        match self {
            Value::String(s) => s == other.as_ref(),
            _ => false,
        }
    }
}

impl<S> PartialEq<S> for ObjectId
where
    S: AsRef<str>,
{
    fn eq(&self, other: &S) -> bool {
        let other = other.as_ref();
        match self {
            ObjectId::None => false,
            ObjectId::BlankNode(n) | ObjectId::NamedNode(n) => n == other,
        }
    }
}
