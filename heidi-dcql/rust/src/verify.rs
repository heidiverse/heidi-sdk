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

use std::sync::Arc;
use uniffi::Object;

#[derive(Object)]
pub struct PossumExpression {
    expression: jlc::Expression
}

#[uniffi::export]
impl PossumExpression {
    #[uniffi::constructor]
    pub fn from_str(str: &str) -> Arc<Self> {
        let Ok(expression) = jlc::arithmetic::expression(str) else {
            return Arc::new(Self {
                expression: jlc::Expression::Atomic(jlc::Value::Null)
            })
        };
        Arc::new(Self {
            expression
        })
    }
    pub fn evaluate(self: &Arc<Self>, data: &str) -> Arc<Self> {
        let Ok(data) = serde_json::from_str(data) else {
            return Arc::new(PossumExpression {
                expression: jlc::Expression::Atomic(jlc::Value::Null)
            });
        };
        Arc::new(
            Self {
                expression: self.expression.eval(&data).unwrap_or(jlc::Expression::Atomic(jlc::Value::Null))
            }
        )
    }
    pub fn is_truthy(self: &Arc<Self>) -> bool {
        self.expression.as_bool().unwrap_or(false)
    }
    pub fn is_null(self: &Arc<Self>) -> bool {
        matches!(self.expression, jlc::Expression::Atomic(jlc::Value::Null))
    }
    pub fn as_json(self: &Arc<Self>) -> Option<String> {
      if let jlc::Expression::Atomic(v) = &self.expression {
          Some(v.to_serde_json().to_string())
      }  else {
          None
      }
    }
}
