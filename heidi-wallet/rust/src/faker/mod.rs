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

//! This module covers the implementation of the untraceability feature. By defining how to issue fake
//! requests, it allows the wallet to mimic actual usage, when in fact nothing happens. Currently we only
//! hide traffic towards the cloud HSM. In the future one could think of also issuing fake requests towards
//! verifying parties.

use crate::get_default_client;
use crate::unix_timestamp;
use rand::distributions::{Alphanumeric, Distribution};
use rand::Rng;
use rand_distr::Poisson;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use uniffi::Object;

#[derive(Object)]
/// Expose the faker object to the wallets
pub struct Faker {
    sequences: Vec<Sequence>,
    client: Client,
}

#[uniffi::export(async_runtime = "tokio")]
impl Faker {
    #[uniffi::constructor]
    /// indicating the base_url used for the fake requests. Currently we only support the cloud hsm part.
    pub fn new(base_url: String) -> Self {
        let mut sequences: Vec<Sequence> = Vec::new();

        let presentation_sequence = Sequence {
            name: "presentation".to_string(),
            steps: vec![
                SequenceStep::new(
                    format!("{}/batch/sign-device-auth", base_url).as_str(),
                    Method::POST,
                    Box::new(|step| {
                        json!({
                            "uuid": uuid::Uuid::new_v4().to_string(),
                            "pinNonce": step.generate_random_string(16),
                            "userPinSignedNonce": step.generate_random_string(64),
                            "walletAuthSignedNonce": step.generate_random_string(64),
                            "deviceAuthHash": step.generate_random_string(32),
                            "keyId": step.generate_random_string(8),
                            "isFake": 1,
                        })
                    }),
                    None,
                ),
                SequenceStep::new(
                    format!("{}/batch/sign-batch-pops", base_url).as_str(),
                    Method::POST,
                    Box::new(|step| {
                        json!({
                            "uuid": uuid::Uuid::new_v4().to_string(),
                            "pinNonce": step.generate_random_string(16),
                            "userPinSignedNonce": step.generate_random_string(64),
                            "walletAuthSignedNonce": step.generate_random_string(64),
                            "hashedPoPs": [
                                step.generate_random_string(32),
                            ],
                            "isFake": 1,
                        })
                    }),
                    Some((5, 10)),
                ),
            ],
            probability: 0.5,
            min_duration: 2 * 24 * 60 * 60 * 1000, // 2 days in milliseconds
        };

        sequences.push(presentation_sequence);

        Faker {
            sequences,
            client: get_default_client(),
        }
    }

    /// Sample from a poisson distribution, to decide if we should initiate a fake request. The possion distribution
    /// models a process having a fixed mean rate with events being independent of the last time. We keep the last_timestamps since
    /// we sample from the interval [0, timestamp]. If event_count is larger than 0, we issue an event.
    #[allow(clippy::unwrap_used)]
    pub async fn do_requests(
        self: &Arc<Self>,
        last_timestamps: HashMap<String, u64>,
    ) -> HashMap<String, u64> {
        let mut new_timestamps = last_timestamps.into_iter().collect::<HashMap<_, _>>();

        for sequence in &self.sequences {
            let poisson = Poisson::new(sequence.probability).unwrap();
            let event_count = poisson.sample(&mut rand::thread_rng());

            if event_count > 0.0 {
                let now_millis = unix_timestamp!(ms) as u64;
                let last_timestamp = new_timestamps
                    .get(&sequence.name)
                    .cloned()
                    .unwrap_or_else(|| now_millis - sequence.min_duration - 1);

                if now_millis - last_timestamp >= sequence.min_duration {
                    for step in &sequence.steps {
                        let payload = (step.payload_generator)(step);

                        let request_builder = self
                            .client
                            .request(step.method.clone(), &step.url)
                            .json(&payload);

                        let response = request_builder.send().await;

                        match response {
                            Ok(resp) => {
                                let status = resp.status();
                                if !status.is_success() {
                                    let body = resp.text().await.unwrap_or_else(|_| {
                                        "Failed to read response body".to_string()
                                    });
                                    eprintln!(
                                        "Error sending request to {}: Status: {}, Body: {}",
                                        step.url, status, body
                                    );
                                } else {
                                    println!("Sent request to {}: {:?}", step.url, resp);
                                }
                            }
                            Err(err) => {
                                eprintln!("Error sending request to {}: {:?}", step.url, err)
                            }
                        }

                        if let Some((min, max)) = step.wait_interval {
                            let wait_seconds = step.generate_random_interval(min, max);
                            sleep(Duration::from_secs(wait_seconds)).await;
                        }
                    }

                    new_timestamps.insert(sequence.name.clone(), now_millis);
                }
            }
        }

        new_timestamps
    }
}

/// Defines a process sequence with a certain expected amount of events [probability] in the defined interval.
struct Sequence {
    name: String,
    steps: Vec<SequenceStep>,
    probability: f64,
    min_duration: u64,
}

/// One step in the process. A process consists of 1 or more [SequenceStep]s
struct SequenceStep {
    url: String,
    method: Method,
    payload_generator: Box<dyn Fn(&SequenceStep) -> Value + Send + Sync>,
    wait_interval: Option<(u64, u64)>,
}

impl SequenceStep {
    fn new(
        url: &str,
        method: Method,
        payload_generator: Box<dyn Fn(&SequenceStep) -> Value + Send + Sync>,
        wait_interval: Option<(u64, u64)>,
    ) -> Self {
        Self {
            url: url.to_string(),
            method,
            payload_generator,
            wait_interval,
        }
    }

    fn generate_random_string(&self, length: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    fn generate_random_interval(&self, min: u64, max: u64) -> u64 {
        let mut rng = rand::thread_rng();
        rng.gen_range(min..=max)
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn test_do_requests() {
    // Initialize Faker with a known sequence
    let faker = Arc::new(Faker::new("https://example.com".to_string()));

    let mut last_timestamps = HashMap::new();
    let now_millis = (unix_timestamp!(ms) as u64) - 2 * 24 * 60 * 60 * 1000; // 2 days in milliseconds

    last_timestamps.insert("presentation".to_string(), now_millis);

    let new_timestamps = faker.do_requests(last_timestamps).await;

    println!("{:?}", new_timestamps);

    assert!(new_timestamps.contains_key("presentation"));
    assert!(new_timestamps.get("presentation").unwrap() >= &now_millis);
}
