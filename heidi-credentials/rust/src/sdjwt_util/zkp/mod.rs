use serde::{Deserialize, Serialize};

use crate::models::Pointer;

pub mod equality_proof;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZkProof {
    pub inputs: Vec<Input>,
    pub system: Vec<i8>,
    pub context: String,
    pub proof: String,
    pub proof_type: ProofType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProofType {
    #[serde(rename = "equality_proof")]
    Equality,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Input {
    Public {
        public_value: heidi_util_rust::value::Value,
    },
    Private {
        path: Pointer,
        value: String,
    },
}
