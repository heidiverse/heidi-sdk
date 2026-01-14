use serde::{Deserialize, Serialize};

pub mod equality_proof;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZkProof {
    inputs: Vec<Input>,
    system: Vec<i8>,
    context: String,
    proof: String,
    proof_type: ProofType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProofType {
    #[serde(rename = "equality_proof")]
    Equality,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Input {
    Public { public_value: serde_json::Value },
    Private { path: String, value: String },
}
