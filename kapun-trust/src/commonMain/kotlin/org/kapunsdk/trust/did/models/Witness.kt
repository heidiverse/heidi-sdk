package org.kapunsdk.trust.did.models

import kotlinx.serialization.Serializable
import uniffi.kapun_util_rust.Value

@Serializable
data class WitnessParam(
    val threshold: Long,
    val witnesses: List<WitnessRef>,
)

@Serializable
data class WitnessRef(val id: String)

@Serializable
data class WitnessProof(
    val versionId: String,
    val proof: List<Value>
)
