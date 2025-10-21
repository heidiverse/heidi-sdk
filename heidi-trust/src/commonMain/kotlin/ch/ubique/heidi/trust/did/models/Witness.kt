package ch.ubique.heidi.trust.did.models

import kotlinx.serialization.Serializable
import uniffi.heidi_util_rust.Value

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
