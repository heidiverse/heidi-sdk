package org.kapunsdk.trust.did.models

import kotlinx.serialization.Serializable
import uniffi.kapun_util_rust.Value

@Serializable
data class Parameters(
    val method: String?,
    val scid: String?,
    val updateKeys: List<String>?,
    val prerotation: Boolean?,
    val nextKeyHashes: List<String>?,
    val witness: Value?,
)
