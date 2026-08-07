package org.kapunsdk.trust.did.models

data class VersionId(
    val version: Int,
    val entryHash: String,
) {
    override fun toString(): String =
        "$version-$entryHash"
}