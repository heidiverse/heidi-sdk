package ch.ubique.heidi.trust.did

import ch.ubique.heidi.trust.did.models.DidLogEntry
import ch.ubique.heidi.trust.did.models.ResolveException
import ch.ubique.heidi.trust.did.models.WitnessProof
import ch.ubique.heidi.trust.did.tdw03.DidTdwResolver
import ch.ubique.heidi.trust.did.webvh10.DidWebVHResolver

interface DidResolver {
    companion object {
        const val DID_TDW_03_METHOD = "did:tdw:0.3"

        const val DID_WEB_VH_10_METHOD = "did:webvh:1.0"

        fun fromJsonL(lines: List<String>): DidResolver {
            val entries = lines.map { DidLogEntry.parse(it) }

            // Check if all entries are of type did:tdw:0.3 and
            // the first entry specifies the did:tdw:0.3 method
            // and no other entry specifies a different method.
            if (entries.all { it is DidLogEntry.Tdw03 } &&
                entries.firstOrNull()?.parameters?.method == DID_TDW_03_METHOD &&
                entries.none { it.parameters.method?.equals(DID_TDW_03_METHOD) == false}) {
                return DidTdwResolver(entries)
            }

            // Same check, but now for did:webvh:1.0
            if (entries.all { it is DidLogEntry.WebVH10 } &&
                entries.firstOrNull()?.parameters?.method == DID_WEB_VH_10_METHOD &&
                entries.none { it.parameters.method?.equals(DID_WEB_VH_10_METHOD) == false}) {
                return DidWebVHResolver(entries)
            }

            throw ResolveException("Mixed or unsupported versions of did log entries.")
        }
    }

    fun resolveLatest(
        verify: Boolean = true,
        witnesses: List<WitnessProof>? = null): DidLogEntry
}
