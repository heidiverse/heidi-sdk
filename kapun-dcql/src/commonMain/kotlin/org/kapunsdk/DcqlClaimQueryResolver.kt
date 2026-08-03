package org.kapunsdk

import uniffi.kapun_credentials_rust.PointerPart
import uniffi.kapun_dcql_rust.ClaimsQuery
import uniffi.kapun_dcql_rust.CredentialQuery
import uniffi.kapun_util_rust.Value
import kotlin.text.iterator

object DcqlClaimQueryResolver {
    /**
     * If the credential satisfies the `credentialQuery`, the
     * function returns all ClaimsQueries that must be revealed.
     *
     * Returns null if the credential does not satisfy the query.
     * */
    fun neededClaims(
        credentialQuery: CredentialQuery,
        hasClaim: (List<PointerPart>, List<Value>?) -> Boolean
    ): List<ClaimsQuery>? {
        val claims = credentialQuery.claims
            ?: return emptyList()

        // If claim sets are not present, we can return the claims
        val claimSets = credentialQuery.claimSets

        if (claimSets == null) {
            return if (claims.all { hasClaim(it.path, it.values) }) {
                claims
            } else {
                null
            }
        } else {
            for (set in claimSets) {
                val setClaims = set.mapNotNull { claims.find { c -> c.id == it } }

                if (setClaims.all { hasClaim(it.path, it.values) })
                    return setClaims
            }
        }

        return null
    }
}