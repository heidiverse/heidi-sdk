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

package ch.ubique.heidi.dcql

import uniffi.heidi_dcql_rust.CredentialQuery
import ch.ubique.heidi.credentials.*
import uniffi.heidi_credentials_rust.*
import uniffi.heidi_util_rust.*

fun SdJwtBuilder.getVpToken(
    claims: Value,

    query: CredentialQuery,
    audience: String,
    transactionData: List<String>?,
    specVersion: SpecVersion?,
    nonce: String,
    signer: SignatureCreator?,
    overrideDisclosures: List<List<PointerPart>>? = null
) : Result<String> {
    this.withAudience(audience)
    this.withNonce(nonce)

    if(transactionData != null && specVersion != null) {
        this.withTransactionData(transactionData, specVersion);
    }

    // useful for tests
    overrideDisclosures?.let {
        it.forEach { ptr -> this.addDisclosure(ptr) }
        return Result.success(this.build(signer))
    }

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-selecting-claims
    // `If claims is absent, the Verifier requests all claims existing in the Credential`
    if(query.claims == null){
        this.addAll()
        return Result.success(this.build(signer))
    }

    // If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims
    if(query.claimSets == null){
        for(claim in query.claims){
            val path = if (this.isW3c() && claim.path.firstOrNull() != PointerPart.String("credentialSubject")) {
                listOf(PointerPart.String("credentialSubject")) + claim.path
            } else {
                claim.path
            }
            val ptrs = resolvePointer(claims, path)
            for (ptr in ptrs) {
                val r = claims[ptr.asSelector()]
                if(r.size > 1 || r.isEmpty()) {
                    return Result.failure(SdJwtErrors.InvalidDisclosurePath(claim.path))
                }
                this.addDisclosure(ptr)
            }
        }
    } else  {
        // If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in claim_sets.
        // The order of the options conveyed in the claim_sets array expresses the Verifier's preference for what is returned;
        // the Wallet MUST return the first option that it can satisfy.
        // If the Wallet cannot satisfy any of the options, it MUST NOT return any claims
        setLoop@ for (option in query.claimSets){
            var disclosurePtrs = mutableListOf<List<PointerPart>>()
            for(claim in option) {
                val claimQuery = query.claims.firstOrNull { it.id == claim } ?: continue
                val ptrs = resolvePointer(claims, claimQuery.path)
                if(ptrs.isEmpty()) {
                    // we don't have claims matching the query, so skip these options
                    continue@setLoop
                }
                for(ptr in ptrs) {
                    val res = ptr.asSelector().select(claims)
                    if (res.isEmpty()) {
                        continue@setLoop
                    }
                }
                disclosurePtrs.addAll(ptrs)
            }
            // we passed all options, so lets add them to the token and return
            for(ptr in disclosurePtrs){
                try {
                    this.addDisclosure(ptr)
                }catch (e: Exception) {
                    println(e)
                }
            }
            return Result.success(this.build(signer))
        }
        this.removeAll()
        return Result.success(this.build(signer))
    }
    return Result.success(this.build(signer))
}

private fun resolvePointer(claims: Value, ptr: List<PointerPart>) : List<List<PointerPart>> {
    val p = ClaimsPointer(ptr)
    return p.resolvePtr(claims)
}
