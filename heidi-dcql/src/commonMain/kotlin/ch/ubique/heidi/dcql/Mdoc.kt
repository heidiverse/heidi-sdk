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

import ch.ubique.heidi.credentials.Mdoc
import ch.ubique.heidi.credentials.Mdoc.Companion.MDOC_FORMATS
import ch.ubique.heidi.credentials.SdJwtErrors
import ch.ubique.heidi.util.extensions.asArray
import ch.ubique.heidi.util.extensions.asBytes
import ch.ubique.heidi.util.extensions.asObject
import ch.ubique.heidi.util.extensions.asOrderedObject
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.asTag
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.isSame
import ch.ubique.heidi.util.extensions.toCbor
import uniffi.heidi_credentials_rust.PointerPart
import uniffi.heidi_credentials_rust.SignatureCreator
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.decodeCbor
import uniffi.heidi_util_rust.encodeCbor

fun Mdoc.getVpToken(
    query: CredentialQuery,
    clientIdHash: ByteArray,
    responseUriHash: ByteArray,
    nonce: String,
    signer: SignatureCreator,
): Result<String> {
    if (!MDOC_FORMATS.contains(query.format)) {
        return Result.failure(SdJwtErrors.InvalidFormat(query.format))
    }
    val sessionTranscript = this.getSessionTranscript(clientIdHash, responseUriHash, nonce)
    val coseSign1 = this.deviceSignature(signer, this.doctype()!!, sessionTranscript)
    val deviceNameSpacesBytes = encodeCbor(mapOf<String, String>().toCbor()).toCbor()
    var issuerSigned = this.mdoc.originalDecoded
    var originalIssuerAuth = issuerSigned.get("issuerAuth")

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-selecting-claims
    // `If claims is absent, the Verifier requests all claims existing in the Credential`
    if (query.claims == null) {
        val vpToken = base64UrlEncode(
            encodeCbor(
                mapOf(
                    "version" to this.version(), "status" to 0, "documents" to listOf(
                        mapOf(
                            "docType" to this.doctype(),
                            "issuerSigned" to issuerSigned,
                            "deviceSigned" to mapOf(
                                "nameSpaces" to Pair(24, deviceNameSpacesBytes),
                                "deviceAuth" to mapOf(
                                    "deviceSignature" to coseSign1
                                )
                            ),
                        )
                    )
                ).toCbor()
            )
        )
        return Result.success(vpToken)
    }
    val namespaces = mutableMapOf<String, MutableList<Value>>()
    // If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims
    if (query.claimSets == null) {
        for (claim in query.claims) {
            val namespace = (claim.path[0] as PointerPart.String).v1
            val claimName = (claim.path[1] as PointerPart.String).v1

            val theNamespace = this.mdoc.originalDecoded["nameSpaces"][namespace]
            if (theNamespace == Value.Null) {
                return Result.failure(InvalidClaimsQuery(claim))
            }
            val pair = theNamespace.asArray()!!
                .map{ value ->
                    Pair(value, decodeCbor(value.asTag()!!.value[0].asBytes()!!))
                }.first { it.second["elementIdentifier"].asString()!! == claimName }
            val element = pair.second
            if (element.isSame(Value.Null)) {
                return Result.failure(InvalidClaimsQuery(claim))
            }
            // Ensure the value matches the predicates
            if (claim.values != null) {
                if (!claim.values.any { it.isSame(element["elementValue"]) }) {
                    return Result.failure(InvalidClaimsQuery(claim))
                }
            }
            val namespaceElements = namespaces.getOrPut(namespace) { mutableListOf() }
            namespaceElements.add(pair.first.toCbor())
        }
    } else {
        // If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in claim_sets.
        // The order of the options conveyed in the claim_sets array expresses the Verifier's preference for what is returned;
        // the Wallet MUST return the first option that it can satisfy.
        // If the Wallet cannot satisfy any of the options, it MUST NOT return any claims
        setLoop@ for (option in query.claimSets) {
            var disclosurePtrs = mutableMapOf<String, MutableList<Value>>()
            for (claim in option) {
                val claimQuery = query.claims.firstOrNull {
                    it.id == claim
                } ?: continue

                val namespace = (claimQuery.path[0] as PointerPart.String).v1
                val claimName = (claimQuery.path[1] as PointerPart.String).v1

                val theNamespace = this.mdoc.originalDecoded["nameSpaces"][namespace]
                if (theNamespace == Value.Null) {
                    continue@setLoop
                }
                val element = theNamespace.asArray()!!
                    .map {
                        decodeCbor(it.asTag()!!.value[0].asBytes()!!)
                    }
                    .firstOrNull() { it["elementIdentifier"].asString()!! == claimName }
                    ?: Value.Null
                if (element.isSame(Value.Null)) {
                    continue@setLoop
                }
                // Ensure the value matches the predicates
                if (claimQuery.values != null) {
                    if (!claimQuery.values.any { it.isSame(element) }) {
                        return Result.failure(InvalidClaimsQuery(claimQuery))
                    }
                }
                val namespaceElements = disclosurePtrs.getOrPut(namespace) { mutableListOf() }
                namespaceElements.add((24 to encodeCbor(element)).toCbor())
            }
            // we passed all options, so lets add them to the token and return
            for (ptr in disclosurePtrs) {
                var entry = namespaces.getOrPut(ptr.key) { mutableListOf() }
                entry.addAll(ptr.value)
            }
            issuerSigned = mapOf(
                "issuerAuth" to originalIssuerAuth,
                "nameSpaces" to namespaces
            ).toCbor()

            val token = this.buildToken(
                signer,
                issuerSigned,
                sessionTranscript,
            )

            return Result.success(
                base64UrlEncode(encodeCbor(token))
            )
        }

        issuerSigned = mapOf(
            "issuerAuth" to originalIssuerAuth,
            "nameSpaces" to listOf<String>()
        ).toCbor()
        val token = this.buildToken(
            signer,
            issuerSigned,
            sessionTranscript,
        )

        return Result.success(
            base64UrlEncode(encodeCbor(token))
        )
    }
    issuerSigned = mapOf(
        "issuerAuth" to originalIssuerAuth,
        "nameSpaces" to namespaces
    ).toCbor()
    val token = this.buildToken(
        signer,
        issuerSigned,
        sessionTranscript,
    )

    return Result.success(
        base64UrlEncode(encodeCbor(token))
    )
}

fun Mdoc.getOriginalNumClaims(): Int {
    return this.mdoc.issuerAuth["valueDigests"].asObject()!!
        .map { (_, v) -> v.asOrderedObject()!!.entries.size }
        .sum()
}

fun Mdoc.getNumDisclosed(): Int {
    return this.mdoc.namespaceMap.asOrderedObject()!!
        .entries.sumOf { (_, v) -> v.asOrderedObject()!!.entries.size }
}
