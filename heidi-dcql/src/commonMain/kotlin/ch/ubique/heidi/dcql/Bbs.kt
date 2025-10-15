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

import ch.ubique.heidi.credentials.Bbs
import ch.ubique.heidi.credentials.Bbs.Companion.BBS_TERMWISE_FORMATS
import ch.ubique.heidi.credentials.SdJwtErrors
import ch.ubique.heidi.util.extensions.asObject
import ch.ubique.heidi.util.extensions.get
import uniffi.heidi_credentials_rust.BbsRust
import uniffi.heidi_credentials_rust.ClaimBasedParams
import uniffi.heidi_credentials_rust.PointerPart
import uniffi.heidi_credentials_rust.bbsDeriveClaimBasedProof
import uniffi.heidi_credentials_rust.bbsGetBody
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_util_rust.Value

sealed interface BbsErrors {
    data object InvalidCredentialBodyType : BbsErrors, Throwable("Invalid credential body type")

    data class UnsatisfiableClaim(
        val key: String
    ) : BbsErrors, Throwable("Expected a claim with name: $key")

    data class UnsatisfiableClaimValue(
        val key: String,
        val value: String,
        val values: List<String>
    ) : BbsErrors, Throwable("$key = $value, but expected one of $values")

    data object UnsatisfiableCredentialQuery : BbsErrors,
        Throwable("The credential query couldn't be satisfied")
}

fun BbsRust.body() : Value {
    return bbsGetBody(this)
}

fun Bbs.getVpToken(
    query: CredentialQuery,
    issuerPk: String,
    issuerId: String,
    issuerKeyId: String,
    deviceBindingPk: ByteArray?,
    message: ByteArray,
    messageSignature: ByteArray?,
    clientId: String,
    nonce: String,
): Result<String> {
    if (!BBS_TERMWISE_FORMATS.contains(query.format)) {
        return Result.failure(SdJwtErrors.InvalidFormat(query.format))
    }

    val claims = this.inner.body().asObject()
        ?: return Result.failure(BbsErrors.InvalidCredentialBodyType)

    val builder = this.presentation(issuerPk, issuerId, issuerKeyId)

    // Add device binding
    if (messageSignature != null && deviceBindingPk != null) {
        builder.setDeviceBinding(
            uncompressedPublicKey = deviceBindingPk,
            message = message,
            signature = messageSignature,
            commKeySecpLabel = "$clientId-$nonce-secp".encodeToByteArray(),
            commKeyTomLabel = "$clientId-$nonce-tom".encodeToByteArray(),
            commKeyBlsLabel = "$clientId-$nonce-bls".encodeToByteArray(),
            bppSetupLabel = "$clientId-$nonce-bpp".encodeToByteArray(),
        )
    }

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-selecting-claims
    // `If claims is absent, the Verifier requests all claims existing in the Credential`
    if (query.claims == null) {
        for (key in claims.keys) {
            builder.addDisclosure(key)
        }

        return Result.success(builder.buildWithStacksize(8388608U))
    }

    // If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims
    if (query.claimSets == null) {
        for (claim in query.claims) {
            // TODO: Add support for nested paths
            val key = (claim.path[0] as PointerPart.String).v1

            if (!claims.keys.contains(key)) {
                return Result.failure(BbsErrors.UnsatisfiableClaim(key))
            }

            if (claim.values != null && !claim.values.contains(claims[key])) {
                return Result.failure(
                    BbsErrors.UnsatisfiableClaimValue(
                        key,
                        claims[key].toString(),
                        claim.values.map { it.toString() })
                )
            }

            builder.addDisclosure(key)
        }
        return runCatching { builder.buildWithStacksize(8388608U) }
    }

    // If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in claim_sets.
    // The order of the options conveyed in the claim_sets array expresses the Verifier's preference for what is returned;
    // the Wallet MUST return the first option that it can satisfy.
    // If the Wallet cannot satisfy any of the options, it MUST NOT return any claims
    setLoop@ for (option in query.claimSets) {
        var disclosures = mutableListOf<String>()
        for (claim in option) {
            val claimQuery = query.claims.firstOrNull {
                it.id == claim
            } ?: continue@setLoop

            // TODO: Add support for nested paths
            val key = (claimQuery.path[0] as PointerPart.String).v1

            if (!claims.keys.contains(key)) {
                continue@setLoop
            }

            if (claimQuery.values != null && !claimQuery.values.contains(claims[key])) {
                continue@setLoop
            }

            disclosures.add(key)
        }

        // we passed all options, so lets add them to the token and return
        for (key in disclosures) {
            builder.addDisclosure(key)
        }
        return runCatching { builder.buildWithStacksize(8388608U) }
    }

    return Result.failure(BbsErrors.UnsatisfiableCredentialQuery)
}

fun bbsCombinedClaimBasedProof(
    vc1: Bbs,
    q1: CredentialQuery,

    deviceBindingPk: ByteArray,
    message: ByteArray,
    messageSignature: ByteArray,
    clientId: String,
    nonce: String,

    vc2: Bbs,
    q2: CredentialQuery,

    issuerPk: String,
    issuerId: String,
    issuerKeyId: String,
): Result<String> {
    val vc1Body = vc1.body()
    val claims1 = DcqlClaimQueryResolver.neededClaims(q1, { path, values ->
        val key = (path.first() as? PointerPart.String)?.v1 ?: return@neededClaims false
        val value = vc1Body[key]
        values?.contains(value) ?: true
    }) ?: return Result.failure(Exception("VC1 doesn't satisfy Q1"))

    val vc2Body = vc2.body()
    val claims2 = DcqlClaimQueryResolver.neededClaims(q2, { path, values ->
        val key = (path.first() as? PointerPart.String)?.v1 ?: return@neededClaims false
        val value = vc2Body[key]
        values?.contains(value) ?: true
    }) ?: return Result.failure(Exception("VC2 doesn't satisfy Q2"))

    val dis1 = claims1.map { (it.path.first() as PointerPart.String).v1 }
    val dis2 = claims2.map { (it.path.first() as PointerPart.String).v1 }

    val common = dis1.intersect(dis2).toList()

    return runCatching {
        bbsDeriveClaimBasedProof(ClaimBasedParams(
            vc1 = vc1.inner,
            dis1 = dis1 - common,
            uncompressedPublicKey = deviceBindingPk,
            message = message,
            signature = messageSignature,
            commKeySecpLabel = "$clientId-$nonce-secp".encodeToByteArray(),
            commKeyTomLabel = "$clientId-$nonce-tom".encodeToByteArray(),
            commKeyBlsLabel = "$clientId-$nonce-bls".encodeToByteArray(),
            bppSetupLabel = "$clientId-$nonce-bpp".encodeToByteArray(),
            vc2 = vc2.inner,
            dis2 = dis2 - common,
            common = common,
            issuerPk = issuerPk,
            issuerId = issuerId,
            issuerKeyId = issuerKeyId,
            stackSize = 8U * 1024U * 1024U,
        ))
    }
}
