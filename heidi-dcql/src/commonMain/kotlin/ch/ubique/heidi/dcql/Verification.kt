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
import ch.ubique.heidi.credentials.BbsPresentation
import ch.ubique.heidi.credentials.Mdoc
import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.W3C
import ch.ubique.heidi.credentials.get
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.toClaimsPointer
import ch.ubique.heidi.util.extensions.asArray
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import uniffi.heidi_credentials_rust.PointerPart
import uniffi.heidi_credentials_rust.verifySecuredDocumentString
import uniffi.heidi_crypto_rust.base64UrlDecode
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_dcql_rust.ClaimsQuery
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_dcql_rust.CredentialSetQuery
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_dcql_rust.Meta
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.decodeCbor
import uniffi.heidi_util_rust.encodeCbor

private fun <T> List<Result<T>>.collect(): Result<List<T>> {
    val failure = find { it.isFailure }?.exceptionOrNull()

    return if (failure != null) Result.failure(failure)
    else Result.success(map { it.getOrNull()!! })
}

fun PointerPart.toReadableString(): String = when (this) {
    is PointerPart.String -> this.v1
    is PointerPart.Index -> this.v1.toString()
    is PointerPart.Null -> "null"
}

typealias DcqlPresentation = Map<String, String>

fun interface CheckVpTokenCallback {
    // Makes Java aware that this function can throw exceptions
    @Throws(Exception::class)
    fun check(credentialType: CredentialType, vpToken: String, queryId: String): Map<String, Value>
}

open class DcqlVerificationException(message: String) : Exception(message)
class CredentialQueryNotFoundException(id: String) :
    DcqlVerificationException("Credential Query with id = $id not found!")

class ClaimQueryNotFoundException(id: String) :
    DcqlVerificationException("Credential Query with id = $id not found!")

class UnknownCredentialQueryFormatException(format: String) :
    DcqlVerificationException("Credential Query format = $format is unknown!")

class InvalidCredentialQueryMetaException(expected: String, actual: String) :
    DcqlVerificationException("Credential Query with meta = $actual is invalid, expected meta = $expected!")

class InvalidClaimTypeException(expected: String, actual: String) :
    DcqlVerificationException("Claim with type = $actual is invalid, expected type = $expected!")

class InvalidVctValueException(allowed: List<String>, actual: String) :
    DcqlVerificationException("vct = $actual is not in allowed = $allowed!")

class NotAllClaimsProvidedException() :
    DcqlVerificationException("A fully disclosed VC was expected, but a restricted was received")

class NoCredentialSetQueryOptionSatisfiedException() :
    DcqlVerificationException("No credential set option was satisfied!")

class NoClaimSetQueryOptionSatisfiedException() :
    DcqlVerificationException("No claim set option was satisfied!")

class ClaimHasNoValueException(path: String) :
    DcqlVerificationException("Claim with path = $path has no value!")

class ClaimValueNotAllowed(allowed: List<Value>, actual: Value, path: String) :
    DcqlVerificationException("Claim with path = $path has value = $actual, but one of $allowed was expected!")

class InvalidDocTypeException(expected: String, actual: String) :
    DcqlVerificationException("A document with docType = $expected was expected, but got docType = $actual!")

class InvalidCredentialTypeException(expected: List<String>, actual: List<String>) :
    DcqlVerificationException("A document with credentialType in $expected was expected, but got credentialTypes = $actual!")

class InvalidCredentialTypeCombinationException(expected: List<List<String>>, actual: List<String>) :
    DcqlVerificationException("A document with credentialType combination in $expected was expected, but got credentialTypes = $actual!")


private fun checkClaimQuery(
    query: ClaimsQuery, claims: Value
): Result<Unit> {
    val value = claims[query.path.toClaimsPointer()!!]

    if (value.size != 1) return Result.failure(
        ClaimHasNoValueException(query.path.joinToString("->") { it.toReadableString() })
    )

    query.values?.let { values ->
        if (!values.contains(value[0])) return Result.failure(
            ClaimValueNotAllowed(
                values, value[0], query.path.joinToString("->") { it.toReadableString() })
        )
    }

    return Result.success(Unit)
}

private fun checkCredentialQuery(
    query: CredentialQuery,
    claims: Value,
    originalNumClaims: Int,
    numClaimsDisclosed: Int,
): Result<Unit> {
    val claimQueries = query.claims
    if (claimQueries == null) {
        // If claims is absent, the Verifier requests all claims existing in the Credential

        // NOTE: Currently for some formats (SdJwt, W3C, Mdoc?) counting the total number of
        // claims does not work for nested disclosures (nested disclosures are not counted).
        // Thus, for now, numClaimsDisclosed must be at least originalNumClaims
        if (originalNumClaims > numClaimsDisclosed) return Result.failure(
            NotAllClaimsProvidedException()
        )
        return Result.success(Unit)
    } else {
        val claimQuerySets = query.claimSets

        if (claimQuerySets == null) {
            // If claims is present, but claim_sets is absent, the Verifier requests all
            // claims listed in claims.
            return claimQueries.map { checkClaimQuery(it, claims) }.collect().map { }
        } else {
            // If both claims and claim_sets are present, the Verifier requests one combination
            // of the claims listed in claim_sets.
            return claimQuerySets.map { set ->
                set.map inner@{ id ->
                    val claimQuery = claimQueries.find { it.id == id }

                    return@inner claimQuery?.let { checkClaimQuery(it, claims) }
                        ?: Result.failure(ClaimQueryNotFoundException(id))
                }.collect().map { }
            }.find { it.isSuccess } ?: Result.failure(NoClaimSetQueryOptionSatisfiedException())
        }
    }
}

private fun checkMetaSdJwt(
    meta: Meta, sdJwt: SdJwt
): Result<Unit> {
    if (meta !is Meta.SdjwtVc) return Result.failure(
        InvalidCredentialQueryMetaException(
            "SdJwt",
            meta.toString()
        )
    )

    val vctValue = sdJwt.innerJwt.claims["vct"]
    if (vctValue !is Value.String) return Result.failure(
        InvalidClaimTypeException(
            "Value.String", vctValue::class.simpleName.toString()
        )
    )

    if (!meta.vctValues.contains(vctValue.v1)) return Result.failure(
        InvalidVctValueException(
            meta.vctValues,
            vctValue.v1
        )
    )
    return Result.success(Unit)
}

private fun checkMetaMdoc(
    meta: Meta,
    docType: String,
): Result<Unit> {
    if (meta !is Meta.IsoMdoc) return Result.failure(
        InvalidCredentialQueryMetaException(
            "IsoMdoc",
            meta.toString()
        )
    )

    if (meta.doctypeValue != docType) return Result.failure(
        InvalidDocTypeException(
            meta.doctypeValue,
            docType
        )
    )

    return Result.success(Unit)
}

private fun checkMetaBbs(
    meta: Meta,
    types: List<String>
): Result<Unit> {
    // BBS and W3C use the same metadata structure
    if (meta !is Meta.W3c)
        return Result.failure(InvalidCredentialQueryMetaException("BBS", meta.toString()))

    return if (meta.credentialTypes.intersect(types).isEmpty()) {
        Result.failure(
            InvalidCredentialTypeException(
                meta.credentialTypes, types
            )
        )
    } else {
        Result.success(Unit)
    }
}

private fun checkMetaW3C(
    meta: Meta
): Result<Unit> {
    return Result.failure(InvalidCredentialQueryMetaException("W3C", meta.toString()))
}

private fun checkMetaOpenBadges(
    meta: Meta,
    types: List<String>
): Result<Unit> {
    if (meta !is Meta.LdpVc)
        return Result.failure(InvalidCredentialQueryMetaException("BBS", meta.toString()))

    return if (meta.typeValues.any { it.containsAll(types) }) {
        Result.success(Unit)
    } else {
        Result.failure(InvalidCredentialTypeCombinationException(meta.typeValues, types))
    }
}


private fun getCredentialType(vpToken: String, expectedFormat: String): Result<CredentialType> {
    // BBS term-wise has unique formats
    if (Bbs.BBS_TERMWISE_FORMATS.contains(expectedFormat))
        return Result.success(CredentialType.BbsTermwise)

    // Mdoc has unique formats
    if (Mdoc.MDOC_FORMATS.contains(expectedFormat))
        return Result.success(CredentialType.Mdoc)

    // SD-JWT and W3C have overlapping formats
    if (SdJwt.SD_JWT_FORMATS.contains(expectedFormat)
        && W3C.W3C_FORMATS.contains(expectedFormat)
    ) {
        // If parsing one credential fails, its the other format
        val sdJwt = runCatching { SdJwt.parse(vpToken) }.getOrElse {
            return Result.success(CredentialType.W3C_VCDM)
        }
        val w3c = runCatching { W3C.parse(vpToken) }.getOrElse {
            return Result.success(CredentialType.SdJwt)
        }

        // Otherwise, try to distinguish the formats using a heuristic:
        // "Pure" SD-JWT credentials should not have a "@context" property
        return if (w3c.asJson()["@context"] !is Value.Null) {
            Result.success(CredentialType.W3C_VCDM)
        } else {
            Result.success(CredentialType.SdJwt)
        }
    }

    if (SdJwt.SD_JWT_FORMATS.contains(expectedFormat))
        return Result.success(CredentialType.SdJwt)

    if (W3C.W3C_FORMATS.contains(expectedFormat))
        return Result.success(CredentialType.W3C_VCDM)

    if (W3C.OpenBadge303.OPEN_BADGE_FORMATS.contains(expectedFormat))
        return Result.success(CredentialType.OpenBadge303)

    return Result.failure(UnknownCredentialQueryFormatException(expectedFormat))
}

private fun checkCredentialQuery(
    query: CredentialQuery,
    vpTokens: DcqlPresentation,
    checkVpToken: (credentialType: CredentialType, vpToken: String, queryId: String) -> Map<String, Value>,
): Result<Map<String, Value>> {
    val vpToken =
        vpTokens[query.id] ?: return Result.failure(CredentialQueryNotFoundException(query.id))

    val credentialType =
        getCredentialType(vpToken, query.format).getOrElse { return Result.failure(it) }

    return when (credentialType) {
        CredentialType.SdJwt -> {
            val result = runCatching {
                checkVpToken(CredentialType.SdJwt, vpToken, query.id)
            }.getOrElse { return Result.failure(it) }
            val sdJwt = SdJwt.parse(vpToken)

            query.meta?.let {
                checkMetaSdJwt(it, sdJwt).exceptionOrNull()?.let { e -> return Result.failure(e) }
            }

            checkCredentialQuery(
                query, sdJwt.innerJwt.claims, sdJwt.getOriginalNumClaims(), sdJwt.getNumDisclosed()
            ).map { result }
        }

        CredentialType.Mdoc -> {
            val result = runCatching {
                checkVpToken(CredentialType.Mdoc, vpToken, query.id)
            }.getOrElse { return Result.failure(it) }

            val parsedCbor = decodeCbor(base64UrlDecode(vpToken))
            val issuerSigned =
                base64UrlEncode(encodeCbor(parsedCbor["documents"][0]["issuerSigned"]))

            val docType = parsedCbor["documents"][0]["docType"].asString()!!

            val mdoc = Mdoc.parse(issuerSigned)

            query.meta?.let {
                checkMetaMdoc(it, docType).exceptionOrNull()?.let { e -> return Result.failure(e) }
            }

            checkCredentialQuery(
                query, mdoc.mdoc.namespaceMap, mdoc.getOriginalNumClaims(), mdoc.getNumDisclosed()
            ).map { result }
        }

        CredentialType.BbsTermwise -> {
            val result = runCatching {
                checkVpToken(CredentialType.BbsTermwise, vpToken, query.id)
            }.getOrElse { return Result.failure(it) }
            val bbs = BbsPresentation.parse(vpToken)

            query.meta?.let {
                checkMetaBbs(it, bbs.vcTypes()).exceptionOrNull()
                    ?.let { e -> return Result.failure(e) }
            }

            checkCredentialQuery(
                query,
                bbs.claims(),
                bbs.getOriginalNumClaims(),
                bbs.getNumDisclosed()
            ).map { result }
        }

        CredentialType.W3C_VCDM -> {
            val result = runCatching {
                checkVpToken(CredentialType.W3C_VCDM, vpToken, query.id)
            }.getOrElse { return Result.failure(it) }
            val w3c = W3C.parse(vpToken)

            query.meta?.let {
                checkMetaW3C(it).exceptionOrNull()?.let { e -> return Result.failure(e) }
            }

            checkCredentialQuery(
                query, w3c.asJson(), w3c.getOriginalNumClaims(), w3c.getNumDisclosed()
            ).map { result }
        }

        CredentialType.OpenBadge303 -> {
            val result = runCatching {
                checkVpToken(CredentialType.OpenBadge303, vpToken, query.id)
            }.getOrElse { return Result.failure(it) }
            val vpJson = Json.decodeFromString<Value>(vpToken)
            val vcJson = vpJson["verifiableCredential"][0]

            query.meta?.let {
                val types = vcJson["type"]
                    .asArray()
                    ?.mapNotNull { t -> t.asString() }
                    ?: listOf()

                checkMetaOpenBadges(it, types).exceptionOrNull()?.let { e -> return Result.failure(e) }
            }

            checkCredentialQuery(
                query, vcJson, 0, 0
            ).map { result }
        }

        CredentialType.Unknown -> Result.failure(UnknownCredentialQueryFormatException(query.format))
    }
}

private fun checkCredentialSetQuery(
    query: CredentialSetQuery,
    credentialQueries: List<CredentialQuery>,
    vpTokens: DcqlPresentation,
    checkVpToken: (credentialType: CredentialType, vpToken: String, queryId: String) -> Map<String, Value>,
): Result<Map<String, Map<String, Value>>> {
    if (!query.required) return Result.success(emptyMap<String, Map<String, Value>>())

    // To satisfy a Credential Set Query, the Wallet MUST return presentations
    // of a set of Credentials that match to one of the options inside the
    // Credential Set Query.
    return query.options.map { option ->
        option.map { id ->
            credentialQueries.find { it.id == id }?.let {
                checkCredentialQuery(
                    it, vpTokens, checkVpToken
                )
            }?.map { Pair(id, it) } ?: Result.failure(
                CredentialQueryNotFoundException(
                    id
                )
            )
        }.collect().map { it.associate { (id, res) -> id to res } }
    }.find { it.isSuccess } ?: Result.failure(NoCredentialSetQueryOptionSatisfiedException())
}

/**
 * Validates a presented credential set against a DCQL query.
 *
 * If [checkVpToken] throws while validating a VP token, the exception is captured
 * and propagated as a `Result.failure`, allowing callers to handle verification issues
 * without uncaught exceptions.
 */
fun checkDcqlPresentation(
    query: DcqlQuery,
    vpTokens: DcqlPresentation,
    checkVpToken: CheckVpTokenCallback,
): Result<Map<String, Map<String, Value>>> {
    val credentialQueries = query.credentials ?: return Result.success(emptyMap<String, Map<String, Value>>())
    val credentialSetQueries = query.credentialSets

    // The Verifier requests presentations of Credentials to be returned satisfying
    // all of the Credential Set Queries in the credential_sets array where the
    // required attribute is true.
    return credentialSetQueries?.map {
        checkCredentialSetQuery(
            it,
            credentialQueries,
            vpTokens,
            { type, vpToken, id -> checkVpToken.check(type, vpToken, id) },
        )
    }?.collect()?.map { it.reduce { acc, map -> acc + map } }
    // If credential_sets is not provided, the Verifier requests presentations
    // for all Credentials in credentials to be returned.
        ?: credentialQueries.map {
            checkCredentialQuery(
                it, vpTokens,
                { type, vpToken, id -> checkVpToken.check(type, vpToken, id) },
            ).map { res -> Pair(it.id, res) }
        }.collect().map { it.associate { (id, res) -> id to res } }
}

fun verifyDcqlPresentation(
    query: DcqlQuery,
    vpTokens: DcqlPresentation,
    checkVpToken: CheckVpTokenCallback,
) = checkDcqlPresentation(query, vpTokens, checkVpToken).getOrThrow()

fun parseDcqlQuery(string: String): DcqlQuery = Json.decodeFromString<DcqlQuery>(string)
