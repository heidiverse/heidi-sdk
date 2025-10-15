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

package ch.ubique.heidi.trust.framework.germany

import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.dcql.disallowedClaims
import ch.ubique.heidi.dcql.isSubset
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.trust.di.HeidiTrustKoinComponent
import ch.ubique.heidi.trust.framework.DocumentProvider
import ch.ubique.heidi.trust.framework.X509TrustAnchorProvider
import ch.ubique.heidi.trust.framework.TrustFramework
import ch.ubique.heidi.trust.framework.ValidationInfo
import ch.ubique.heidi.trust.framework.oid4vp.IdentitySigner
import ch.ubique.heidi.trust.framework.oid4vp.StaticX509TrustAnchorProvider
import ch.ubique.heidi.trust.framework.oid4vp.getString
import ch.ubique.heidi.trust.model.AgentInformation
import ch.ubique.heidi.trust.model.AgentType
import ch.ubique.heidi.trust.revocation.RevocationCheck
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.transform
import io.ktor.http.Url
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.koin.core.component.inject
import uniffi.heidi_crypto_rust.SanType
import uniffi.heidi_crypto_rust.getX509FromJwt
import uniffi.heidi_crypto_rust.validateJwtWithPubKey
import uniffi.heidi_dcql_rust.ClaimsQuery
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_dcql_rust.Meta
import uniffi.heidi_crypto_rust.parseEncodedJwtPayload
import uniffi.heidi_util_rust.Value

const val EU_TRUST_FRAMEWORK_ID : String = "eudi_basic_trust"

class EuTrustFramework(private val documentProvider: DocumentProvider, private val trustedDomains: List<String>, val trustAnchorProvider: X509TrustAnchorProvider = StaticX509TrustAnchorProvider()) : TrustFramework, HeidiTrustKoinComponent {
    override val frameworkId: String = EU_TRUST_FRAMEWORK_ID
    val revocationCheck: RevocationCheck = RevocationCheck()
    val json : Json by inject<Json>()
    init {
        // Add German-Registrar trust anchor
        trustAnchorProvider.addCertificate("MIIBdTCCARugAwIBAgIUHsSmbGuWAVZVXjqoidqAVClGx4YwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQR2VybWFuIFJlZ2lzdHJhcjAeFw0yNTAzMzAxOTU4NTFaFw0yNjAzMzAxOTU4NTFaMBsxGTAXBgNVBAMMEEdlcm1hbiBSZWdpc3RyYXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASQWCESFd0Ywm9sK87XxqxDP4wOAadEKgcZFVX7npe3ALFkbjsXYZJsTGhVp0+B5ZtUao2NsyzJCKznPwTz2wJcoz0wOzAaBgNVHREEEzARgg9mdW5rZS13YWxsZXQuZGUwHQYDVR0OBBYEFMxnKLkGifbTKrxbGXcFXK6RFQd3MAoGCCqGSM49BAMCA0gAMEUCIQD4RiLJeuVDrEHSvkPiPfBvMxAXRC6PuExopUGCFdfNLQIgHGSa5u5ZqUtCrnMiaEageO71rjzBlov0YUH4+6ELioY=")
    }

    override suspend fun getIssuerInformation(
        baseUrl: String,
        credentialConfigurationIds: List<String>,
        credentialIssuerMetadata: CredentialIssuerMetadata
    ): AgentInformation? {
        val host = runCatching { Url(baseUrl).host }.getOrDefault(baseUrl)
        val isTrusted = trustedDomains.contains(host)
        if(!isTrusted) {
            return null
        }
        val displayName = credentialIssuerMetadata.display?.firstOrNull()?.name ?: baseUrl
        val displayLogo = credentialIssuerMetadata.display?.firstOrNull()?.logo?.uri
        val mutableMap = mutableMapOf<String, Value>()
        mutableMap.apply {
            put("entityName", Value.Object(mapOf(
                "de" to Value.String(displayName)
            )))
            displayLogo?.let {
                put("logoUri", Value.Object(mapOf(
                    "de" to Value.String(it)
                )))
            }
        }
        val identityJwt = SdJwt.create(
            Value.Object(
                mutableMap
            ),
            listOf(), "<unsigned>",
            key = IdentitySigner(),
            pubKeyJwk = null,
        )
        return AgentInformation(
            type = AgentType.ISSUER,
            domain = host,
            displayName = displayName,
            logoUri = displayLogo,
            isTrusted = isTrusted,
            isVerified = true,
            identityTrust = identityJwt?.innerJwt?.originalSdjwt,
            trustFrameworkId = this.frameworkId,)
    }

    override suspend fun getVerifierInformation(
        requestUri: String,
        presentationRequest: PresentationRequest,
        originalRequest: String?
    ): AgentInformation? {
        val certs = getX509FromJwt(originalRequest!!)
        val isChainValid = certs?.let { trustAnchorProvider.verifyChain(it)  } ?: false
        val isSigned = certs?.getOrNull(0)?.publicKey?.let {
            validateJwtWithPubKey(originalRequest, it)
        } ?: false
        val isTrusted = isSigned and isChainValid
        val san = if (presentationRequest.clientId.startsWith("x509_san_uri")){
            SanType.Uri(presentationRequest.clientId.replace("x509_san_uri:", ""))
        } else  {
            SanType.Dns(presentationRequest.clientId.replace("x509_san_dns:", ""))
        }
        val isValid = certs?.getOrNull(0)?.san?.contains(
            san
        )?:false

        val baseUrl = certs?.getOrNull(0)?.subject ?: requestUri

        val mutableMap = mutableMapOf<String, Value>()

        mutableMap.apply {
            put(
                "entityName", Value.Object(
                    mapOf(
                        "de" to Value.String(presentationRequest.clientMetadata?.clientName ?: san.getString())
                    )
                ),
            )
            presentationRequest.clientMetadata?.logoUri?.let {
                put(
                    "logoUri", Value.Object(
                        mapOf(
                            "de" to Value.String(it)
                        )
                    ),
                )
            }
        }
        val verifierAttestations = presentationRequest.verifierAttestations ?: return null
        val trustedStatements = mutableListOf<JsonElement>()
        for(attestation in verifierAttestations) {
            val att = attestation["data"].asString() ?: continue
            val attestationCerts = getX509FromJwt(att) ?: continue
            if(attestationCerts.isEmpty()) {
                continue
            }
            val isTrusted = trustAnchorProvider.isTrusted(attestationCerts)
            if(!isTrusted) {
                continue
            }
            val verifiedJwt = validateJwtWithPubKey(att, attestationCerts[0].publicKey)
            if(!verifiedJwt) {
                continue
            }
            val jwtPayloadString = parseEncodedJwtPayload(att) ?: continue
            val jwtPayload = runCatching { json.parseToJsonElement(jwtPayloadString) }.getOrNull() ?: continue
            val subject = kotlin.runCatching {   jwtPayload.jsonObject["sub"]?.jsonPrimitive?.content }.getOrNull()?: continue
            val prSubject = certs?.getOrNull(0)?.subject ?: continue
            if(subject != prSubject) {
                continue
            }
            val statusListUri = kotlin.runCatching { jwtPayload.jsonObject["status"]?.jsonObject?.get("status_list")?.jsonObject?.get("uri")?.jsonPrimitive?.content }.getOrNull() ?: continue
            val statusListIndex = kotlin.runCatching { jwtPayload.jsonObject["status"]?.jsonObject?.get("status_list")?.jsonObject?.get("idx")?.jsonPrimitive?.int }.getOrNull() ?: continue
            val isRevoked = revocationCheck.check(statusListUri, statusListIndex)
            if(isRevoked) {
                continue
            }
            trustedStatements.add(jwtPayload)
        }
        if(trustedStatements.isEmpty()) {
            return null
        }

        val identityJwt = SdJwt.create(
            Value.Object(
                mutableMap
            ),
            listOf(), "<unsigned>",
            key = IdentitySigner(),
            pubKeyJwk = null,
        )
        return AgentInformation(
            type = AgentType.VERIFIER,
            domain = baseUrl,
            displayName = presentationRequest.clientMetadata?.clientName ?: san.getString(),
            logoUri = presentationRequest.clientMetadata?.logoUri,
            isTrusted = isTrusted,
            isVerified = isValid,
            identityTrust = identityJwt?.innerJwt?.originalSdjwt,
            trustFrameworkId = this.frameworkId,
        )
    }

    override suspend fun validatePresentationRequest(presentationRequest: PresentationRequest): ValidationInfo {
        // Ignore dif pex, only validate dcql
        if(presentationRequest.dcqlQuery == null && presentationRequest.presentationDefinition != null) {
            return ValidationInfo(isValid = true)
        } else if (presentationRequest.dcqlQuery == null && presentationRequest.presentationDefinition == null) {
            return ValidationInfo(isValid = false, errorInfo = "invalid_request")
        }
        val verifierAttestations = presentationRequest.verifierAttestations ?: return ValidationInfo(isValid =  false, errorInfo = "no_attestations")
        val overaskingFields = mutableListOf<ClaimsQuery>()
        for(attestation in verifierAttestations) {
            val att = attestation["data"].asString() ?: continue
            val jwtPayloadString = parseEncodedJwtPayload(att) ?: continue
            val jwtPayload = runCatching { json.decodeFromString<Value>(jwtPayloadString) }.getOrNull() ?: continue

            val dcqlRegister = DcqlQuery(createIdForCredential(jwtPayload["credentials"].transform() ?: emptyList()), jwtPayload["credential_sets"].transform())
            if(presentationRequest.dcqlQuery?.isSubset(dcqlRegister) == true) {
                return ValidationInfo(isValid = true)
            }
            overaskingFields.addAll(presentationRequest.dcqlQuery?.disallowedClaims(dcqlRegister)?: emptyList())
        }
        return ValidationInfo(isValid = false, disallowedProperties = overaskingFields, errorInfo = "overasking")
    }

    override suspend fun getAllowedDocuments(
        presentationRequest: PresentationRequest,
        includeUsedCredentials: Boolean
    ): List<CredentialModel> {
        val verifierAttestations = presentationRequest.verifierAttestations ?: return emptyList()
        val credentials = mutableListOf<CredentialModel>()
        for(attestation in verifierAttestations) {
            val att = attestation["data"].asString() ?: continue
            val jwtPayloadString = parseEncodedJwtPayload(att) ?: continue
            val jwtPayload = runCatching { json.decodeFromString<Value>(jwtPayloadString) }.getOrNull() ?: continue

            val dcqlRegister = DcqlQuery(createIdForCredential(jwtPayload["credentials"].transform() ?: emptyList()), jwtPayload["credential_sets"].transform())
            for(cq in dcqlRegister.credentials ?: emptyList()) {
                when(cq.meta) {
                    is Meta.SdjwtVc -> {
                        for(vct in (cq.meta as Meta.SdjwtVc).vctValues) {
                            credentials += documentProvider.getCredentialsByDocType(vct, includeUsedCredentials)
                        }
                    }
                    is Meta.IsoMdoc -> {
                        credentials += documentProvider.getCredentialsByDocType((cq.meta as Meta.IsoMdoc).doctypeValue, includeUsedCredentials)
                    }
                    else -> {}
                }
            }
        }
        return credentials
    }
}

fun createIdForCredential(cq: List<Value>): List<CredentialQuery> {
    val queries = mutableListOf<CredentialQuery>()
    var index = 0
    for(v in cq) {
        queries.add(
            CredentialQuery(
                id = "$index",
                format = v["format"].transform() ?: continue,
                multiple = v["multiple"].transform(),
                meta = v["meta"].transform(),
                trustedAuthorities = v["trusted_authorities"].transform(),
                requireCryptographicHolderBinding = v["require_cryptographic_holder_binding"].transform(),
                claims = v["claims"].transform(),
                claimSets = v["claim_sets"].transform()
            )
        )
        index += 1
    }
    return queries
}
