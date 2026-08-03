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

package org.kapunsdk.trust.framework.oid4vp

import org.kapunsdk.credentials.SdJwt
import org.kapunsdk.credentials.models.credential.CredentialModel
import org.kapunsdk.issuance.metadata.data.CredentialIssuerMetadata
import org.kapunsdk.presentation.request.PresentationRequest
import org.kapunsdk.trust.di.KapunTrustKoinComponent
import org.kapunsdk.trust.framework.DidWebTrustAnchorProvider
import org.kapunsdk.trust.framework.DocumentProvider
import org.kapunsdk.trust.framework.X509TrustAnchorProvider
import org.kapunsdk.trust.framework.TrustFramework
import org.kapunsdk.trust.framework.ValidationInfo
import org.kapunsdk.trust.model.AgentInformation
import org.kapunsdk.trust.model.AgentType
import io.ktor.http.Url
import uniffi.kapun_credentials_rust.SignatureCreator
import uniffi.kapun_crypto_rust.SanType
import uniffi.kapun_crypto_rust.base64UrlEncode
import uniffi.kapun_crypto_rust.getKidFromJwt
import uniffi.kapun_crypto_rust.getX509FromJwt
import uniffi.kapun_crypto_rust.sha256Rs
import uniffi.kapun_crypto_rust.validateJwtWithPubKey
import uniffi.kapun_util_rust.Value

class IdentitySigner : SignatureCreator {
    override fun alg(): String {
        return "none"
    }

    override fun sign(bytes: ByteArray): ByteArray {
        return ByteArray(0)
    }

}

data class X509TrustInfo(
    val isTrusted: Boolean,
    val isValid: Boolean,
    val baseUrl: String?,
    val san: String,
)

data class DidWebTrustInfo(
    val isTrusted: Boolean,
    val isValid: Boolean,
)

const val OID4VP_BASIC_TRUST : String = "oid4vp_basic_trust"
const val EUDI_BASIC_TRUST: String = "eudi_basic_trust"

class Oid4VpTrustFramework(
    val documentProvider: DocumentProvider,
    val x509TrustAnchorProvider: X509TrustAnchorProvider = StaticX509TrustAnchorProvider(),
    val didWebTrustAnchorProvider: DidWebTrustAnchorProvider = StaticDidWebTrustAnchorProvider(),
    private val trustedDomains: List<String>
) : TrustFramework, KapunTrustKoinComponent {
    override val frameworkId: String
        get() = OID4VP_BASIC_TRUST
    override suspend fun getIssuerInformation(
        baseUrl: String,
        credentialConfigurationIds: List<String>,
        credentialIssuerMetadata: CredentialIssuerMetadata
    ): AgentInformation {
        val host = runCatching { Url(baseUrl).host }.getOrDefault(baseUrl)
        val isTrusted = trustedDomains.contains(host)
        val displayName = credentialIssuerMetadata.claims.display?.firstOrNull()?.name ?: baseUrl
        val displayLogo = credentialIssuerMetadata.claims.display?.firstOrNull()?.logo?.uri
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
    ): AgentInformation {
        val x509Trust = originalRequest?.let {
            getTrustInfoFromX509(presentationRequest, it)
        }
        val didWebTrust = originalRequest?.let {
            getTrustInfoFromDidWeb(it)
        }

        val baseUrl = x509Trust?.baseUrl
            ?: requestUri

        val isTrusted = (x509Trust?.isTrusted == true)
                || (didWebTrust?.isTrusted == true)
        val isValid = (x509Trust?.isValid == true)
                || (didWebTrust?.isValid == true)

        val mutableMap = mutableMapOf<String, Value>()

        mutableMap.apply {
            put(
                "entityName", Value.Object(
                    mapOf(
                        "de" to Value.String(presentationRequest.clientMetadata?.clientName ?: x509Trust!!.san)
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
            displayName = presentationRequest.clientMetadata?.clientName ?: x509Trust!!.san,
            logoUri = presentationRequest.clientMetadata?.logoUri,
            isTrusted = isTrusted,
            isVerified = isValid,
            identityTrust = identityJwt?.innerJwt?.originalSdjwt,
            trustFrameworkId = this.frameworkId,
            )
    }

    private fun getTrustInfoFromX509(
        presentationRequest: PresentationRequest,
        jwt: String
    ): X509TrustInfo {
        //TODO: we still should check the trust anchor
        //TODO: we should check some of the properties like response_uri and such
        val certs = getX509FromJwt(jwt)
        val isChainValid = certs?.let { x509TrustAnchorProvider.verifyChain(it)  } ?: false
        val isSigned = certs?.getOrNull(0)?.publicKey?.let {
            validateJwtWithPubKey(jwt, it)
        } ?: false
        val isTrusted = isSigned and isChainValid
        val san = if (presentationRequest.clientId.startsWith("x509_san_uri")){
            SanType.Uri(presentationRequest.clientId.replace("x509_san_uri:", ""))
        } else if (presentationRequest.clientId.startsWith("x509_san_dns"))  {
            SanType.Dns(presentationRequest.clientId.replace("x509_san_dns:", ""))
        } else {
            null
        }
        val isValid = if (san == null) {
            // check if we have x509_hash
            if(presentationRequest.clientId.startsWith("x509_hash")) {
                val clientIdHash = presentationRequest.clientId
                    .replace("x509_hash:", "")
                    // remove potential padding characters
                    .trim { it == '='}
                certs?.getOrNull(0)?.let {
                    base64UrlEncode(sha256Rs(it.originalCert)) == clientIdHash
                } ?: false
            } else {
                false
            }
        } else {
            certs?.getOrNull(0)?.san?.contains(san)?:false
        }

        return X509TrustInfo(
            isTrusted = isTrusted,
            isValid = isValid,
            baseUrl = certs?.getOrNull(0)?.subject,
            san = san?.getString() ?: presentationRequest.clientId
        )
    }

    private suspend fun getTrustInfoFromDidWeb(jwt: String): DidWebTrustInfo {
        val kid = getKidFromJwt(jwt)

        val isTrusted = kid?.let { didWebTrustAnchorProvider.isTrusted(it) }
            ?: false
        val isValid = didWebTrustAnchorProvider.verifyJwt(jwt)

        return DidWebTrustInfo(
            isTrusted = isTrusted,
            isValid = isValid
        )
    }

    override suspend fun validatePresentationRequest(presentationRequest: PresentationRequest): ValidationInfo {
        return ValidationInfo(isValid = true)
    }

    override suspend fun getAllowedDocuments(
        presentationRequest: PresentationRequest,
        includeUsedCredentials: Boolean
    ): List<CredentialModel> {
        // Filter credentials by their used-state according to includeUsedCredentials
        return documentProvider
            .getAllCredentials()
            .filter { includeUsedCredentials || !it.isUsed }
    }

}

fun SanType.getString() : String {
    return when(this) {
        is SanType.Dns -> this.v1
        is SanType.Uri -> this.v1
    }
}
