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

package ch.ubique.heidi.issuance.metadata

import ch.ubique.heidi.issuance.metadata.data.AuthorizationServerMetadata
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadataClaims
import ch.ubique.heidi.util.extensions.json
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.appendPathSegments
import org.koin.core.module.dsl.factoryOf
import org.koin.dsl.module
import uniffi.heidi_crypto_rust.parseEncodedJwtPayload
import uniffi.heidi_util_rust.FederationResult
import uniffi.heidi_util_rust.fetchMetadataFromIssuerUrl

internal class MetadataService(
	private val httpClient: HttpClient,
) {

	companion object {
		val koinModule = module {
			factoryOf(::MetadataService)
		}

		private const val WELL_KNOWN_PATH = ".well-known"
        private const val AUTHORIZATION_SERVER_METADATA_PATH_PART = "oauth-authorization-server"
		private const val AUTHORIZATION_SERVER_METADATA_PATH = "/$WELL_KNOWN_PATH/$AUTHORIZATION_SERVER_METADATA_PATH_PART"
		// Fallback for old drafts (Yes, looking at you ...)
        private const val AUTHORIZATION_SERVER_METADATA_PATH_FALLBACK_PART = "openid-configuration"
		private const val AUTHORIZATION_SERVER_METADATA_PATH_FALLBACK = "/$WELL_KNOWN_PATH/$AUTHORIZATION_SERVER_METADATA_PATH_FALLBACK_PART"
        private const val CREDENTIAL_ISSUER_METADATA_PATH_PART = "openid-credential-issuer"
        private const val CREDENTIAL_ISSUER_METADATA_PATH = "/$WELL_KNOWN_PATH/$CREDENTIAL_ISSUER_METADATA_PATH_PART"

        private fun prependPath(url: String, path: List<String>): Url =
            URLBuilder(url).apply {
                val segments = pathSegments.toMutableList()
                if (segments.isEmpty()){
                    segments.add("")
                }
                path.forEachIndexed { i, segment ->
                    segments.add(i + 1, segment)
                }
                pathSegments = segments
            }.build()

        fun oidcAuthorizationServerMetadataUrl(baseUrl: String): Url =
            URLBuilder(baseUrl).apply {
                appendPathSegments(AUTHORIZATION_SERVER_METADATA_PATH)
            }.build()

        fun ietfAuthorizationServerMetadataUrl(baseUrl: String): Url =
            prependPath(baseUrl, listOf(WELL_KNOWN_PATH, AUTHORIZATION_SERVER_METADATA_PATH_PART))

        fun oidcFallbackAuthorizationServerMetadataUrl(baseUrl: String): Url =
            URLBuilder(baseUrl).apply {
                appendPathSegments(AUTHORIZATION_SERVER_METADATA_PATH_FALLBACK)
            }.build()

        fun ietfFallbackAuthorizationServerMetadataUrl(baseUrl: String): Url =
            prependPath(baseUrl, listOf(WELL_KNOWN_PATH, AUTHORIZATION_SERVER_METADATA_PATH_FALLBACK_PART))

        fun oidcCredentialIssuerEndpoint(baseUrl: String): Url =
            URLBuilder(baseUrl).apply {
                appendPathSegments(CREDENTIAL_ISSUER_METADATA_PATH)
            }.build()

        fun ietfCredentialIssuerEndpoint(baseUrl: String): Url =
            prependPath(baseUrl, listOf(WELL_KNOWN_PATH, CREDENTIAL_ISSUER_METADATA_PATH_PART))
    }

    suspend fun doAuthorizationServerMetadataRequest(url: Url): AuthorizationServerMetadata {
        return httpClient.get(url).body<AuthorizationServerMetadata>()
    }
    suspend fun doCredentialIssuerMetadataRequest(url: Url, signed: Boolean): CredentialIssuerMetadata {
        val resp = httpClient.get(url) {
            if (signed) {
                header(HttpHeaders.Accept, "application/jwt")
            } else {
                header(HttpHeaders.Accept, ContentType.Application.Json)
            }
        }

        return if (signed) {
            val jwt = resp.bodyAsText()
            val payload = parseEncodedJwtPayload(jwt) ?: throw Exception("Couldn't parse jwt")
            val claims = json.decodeFromString<CredentialIssuerMetadataClaims>(payload)
            CredentialIssuerMetadata.Signed(claims, jwt, url.toString())
        } else {
            CredentialIssuerMetadata.Unsigned(resp.body<CredentialIssuerMetadataClaims>())
        }
    }

	suspend fun resolveOpenIdFederation(baseUrl: String) : FederationResult {
		return fetchMetadataFromIssuerUrl(baseUrl, null)
	}
}
