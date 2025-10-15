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
import ch.ubique.heidi.util.log.Logger
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.http.URLBuilder
import io.ktor.http.appendPathSegments
import org.koin.core.module.dsl.factoryOf
import org.koin.dsl.module

internal class MetadataService(
	private val httpClient: HttpClient,
) {

	companion object {
		val koinModule = module {
			factoryOf(::MetadataService)
		}

		private const val WELL_KNOWN_PATH = "/.well-known"
		private const val AUTHORIZATION_SERVER_METADATA_PATH = "$WELL_KNOWN_PATH/oauth-authorization-server"
		// Fallback for old drafts (Yes, looking at you ...)
		private const val AUTHORIZATION_SERVER_METADATA_PATH_FALLBACK = "$WELL_KNOWN_PATH/openid-configuration"
		private const val CREDENTIAL_ISSUER_METADATA_PATH = "$WELL_KNOWN_PATH/openid-credential-issuer"
	}

	suspend fun doAuthorizationServerMetadataRequest(baseUrl: String): AuthorizationServerMetadata {
		val authorizationServerMetadataUrl = URLBuilder(baseUrl).apply {
			appendPathSegments(AUTHORIZATION_SERVER_METADATA_PATH)
		}.build()

		try {
			return httpClient.get(authorizationServerMetadataUrl).body<AuthorizationServerMetadata>()
		} catch (e: Exception) {
			Logger.info("Authorization Server Metadata Request Fallback detected: $e");

			val authorizationServerMetadataUrlFallback = URLBuilder(baseUrl).apply {
				appendPathSegments(AUTHORIZATION_SERVER_METADATA_PATH_FALLBACK)
			}.build()

			return httpClient.get(authorizationServerMetadataUrlFallback).body<AuthorizationServerMetadata>()
		}
	}

	suspend fun doCredentialIssuerMetadataRequest(baseUrl: String): CredentialIssuerMetadata {
		val credentialIssuerMetadataUrl = URLBuilder(baseUrl).apply {
			appendPathSegments(CREDENTIAL_ISSUER_METADATA_PATH)
		}.build()

		return httpClient.get(credentialIssuerMetadataUrl).body<CredentialIssuerMetadata>()
	}

}
