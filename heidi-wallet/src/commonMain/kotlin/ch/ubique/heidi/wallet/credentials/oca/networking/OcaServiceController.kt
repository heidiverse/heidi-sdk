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

package ch.ubique.heidi.wallet.credentials.oca.networking

import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.W3C
import ch.ubique.heidi.issuance.metadata.data.CredentialConfiguration
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.wallet.credentials.format.mdoc.MdocUtils
import ch.ubique.heidi.wallet.credentials.mapping.defaults.OcaBundleFactory
import ch.ubique.heidi.credentials.models.credential.CredentialMetadata
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.wallet.credentials.metadata.asMetadataFormat
import ch.ubique.heidi.wallet.resources.StringResourceProvider
import io.ktor.client.HttpClient
import io.ktor.http.Url
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.util.encodeBase64
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import uniffi.heidi_wallet_rust.Credential
import uniffi.heidi_wallet_rust.CredentialFormat
import uniffi.heidi_wallet_rust.mdocAsJsonRepresentation

class OcaServiceController(val client: HttpClient, val stringResourceProvider: StringResourceProvider, val json: Json) {
	companion object {
		val koinModule = module {
			singleOf(::OcaServiceController)
		}
	}

	suspend fun getOcaBundleForUrl(url: String): String = client.get(url) {
		header(HttpHeaders.CacheControl, null)
	}.bodyAsText()

	suspend fun getDataFromUrl(url: String): String {
		return client.get(Url(url.trim('"'))).bodyAsText()
	}

	suspend fun getOcaFromMetadata(locale: String, metadata: CredentialIssuerMetadata?, credential: Credential,  credentialMetadata: CredentialMetadata) : String? {
		val credentialType = credential.credential.asMetadataFormat()
		val jsonContent = when (credentialType) {
			CredentialType.SdJwt -> uniffi.heidi_wallet_rust.SdJwt((credential.credential as CredentialFormat.SdJwt).v1).getJson() ?: return null
			//TODO: improve the mdocAsJsonRepresentation
			CredentialType.Mdoc -> mdocAsJsonRepresentation((credential.credential as CredentialFormat.Mdoc).v1) ?: return null
			CredentialType.BbsTermwise -> return null
			CredentialType.W3C_VCDM -> Json.encodeToString(W3C.parse((credential.credential as CredentialFormat.W3c).v1).asJson())
			CredentialType.Unknown -> return null
		}

		val credentialPayload = when(credential.credential) {
			is CredentialFormat.Mdoc -> credential.credential.v1
			is CredentialFormat.SdJwt -> credential.credential.v1
			is CredentialFormat.BbsTermWise -> return null
			is CredentialFormat.W3c -> credential.credential.v1
		}

		val docType = when (credentialType) {
			CredentialType.SdJwt -> SdJwt.parse(credentialPayload).getMetadata().vct
			CredentialType.Mdoc -> MdocUtils.getDocType(credentialPayload)
			CredentialType.W3C_VCDM -> W3C.parse(credentialPayload).docType
			CredentialType.BbsTermwise -> return null
			CredentialType.Unknown -> {
				// Don't insert this credential if it's an unknown type
				return null
			}
		}

		val credentialMetadata = metadata?.credentialConfigurationsSupported?.values?.firstOrNull {
			when(it) {
				is CredentialConfiguration.Mdoc -> it.doctype == docType
				is CredentialConfiguration.SdJwt -> it.vct == docType
				else -> false
			}
		}
		val backgroundImage = runCatching {
			if (credentialMetadata?.display?.firstOrNull()?.backgroundImage?.uri?.startsWith("data:") == true) {
				credentialMetadata.display?.firstOrNull()?.backgroundImage?.uri
			} else {
				credentialMetadata?.display?.firstOrNull()?.backgroundImage?.uri?.let {
					client.get(it).bodyAsBytes().encodeBase64()
				}
			}
		}.getOrNull()

		val bundle = OcaBundleFactory.createOcaFromDisplayMetadata(locale, stringResourceProvider, backgroundImage, metadata, docType, jsonContent)
		return json.encodeToString(bundle)
	}
}
