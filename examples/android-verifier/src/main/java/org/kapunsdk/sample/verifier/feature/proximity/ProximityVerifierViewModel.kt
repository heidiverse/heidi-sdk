/* Copyright 2024 Ubique Innovation AG

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
package org.kapunsdk.sample.verifier.feature.proximity

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import org.kapunsdk.Attribute
import org.kapunsdk.AttributeType
import org.kapunsdk.sdJwtDcqlClaimsFromAttributes
import org.kapunsdk.presentation.request.PresentationRequest
import org.kapunsdk.proximity.ProximityProtocol
import org.kapunsdk.proximity.documents.DocumentRequest
import org.kapunsdk.proximity.documents.DocumentRequester
import org.kapunsdk.proximity.verifier.ProximityVerifier
import org.kapunsdk.proximity.verifier.ProximityVerifierState
import org.kapunsdk.sample.verifier.data.model.VerificationDisclosureResult
import org.kapunsdk.sample.verifier.feature.network.ProofTemplate
import org.kapunsdk.sample.verifier.feature.network.VerifierRepository
import io.ktor.client.plugins.ResponseException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import org.koin.core.component.KoinComponent
import org.koin.core.module.dsl.viewModelOf
import org.koin.dsl.module
import uniffi.kapun_dcql_rust.CredentialQuery
import uniffi.kapun_dcql_rust.DcqlQuery
import uniffi.kapun_dcql_rust.Meta

class ProximityVerifierViewModel(
	private val verifierRepository: VerifierRepository,
) : ViewModel(), KoinComponent {

	companion object {
		val koinModule = module {
			viewModelOf(::ProximityVerifierViewModel)
		}
	}

	private val requester = object : DocumentRequester<VerificationDisclosureResult> {
		private var transactionId: String? = null

		override suspend fun createDocumentRequest(expectedOrigin: String?): DocumentRequest {
			var dcqlQuery = DcqlQuery(credentials = listOf(
				CredentialQuery(id = "test",
					format = "dc+sd-jwt",
					meta = Meta.SdjwtVc(vctValues = listOf("beta-id")),
					claims = sdJwtDcqlClaimsFromAttributes(listOf(
						Attribute(0, "firstName", AttributeType.STRING, displayName = mapOf(
							"de" to "Vorname"
						))
					)))
			))
			var presentationRequest = PresentationRequest(clientId = "x509_san_dns:example.com", dcqlQuery = dcqlQuery, expectedOrigins = listOf(expectedOrigin!!))
			return DocumentRequest.OpenId4Vp(Json.encodeToString(presentationRequest))
		}

		override suspend fun verifySubmittedDocuments(data: ByteArray): VerificationDisclosureResult {
			val transactionId = transactionId ?: return VerificationDisclosureResult(isVerificationSuccessful = false)

			val disclosures = try {
				val response = data.decodeToString()
				verifierRepository.verifyDocuments(response)
				verifierRepository.getAuthorization(transactionId).disclosures
			} catch (e: ResponseException) {
				null
			}

			return VerificationDisclosureResult(
				isVerificationSuccessful = disclosures != null,
				disclosures = disclosures,
			)
		}
	}

	private val proofTemplateMutable = MutableStateFlow(ProofTemplate.IDENTITY_CARD_CHECK)
	val proofTemplate = proofTemplateMutable.asStateFlow()

	private val verifier = ProximityVerifier.create(
		ProximityProtocol.OPENID4VP,
		viewModelScope,
		"Heidi Sample Verifier",
		requester
	)

	val proximityState = verifier?.verifierState ?: MutableStateFlow(ProximityVerifierState.Initial)

	override fun onCleared() {
		super.onCleared()
		verifier?.disconnect()
	}

	fun setProofTemplate(template: ProofTemplate) {
		proofTemplateMutable.value = template
	}

	fun startEngagement() {
		verifier?.startEngagement()
	}

	fun reset() {
		verifier?.reset()
	}

}
