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
package ch.ubique.heidi.sample.verifier.feature.proximity

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ch.ubique.heidi.proximity.ProximityProtocol
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.proximity.documents.DocumentRequester
import ch.ubique.heidi.proximity.verifier.ProximityVerifier
import ch.ubique.heidi.sample.verifier.data.model.VerificationDisclosureResult
import ch.ubique.heidi.sample.verifier.feature.network.ProofTemplate
import ch.ubique.heidi.sample.verifier.feature.network.VerifierRepository
import io.ktor.client.plugins.ResponseException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.koin.core.component.KoinComponent
import org.koin.core.module.dsl.viewModelOf
import org.koin.dsl.module
import java.security.SecureRandom
import java.util.Base64

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

		override suspend fun createDocumentRequest(): DocumentRequest {
			val randomBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
			val nonce = Base64.getEncoder().encodeToString(randomBytes)

			val verificationRequest = verifierRepository.getVerificationRequest(proofTemplate.value, nonce)
			val flow = verificationRequest.sameDeviceFlow
			transactionId = flow.transactionId
			val presentationDefinition = verifierRepository.getPresentationDefinition(flow.requestUri)
			return DocumentRequest.OpenId4Vp(presentationDefinition)
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

	val proximityState = verifier.verifierState

	override fun onCleared() {
		super.onCleared()
		verifier.disconnect()
	}

	fun setProofTemplate(template: ProofTemplate) {
		proofTemplateMutable.value = template
	}

	fun startEngagement() {
		verifier.startEngagement()
	}

	fun reset() {
		verifier.reset()
	}

}
