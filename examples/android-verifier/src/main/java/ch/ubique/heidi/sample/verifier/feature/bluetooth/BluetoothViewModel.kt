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
@file:OptIn(ExperimentalUuidApi::class)

package ch.ubique.heidi.sample.verifier.feature.bluetooth

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.dcql.Attribute
import ch.ubique.heidi.dcql.AttributeType
import ch.ubique.heidi.dcql.CheckVpTokenCallback
import ch.ubique.heidi.dcql.DcqlPresentation
import ch.ubique.heidi.dcql.checkDcqlPresentation
import ch.ubique.heidi.dcql.sdJwtDcqlClaimsFromAttributes
import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.proximity.ProximityProtocol
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.proximity.documents.DocumentRequester
import ch.ubique.heidi.proximity.protocol.TransportProtocol
import ch.ubique.heidi.proximity.verifier.ProximityVerifier
import ch.ubique.heidi.proximity.verifier.ProximityVerifierState
import ch.ubique.heidi.sample.verifier.data.model.VerificationDisclosureResult
import ch.ubique.heidi.sample.verifier.feature.network.ProofTemplate
import ch.ubique.heidi.sample.verifier.feature.network.VerifierRepository
import ch.ubique.heidi.util.extensions.asObject
import io.ktor.client.plugins.ResponseException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.koin.core.component.KoinComponent
import org.koin.core.module.dsl.viewModelOf
import org.koin.dsl.module
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_dcql_rust.Meta
import uniffi.heidi_util_rust.Value
import java.security.SecureRandom
import java.util.Base64
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

private const val DC_SD_JWT = "dc+sd-jwt"

class BluetoothViewModel(
	private val verifierRepository: VerifierRepository,
) : ViewModel(), KoinComponent {

	companion object {
		val koinModule = module {
			viewModelOf(::BluetoothViewModel)
		}

		private val SERVICE_UUID = Uuid.parse("19278c0d-7e57-4371-87f7-5315f7db9a86")
	}

	private var transportProtocol: TransportProtocol? = null

	private val transportProtocolListener = object : TransportProtocol.Listener {
		override fun onConnecting() {
			bluetoothStateMutable.value = ProximityVerifierState.Connecting
		}

		override fun onConnected() {
			bluetoothStateMutable.value = ProximityVerifierState.Connected
		}

		override fun onDisconnected() {
			bluetoothStateMutable.value = ProximityVerifierState.Disconnected
		}

		override fun onMessageReceived() {
			val message = transportProtocol?.getMessage()?.decodeToString()
			if (message != null) {
				bluetoothLogMutable.update { it.plus(message) }
			}
		}

		override fun onTransportSpecificSessionTermination() {
			transportProtocol?.disconnect()
		}

		override fun onError(error: Throwable) {
			bluetoothLogMutable.update { it.plus(error.stackTraceToString()) }
		}
	}

	private val bluetoothStateMutable = MutableStateFlow<ProximityVerifierState>(ProximityVerifierState.Initial)
	val bluetoothState = bluetoothStateMutable.asStateFlow()

	private val bluetoothLogMutable = MutableStateFlow<List<String>>(emptyList())
	val bluetoothLog = bluetoothLogMutable.asStateFlow()

	private val proofTemplateMutable = MutableStateFlow(ProofTemplate.AGE_OVER_18)
	val proofTemplate = proofTemplateMutable.asStateFlow()

	private lateinit var verifier: ProximityVerifier<VerificationDisclosureResult>

	private val requester = object : DocumentRequester<VerificationDisclosureResult> {
		private var transactionId: String? = null

		/**
		 * We hardcode some of the proof templates.
		 */
		fun getDcqlQueryForProofTemplate(proofTemplate: ProofTemplate) : DcqlQuery {
			return when (proofTemplate) {
				ProofTemplate.IDENTITY_CARD_CHECK ->
					DcqlQuery(
						credentials = listOf(
							CredentialQuery(
								id = "test",
								format = DC_SD_JWT,
								// TODO: we probably should be able to select and/or change this from the ui
								meta = Meta.SdjwtVc(vctValues = listOf("beta-id")),
								claims = sdJwtDcqlClaimsFromAttributes(
									listOf(
										Attribute(
											0, "firstName", AttributeType.STRING, displayName = mapOf(
												"de" to "Vorname"
											)
										)
									)
								)
							)
						)
					)

				ProofTemplate.AGE_OVER_16 -> DcqlQuery(
					credentials = listOf(
						CredentialQuery(
							id = "test",
							format = DC_SD_JWT,
							meta = Meta.SdjwtVc(vctValues = listOf("beta-id")),
							claims = sdJwtDcqlClaimsFromAttributes(
								listOf(
									Attribute(
										0, "age_over_16", AttributeType.BOOLEAN, displayName = mapOf(
											"de" to "Über 16"
										)
									)
								)
							)
						)
					)
				)

				ProofTemplate.AGE_OVER_18 -> DcqlQuery(
					credentials = listOf(
						CredentialQuery(
							id = "test",
							format = DC_SD_JWT,
							meta = Meta.SdjwtVc(vctValues = listOf("beta-id")),
							claims = sdJwtDcqlClaimsFromAttributes(
								listOf(
									Attribute(
										0, "age_over_18", AttributeType.BOOLEAN, displayName = mapOf(
											"de" to "Über 18"
										)
									)
								)
							)
						)
					)
				)

				ProofTemplate.AGE_OVER_65 -> DcqlQuery(
					credentials = listOf(
						CredentialQuery(
							id = "test",
							format = DC_SD_JWT,
							meta = Meta.SdjwtVc(vctValues = listOf("beta-id")),
							claims = sdJwtDcqlClaimsFromAttributes(
								listOf(
									Attribute(
										0, "age_over_65", AttributeType.BOOLEAN, displayName = mapOf(
											"de" to "Über 65"
										)
									)
								)
							)
						)
					)
				)
			}
		}

		/**
			Creates a document request as a OpenID4VP Presentation Request. Uses expectedOrigin (supplied from the
			transport library) for session binding of the DC-API request.
		 */
		override suspend fun createDocumentRequest(expectedOrigin: String?): DocumentRequest {

			//TODO: we should save the chosen request template for later verification
			// Else we might verify against a different template than we requested if the user
			// changes it in the ui in the meantime.
			var currentTemplate = proofTemplate.value

			var dcqlQuery = getDcqlQueryForProofTemplate(currentTemplate)

			//TODO: we need to create the correct presentation request:
			// - Use the correct clientID (e.g. did:...)
			// - Sign the presentation request with heidi_crypto or similiar (JWT use key from clientId resolution)
			// - Add potentially needed client_metadata (maybe not needed)
			var presentationRequest = PresentationRequest(
				clientId = "x509_san_dns:example.com",
				dcqlQuery = dcqlQuery,
				expectedOrigins = listOf(expectedOrigin!!)
			)
			// If we have a signed presentation (e.g. the above returns a JWT(S), we already have a string, so no encoding needed)
			return DocumentRequest.OpenId4Vp(Json.encodeToString(presentationRequest))
		}

		/**
		 * The transport library calls this function after receiving the vp token. Data is, in the realm of DC-API over ISO
		 * a openid4vp dcql response (e.g. map with vp-tokens)
		 */
		override suspend fun verifySubmittedDocuments(data: ByteArray): VerificationDisclosureResult {
			var tokenMap = data.decodeToString()
			var dcqlPresentation : DcqlPresentation = Json.decodeFromString(tokenMap)
			//TODO: use the same template as we used for requesting before
			var currentTemplate = proofTemplate.value
			var dcqlQuery = getDcqlQueryForProofTemplate(currentTemplate)

			//TODO: we probably should already try to load the public keys and status lists here. It potentially makes sense
			// to already parse the token(s) here (in an early version we anyways only ever have one token) and load keys (did-logs etc.)
			// and check status list. So the later `CheckVpTokenCallback` does not need to run async/suspending functions

				val result = checkDcqlPresentation(dcqlQuery, dcqlPresentation, object: CheckVpTokenCallback {
					override fun check(
						credentialType: CredentialType,
						vpToken: String,
						queryId: String,
					): Map<String, Value> {
					//TODO: This should use credentialType to switch on the actual type and then use
					// the corresponding format types to verify the credential.
					// In a first version we only support SD-JWT, so we should make sure the classic SD-JWt properties
					// like `exp` `iat` `nbf` and others are checked.
					var token = SdJwt.parse(vpToken)
					return token.innerJwt.claims.asObject()!!
				}
			})
			//TODO: result probably needs to be extended in order to represent states like the following
			// - Could not load (refresh) the did-log -> we don't have a key for verification
			// - We could load the did-log -> still no key
			// - We couldn't fetch or understand the status list
			// - ....
			if(result.isSuccess) {
				return VerificationDisclosureResult(
					isVerificationSuccessful = true,
					disclosures = result.getOrThrow(),
				)
			} else {
				return VerificationDisclosureResult(
					isVerificationSuccessful = false,
					disclosures = null,
				)
			}

		}
	}

	fun startEngagement(qrCodeData: String) {
		viewModelScope.launch {
			val verifierName = "Sample Verifier"
			verifier = ProximityVerifier.create(ProximityProtocol.MDL, viewModelScope, verifierName, requester, qrCodeData)
			verifier.connect()
			verifier.verifierState
			startCollectingWalletState()
		}
	}

	private fun startCollectingWalletState() {
		viewModelScope.launch {
			verifier.verifierState.collect { state ->

				bluetoothStateMutable.value = state

//				if (state is ProximityVerifierState.VerificationResult<>) {
//					 parse the disclosures and show them on the screen
//				}
			}
		}
	}

	fun startServerMode(role: TransportProtocol.Role) {
		bluetoothLogMutable.value = emptyList()

//		transportProtocol = MdlPeripheralServerModeTransportProtocol(role, SERVICE_UUID, characteristics).also {
//			it.setListener(transportProtocolListener)
//			it.connect()
//			bluetoothStateMutable.update {
//				when (role) {
//					TransportProtocol.Role.WALLET -> BluetoothState.Advertising(SERVICE_UUID)
//					TransportProtocol.Role.VERIFIER -> BluetoothState.Scanning(SERVICE_UUID)
//				}
//			}
//		}
	}

	fun startClientMode(role: TransportProtocol.Role) {
		bluetoothLogMutable.value = emptyList()

//		transportProtocol = MdlCentralClientModeTransportProtocol(role, SERVICE_UUID, characteristics).also {
//			it.setListener(transportProtocolListener)
//			it.connect()
//			bluetoothStateMutable.update {
//				when (role) {
//					TransportProtocol.Role.WALLET -> BluetoothState.Scanning(SERVICE_UUID)
//					TransportProtocol.Role.VERIFIER -> BluetoothState.Advertising(SERVICE_UUID)
//				}
//			}
//		}
	}

	fun sendMessage(message: String) {
		transportProtocol?.sendMessage(message.encodeToByteArray())
//		bluetoothStateMutable.value = BluetoothState.
	}

	fun stop() {
		transportProtocol?.disconnect()
		transportProtocol = null
		bluetoothStateMutable.value = ProximityVerifierState.Initial
	}

	fun updateProofTemplate(template: ProofTemplate) {
		proofTemplateMutable.value = template
	}

	fun reset() {
		if (::verifier.isInitialized) {
			verifier.reset()
		}
	}

}
