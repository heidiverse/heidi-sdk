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
import ch.ubique.heidi.proximity.ProximityProtocol
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.proximity.documents.DocumentRequester
import ch.ubique.heidi.proximity.protocol.TransportProtocol
import ch.ubique.heidi.proximity.verifier.ProximityVerifier
import ch.ubique.heidi.sample.verifier.data.model.VerificationDisclosureResult
import ch.ubique.heidi.sample.verifier.feature.network.ProofTemplate
import ch.ubique.heidi.sample.verifier.feature.network.VerifierRepository
import io.ktor.client.plugins.ResponseException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.koin.core.component.KoinComponent
import org.koin.core.module.dsl.viewModelOf
import org.koin.dsl.module
import java.security.SecureRandom
import java.util.Base64
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

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
			bluetoothStateMutable.value = BluetoothState.Connecting
		}

		override fun onConnected() {
			bluetoothStateMutable.value = BluetoothState.Connected
		}

		override fun onDisconnected() {
			bluetoothStateMutable.value = BluetoothState.Disconnected
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

	private val bluetoothStateMutable = MutableStateFlow<BluetoothState>(BluetoothState.Idle)
	val bluetoothState = bluetoothStateMutable.asStateFlow()

	private val bluetoothLogMutable = MutableStateFlow<List<String>>(emptyList())
	val bluetoothLog = bluetoothLogMutable.asStateFlow()

	private val proofTemplateMutable = MutableStateFlow(ProofTemplate.IDENTITY_CARD_CHECK)
	val proofTemplate = proofTemplateMutable.asStateFlow()


	private val requester = object : DocumentRequester<VerificationDisclosureResult> {
		private var transactionId: String? = null

//		override suspend fun createDocumentRequest(): DocumentRequest {



//			return DocumentRequest.Mdl(
//				listOf(
//					DocumentRequest.MdlDocument(
//						"doctype",
//						listOf(DocumentRequest.MdlDocumentItem("namespace", "identifier", false))
//					)
//				)
//			)
//		}

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

	fun startEngagement(qrCodeData: String) {
		viewModelScope.launch {
			val verifierName = "Sample Verifier"
//			val publicKey = qrCodeUri.getQueryParameter("key")
//			val serviceUuid = Uuid.parse(qrCodeUri.getQueryParameter("uuid")!!)

//			print("serviceUuid: " + serviceUuid)
			val verifier = ProximityVerifier.create(ProximityProtocol.MDL, viewModelScope, verifierName, requester, qrCodeData)
			verifier.connect()
//			verifier = ProximityVerifier.create(ProximityProtocol.OPENID4VP, viewModelScope, serviceUuid)
//			verifier.startEngagement(verifierName)
//			startCollectingWalletState()
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
	}

	fun stop() {
		transportProtocol?.disconnect()
		transportProtocol = null
		bluetoothStateMutable.value = BluetoothState.Idle
	}

}
