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
package ch.ubique.heidi.proximity.verifier

import ch.ubique.heidi.proximity.ProximityProtocol
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.proximity.documents.DocumentRequester
import ch.ubique.heidi.proximity.protocol.EngagementBuilder
import ch.ubique.heidi.proximity.protocol.TransportProtocol
import ch.ubique.heidi.proximity.protocol.mdl.MdlEngagement
import ch.ubique.heidi.proximity.protocol.mdl.MdlSessionEstablishment
import ch.ubique.heidi.proximity.protocol.mdl.MdlTransportProtocol
import ch.ubique.heidi.proximity.protocol.mdl.MdlTransportProtocolExtensions
import ch.ubique.heidi.proximity.protocol.openid4vp.OpenId4VpEngagementBuilder
import ch.ubique.heidi.proximity.protocol.openid4vp.OpenId4VpTransportProtocol
import ch.ubique.heidi.util.extensions.toCbor
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import uniffi.heidi_crypto_rust.EphemeralKey
import uniffi.heidi_crypto_rust.Role
import uniffi.heidi_crypto_rust.SessionCipher
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.encodeCbor
import kotlin.uuid.Uuid

/**
 * @param T The type of the verification result, which is returned by the [documentRequester] in its [DocumentRequester.verifySubmittedDocuments] method
 */
class ProximityVerifier<T> private constructor(
	private val protocol: ProximityProtocol,
	private val scope: CoroutineScope,
	private val engagementBuilder: EngagementBuilder?,
	private val transportProtocol: TransportProtocol,
	private val documentRequester: DocumentRequester<T>,
	private var sessionCipher: SessionCipher? = null,
	private val preferDcApi : Boolean = true,
	private val readerKey: Value? = null
) {

	companion object {
		fun <T> create(
			protocol: ProximityProtocol,
			scope: CoroutineScope,
			verifierName: String,
			requester: DocumentRequester<T>,
			qrcodeData: String? = null,
			preferDcApi: Boolean = true
		): ProximityVerifier<T> {
			val publicKey = EphemeralKey(Role.SK_READER) // TODO Generate ephemeral key pair
			return when (protocol) {
				ProximityProtocol.MDL -> {
					val deviceEngagement = MdlEngagement.fromQrCode(qrcodeData!!)
					val coseKey =mapOf(
						//ECDH
						-1 to 1,
						// EC
						1 to 2,
						//x
						-2 to publicKey.publicKey().slice(1..<33).toByteArray(),
						//y
						-3 to publicKey.publicKey().slice(33..<65).toByteArray(),
					).toCbor()
					val transportProtocol = MdlTransportProtocol(TransportProtocol.Role.VERIFIER, deviceEngagement?.centralClientUuid!!,  deviceEngagement.peripheralServerUuid!!, publicKey)
					val sessionCipher = transportProtocol.getSessionCipher(deviceEngagement.originalData, encodeCbor(coseKey.toCbor()))
					ProximityVerifier(protocol, scope, deviceEngagement, transportProtocol, requester, sessionCipher = sessionCipher, readerKey = coseKey, preferDcApi = preferDcApi)
				}
				ProximityProtocol.OPENID4VP -> {
					val serviceUuid = Uuid.random()
					val engagementBuilder = OpenId4VpEngagementBuilder(verifierName,  base64UrlEncode(publicKey.publicKey()), serviceUuid)
					val transportProtocol = OpenId4VpTransportProtocol(TransportProtocol.Role.VERIFIER, serviceUuid, requester)
					ProximityVerifier(protocol, scope, engagementBuilder, transportProtocol, requester)
				}
			}
		}

		@OptIn(DelicateCoroutinesApi::class)
		fun <T> create(
			protocol: ProximityProtocol,
			verifierName: String,
			requester: DocumentRequester<T>,
		): ProximityVerifier<T> {
			return create(protocol, GlobalScope, verifierName, requester)
		}
	}

	private val verifierStateMutable = MutableStateFlow<ProximityVerifierState<T>>(ProximityVerifierState.Initial)
	val verifierState = verifierStateMutable.asStateFlow()

	init {
		transportProtocol.setListener(
			object : TransportProtocol.Listener {
				override fun onConnecting() {
					verifierStateMutable.update { ProximityVerifierState.Connecting }
				}

				override fun onConnected() {
					verifierStateMutable.update { ProximityVerifierState.Connected }
					if(protocol == ProximityProtocol.MDL) {
						scope.launch {
							val sessionTranscriptBytes = encodeCbor ((transportProtocol as MdlTransportProtocolExtensions).sessionTranscript!!)
							val sessionTranscriptBytesHash = base64UrlEncode(sha256Rs(sessionTranscriptBytes))
							val origin = "iso-18013-5://${sessionTranscriptBytesHash}"
							var documentRequest = documentRequester.createDocumentRequest(origin)
							when(documentRequest) {
								is DocumentRequest.Mdl -> {

								}
								is DocumentRequest.OpenId4Vp -> {
									val data = documentRequest.asDcRequest()
									val encryptedData = sessionCipher!!.encrypt(data.encodeToByteArray())
									var sessionEstablishment = MdlSessionEstablishment(readerKey!!, encryptedData!!, true)
									transportProtocol.sendMessage(encodeCbor(sessionEstablishment.toCbor()))
									verifierStateMutable.update {
										ProximityVerifierState.AwaitingDocuments
									}
								}
							}

						}
					}
				}

				override fun onDisconnected() {
					verifierStateMutable.update { ProximityVerifierState.Disconnected }
				}

				override fun onMessageReceived() {
					val message = transportProtocol.getMessage()
					if (message != null) {
						processMessageReceived(message)
					} else {
						verifierStateMutable.update { ProximityVerifierState.Error(Error("Received message is null")) }
					}
				}

				override fun onTransportSpecificSessionTermination() {
					TODO("Not yet implemented")
				}

				override fun onError(error: Throwable) {
					verifierStateMutable.update { ProximityVerifierState.Error(error) }
				}
			}
		)
	}

	@Throws(Exception::class)
	fun startEngagement()  {
		verifierStateMutable.update { ProximityVerifierState.PreparingEngagement }

		if (transportProtocol.isConnected) {
			verifierStateMutable.update { ProximityVerifierState.Error(Error("Verifier is already connected")) }
			return
		}

		scope.launch(Dispatchers.IO) {
			when (protocol) {
				ProximityProtocol.MDL -> TODO("Not yet supported")
				ProximityProtocol.OPENID4VP -> {
					transportProtocol.connect()
					val qrCodeData = engagementBuilder!!.createQrCodeForEngagement()
					verifierStateMutable.update { ProximityVerifierState.ReadyForEngagement(qrCodeData) }
				}
			}
		}
	}

	fun disconnect() {
		transportProtocol.disconnect()
		verifierStateMutable.update { ProximityVerifierState.Disconnected }
	}

	fun reset() {
		disconnect()
		verifierStateMutable.update { ProximityVerifierState.Initial }
	}

	fun connect() {
		scope.launch {
			transportProtocol.connect()
		}
	}

	private fun processMessageReceived(message: ByteArray) {
		scope.launch(Dispatchers.IO) {
			when (protocol) {
				ProximityProtocol.MDL -> TODO("Not yet supported")
				ProximityProtocol.OPENID4VP -> {
					verifierStateMutable.update { current ->
						when (current) {
							is ProximityVerifierState.Connected -> ProximityVerifierState.AwaitingDocuments
							is ProximityVerifierState.AwaitingDocuments -> {
								val verificationResult = documentRequester.verifySubmittedDocuments(message)
								ProximityVerifierState.VerificationResult(verificationResult)
							}
							else -> ProximityVerifierState.Error(Error("Received message in unexpected state: $current"))
						}
					}
				}
			}
		}
	}

}
