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
package ch.ubique.heidi.proximity.wallet

import ch.ubique.heidi.proximity.ProximityProtocol
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.proximity.protocol.EngagementBuilder
import ch.ubique.heidi.proximity.protocol.TransportProtocol
import ch.ubique.heidi.proximity.protocol.mdl.DcApiCapability
import ch.ubique.heidi.proximity.protocol.mdl.MdlCapabilities
import ch.ubique.heidi.proximity.protocol.mdl.MdlCentralClientModeTransportProtocol
import ch.ubique.heidi.proximity.protocol.mdl.MdlCharacteristicsFactory
import ch.ubique.heidi.proximity.protocol.mdl.MdlEngagementBuilder
import ch.ubique.heidi.proximity.protocol.mdl.MdlPeripheralServerModeTransportProtocol
import ch.ubique.heidi.proximity.protocol.mdl.MdlSessionData
import ch.ubique.heidi.proximity.protocol.mdl.MdlSessionEstablishment
import ch.ubique.heidi.proximity.protocol.mdl.MdlTransportProtocol
import ch.ubique.heidi.proximity.protocol.mdl.MdlTransportProtocolExtensions
import ch.ubique.heidi.proximity.protocol.openid4vp.OpenId4VpTransportProtocol
import ch.ubique.heidi.util.extensions.asArray
import ch.ubique.heidi.util.extensions.asBoolean
import ch.ubique.heidi.util.extensions.asBytes
import ch.ubique.heidi.util.extensions.asOrderedObject
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.asTag
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.toCbor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import uniffi.heidi_crypto_rust.EphemeralKey
import uniffi.heidi_crypto_rust.Role
import uniffi.heidi_crypto_rust.SessionCipher
import uniffi.heidi_crypto_rust.SoftwareKeyPair
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.decodeCbor
import uniffi.heidi_util_rust.encodeCbor
import kotlin.uuid.Uuid

class ProximityWallet private constructor(
	private val protocol: ProximityProtocol,
	private val scope: CoroutineScope,
	private val engagementBuilder: EngagementBuilder?,
	private val transportProtocol: TransportProtocol,
	private var sessionCipher: SessionCipher? = null,
	var isDcApi: Boolean = false
) {
	companion object {
		fun create(
			protocol: ProximityProtocol,
			scope: CoroutineScope,
			serviceUuid: String,
			peripheralServerUuid: String? = null
		): ProximityWallet {
			return when (protocol) {
				ProximityProtocol.MDL -> {
					val keypair = EphemeralKey(Role.SK_DEVICE)
					val coseKey = encodeCbor(mapOf(
						//ECDH
						-1 to 1,
						// EC
						1 to 2,
						//x
						-2 to keypair.publicKey().slice(1..<33).toByteArray(),
						//y
						-3 to keypair.publicKey().slice(33..<65).toByteArray(),
					).toCbor())

					val transportProtocol = MdlTransportProtocol(TransportProtocol.Role.WALLET, Uuid.parse(serviceUuid),  Uuid.parse(peripheralServerUuid!!), keypair)
					val engagementBuilder = MdlEngagementBuilder("", coseKey, Uuid.parse(serviceUuid), Uuid.parse(peripheralServerUuid!!), false, transportProtocol.peripheralServerModeTransportProtocol != null, capabilities = MdlCapabilities(mapOf(
						0x44437631 to DcApiCapability(listOf("openid4vp-v1-unsigned", "openid4vp-v1-signed"))
					)))
					ProximityWallet(protocol, scope, engagementBuilder, transportProtocol)
				}
				ProximityProtocol.OPENID4VP -> {
					val transportProtocol = OpenId4VpTransportProtocol(TransportProtocol.Role.WALLET, Uuid.parse(serviceUuid))
					ProximityWallet(protocol, scope, null, transportProtocol)
				}
			}
		}

		fun create(
			protocol: ProximityProtocol,
			scope: CoroutineScope,
			serviceUuid: Uuid,
			peripheralServerUuid: Uuid? = null
		): ProximityWallet {
			return when (protocol) {
				ProximityProtocol.MDL -> {
					val keypair = EphemeralKey(Role.SK_DEVICE)
					val coseKey = encodeCbor(mapOf(
						//ECDH
						-1 to 1,
						// EC
						1 to 2,
						//x
						-2 to keypair.publicKey().slice(1..<33).toByteArray(),
						//y
						-3 to keypair.publicKey().slice(33..<65).toByteArray(),
					).toCbor())

					val transportProtocol = MdlTransportProtocol(TransportProtocol.Role.WALLET,serviceUuid, peripheralServerUuid!!, keypair)
					//TODO: we probably should expose the lis of capabilities somehow to the constructor, or at least let the constructor
					// choose, which protocols we wish to support.
					val engagementBuilder = MdlEngagementBuilder("", coseKey, serviceUuid, peripheralServerUuid!!, transportProtocol.centralClientModeTransportProtocol != null, transportProtocol.peripheralServerModeTransportProtocol != null,capabilities = MdlCapabilities(mapOf(
						0x44437631 to DcApiCapability(listOf("openid4vp-v1-unsigned", "openid4vp-v1-signed"))
					)))
					ProximityWallet(protocol, scope, engagementBuilder, transportProtocol)
				}
				ProximityProtocol.OPENID4VP -> {
					val transportProtocol = OpenId4VpTransportProtocol(TransportProtocol.Role.WALLET, serviceUuid)
					ProximityWallet(protocol, scope, null,transportProtocol)
				}
			}
		}
	}

	private val walletStateMutable = MutableStateFlow<ProximityWalletState>(ProximityWalletState.Initial)
	val walletState = walletStateMutable.asStateFlow()

	private var verifierName: String? = null

	init {
		transportProtocol.setListener(
			object : TransportProtocol.Listener {
				override fun onConnecting() {
					walletStateMutable.update { ProximityWalletState.Connecting(verifierName ?: "Unknown verifier") }
				}

				override fun onConnected() {
					walletStateMutable.update { ProximityWalletState.Connected(verifierName ?: "Unknown verifier") }
				}

				override fun onDisconnected() {
					walletStateMutable.update { ProximityWalletState.Disconnected }
				}

				override fun onMessageReceived() {
					val message = transportProtocol.getMessage()
					if (message != null) {
						processMessageReceived(message)
					} else {
						walletStateMutable.update { ProximityWalletState.Error(Error("Received message is null")) }
					}
				}

				override fun onTransportSpecificSessionTermination() {
					disconnect()
					walletStateMutable.update {
						ProximityWalletState.Disconnected
					}
				}

				override fun onError(error: Throwable) {
					walletStateMutable.update { ProximityWalletState.Error(error) }
				}
			}
		)
	}

	fun getSessionTranscript() : Value? {
		return (transportProtocol as MdlTransportProtocolExtensions).sessionTranscript
	}

	fun startEngagement(verifierName: String) {
		this.verifierName = verifierName

		scope.launch(Dispatchers.IO) {
			when (protocol) {
				ProximityProtocol.MDL -> {
					walletStateMutable.update {
						ProximityWalletState.ReadyForEngagement(engagementBuilder!!.createQrCodeForEngagement())
					}
					transportProtocol.connect()
				}
				ProximityProtocol.OPENID4VP -> transportProtocol.connect()
			}
		}
	}

	fun submitDocument(data: ByteArray): Boolean {
		if (walletState.value !is ProximityWalletState.RequestingDocuments) {
			return false
		}
		walletStateMutable.update { ProximityWalletState.SubmittingDocuments }
		val encryptedData = sessionCipher!!.encrypt(data)!!

		transportProtocol.sendMessage(encodeCbor(mapOf("data" to encryptedData).toCbor()))

		walletStateMutable.update { ProximityWalletState.PresentationCompleted }
		return true
	}

	fun disconnect() {
		transportProtocol.disconnect()
		walletStateMutable.update { ProximityWalletState.Disconnected }
	}

	private fun processMessageReceived(message: ByteArray) {
		scope.launch(Dispatchers.IO) {
			when (protocol) {
				ProximityProtocol.MDL -> {
					if(sessionCipher == null) {
						val sessionEstablishment = MdlSessionEstablishment.fromCbor(message) ?: run {
							transportProtocol.disconnect()
							return@launch
						}
						val builder = engagementBuilder as MdlEngagementBuilder
						val eReaderKey = sessionEstablishment.eReaderKey.asTag()?.value?.firstOrNull()?.asBytes() ?: run {
							transportProtocol.disconnect()
							return@launch
						}
						sessionCipher = (transportProtocol as MdlTransportProtocolExtensions).getSessionCipher(builder.getEngagementBytes(), eReaderKey)
						val result = sessionCipher?.decrypt(sessionEstablishment.data) ?: run {
							disconnect()
							return@launch
						}
						// The reader selected dcAPI
						if(sessionEstablishment.dcApiSelected == true) {
							isDcApi = true
							val sessionTranscriptBytes = encodeCbor ((transportProtocol as MdlTransportProtocolExtensions).sessionTranscript!!)
							val sessionTranscriptBytesHash = base64UrlEncode(sha256Rs(sessionTranscriptBytes))
							val origin = "iso-18013-5://${sessionTranscriptBytesHash}"
							//TODO: handle multiple requests and such
							//TODO: we should choose which protocols we support and wish (e.g .signed not signed)
							val dcRequest = Json.decodeFromString<JsonObject>(result.decodeToString())
							// we just use the first request
							runCatching {  dcRequest["requests"]!!.jsonArray.getOrNull(0)!!.jsonObject["data"]!!.jsonObject["request"]!!.jsonPrimitive.content }
								.onFailure { error ->
									walletStateMutable.update {
										ProximityWalletState.Error(error)
									}
								}
								.onSuccess { result ->
									// Update our state to openid4vp document selection (and set the origin to the session transcript hash)
									walletStateMutable.update {
										ProximityWalletState.RequestingDocuments(DocumentRequest.OpenId4Vp(result, origin = origin))
									}
								}
						} else {
							val request = decodeCbor(result)
							val docRequests = request.get("docRequests").asArray()!!.map {
								val itemsRequestBytes = it.get("itemsRequest").asTag()?.value?.firstOrNull()?.asBytes()!!
								val itemsRequest = decodeCbor(itemsRequestBytes)
								val namespaces = itemsRequest.get("nameSpaces")
								val elements = mutableListOf<DocumentRequest.MdlDocumentItem>()
								for ((namespace, entries) in namespaces.asOrderedObject()!!.entries) {
									for ((name, intentToRetain) in entries.asOrderedObject()!!.entries) {
										elements.add(
											DocumentRequest.MdlDocumentItem(
												namespace.asString()!!,
												name.asString()!!,
												intentToRetain.asBoolean()!!
											)
										)
									}
								}
								DocumentRequest.MdlDocument(
									itemsRequest.get("docType").asString()!!,
									elements
								)
							}
							walletStateMutable.update {
								ProximityWalletState.RequestingDocuments(DocumentRequest.Mdl(docRequests))
							}
						}
					} else {
						val sessionData = MdlSessionData.fromCbor(message) ?: run {
							disconnect()
							return@launch
						}
						if(sessionData.status != null) {
							walletStateMutable.update {
								ProximityWalletState.Disconnected
							}
							disconnect()
							return@launch
						}
						val data = sessionCipher?.decrypt(sessionData.data!!)!!

						if(isDcApi) {
							isDcApi = true
							val sessionTranscriptBytes = encodeCbor ((transportProtocol as MdlTransportProtocolExtensions).sessionTranscript!!)
							val sessionTranscriptBytesHash = base64UrlEncode(sha256Rs(sessionTranscriptBytes))

							val vpRequest = data.decodeToString()
							walletStateMutable.update {
								ProximityWalletState.RequestingDocuments(DocumentRequest.OpenId4Vp(vpRequest, origin = "iso-18013-5://${sessionTranscriptBytesHash}"))
							}
						} else {
							val request = decodeCbor(data)
							if(request.get("docRequests") != Value.Null) {
								val docRequests = request.get("docRequests").asArray()!!.map {
									val itemsRequestBytes = it.get("itemsRequest").asTag()?.value?.firstOrNull()?.asBytes()!!
									val itemsRequest = decodeCbor(itemsRequestBytes)
									val namespaces = itemsRequest.get("nameSpaces")
									val elements = mutableListOf<DocumentRequest.MdlDocumentItem>()
									for ((namespace, entries) in namespaces.asOrderedObject()!!.entries) {
										for ((name, intentToRetain) in entries.asOrderedObject()!!.entries) {
											elements.add(
												DocumentRequest.MdlDocumentItem(
													namespace.asString()!!,
													name.asString()!!,
													intentToRetain.asBoolean()!!
												)
											)
										}
									}
									DocumentRequest.MdlDocument(
										itemsRequest.get("docType").asString()!!,
										elements
									)
								}
								walletStateMutable.update {
									ProximityWalletState.RequestingDocuments(DocumentRequest.Mdl(docRequests))
								}
							}
						}
					}
				}
				ProximityProtocol.OPENID4VP -> {
					walletStateMutable.update { current ->
						when (current) {
							is ProximityWalletState.Connected -> {
								val request = message.decodeToString()
								val documentRequest = DocumentRequest.OpenId4Vp(request) // TODO Should not be decoded like this
								ProximityWalletState.RequestingDocuments(documentRequest)
							}
							is ProximityWalletState.SubmittingDocuments -> {
								transportProtocol.disconnect()
								ProximityWalletState.PresentationCompleted
							}
							else -> ProximityWalletState.Error(Error("Received message in unexpected state: $current"))
						}
					}
				}
			}
		}
	}

}
