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
package ch.ubique.heidi.proximity.protocol.openid4vp

import ch.ubique.heidi.proximity.ProximityError
import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.proximity.ble.server.BleGattServer
import ch.ubique.heidi.proximity.ble.server.BleGattServerListener
import ch.ubique.heidi.proximity.ble.server.GattRequestResult
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.proximity.documents.DocumentRequestEncoder
import ch.ubique.heidi.proximity.protocol.TransportProtocol

internal class OpenId4VpServerHandler(
	private val gattServer: BleGattServer,
	private val documentRequest: DocumentRequest,
	private val onConnecting: () -> Unit,
	private val onConnected: () -> Unit,
	private val onDisconnected: () -> Unit,
	private val onMessageReceived: (ByteArray) -> Unit,
	private val onError: (ProximityError) -> Unit,
) : BleGattServerListener {

	/** The encoded document request to be transmitted to the wallet */
	private val encodedDocumentRequest = DocumentRequestEncoder.create(documentRequest).encodeDocumentRequest()

	/** The size in bytes of the document content that the wallet wants to transmit */
	private var documentContentSize: Int? = null

	override fun onPeerConnecting() {
		onConnecting.invoke()
	}

	override fun onPeerConnected() {
		documentContentSize = null

		onConnected.invoke()
	}

	override fun onPeerDisconnected() {
		documentContentSize = null

		onDisconnected.invoke()
	}

	override fun onError(error: ProximityError) {
		onError.invoke(error)
	}

	override fun onCharacteristicReadRequest(characteristic: BleGattCharacteristic): GattRequestResult {
		return when (characteristic.uuid) {
			OpenId4VpTransportProtocol.charRequestSizeUuid -> {
				// The wallet has requested to read the size of the document request
				val requestSize = encodedDocumentRequest.size
				val data = requestSize.toString().encodeToByteArray()
				GattRequestResult(isSuccessful = true, data = data)
			}
			OpenId4VpTransportProtocol.charRequestUuid -> {
				// The wallet has requested to read the document request. Send an empty message to the verifier to notify it
				// TODO Sending an empty message relies on the verifier keeping track of the correct state and interpreting it accordingly
				onMessageReceived.invoke(TransportProtocol.EMPTY_MESSAGE)
				GattRequestResult(isSuccessful = true, data = encodedDocumentRequest)
			}
			else -> GattRequestResult(isSuccessful = false)
		}
	}

	override fun onCharacteristicWriteRequest(characteristic: BleGattCharacteristic): GattRequestResult {
		return when (characteristic.uuid) {
			OpenId4VpTransportProtocol.charIdentifyUuid -> {
				// TODO Handle session encryption
				GattRequestResult(isSuccessful = true)
			}
			OpenId4VpTransportProtocol.charContentSizeUuid -> {
				// The wallet transmitted the content size
				documentContentSize = characteristic.value?.decodeToString()?.toIntOrNull() ?: 0
				GattRequestResult(isSuccessful = true)
			}
			OpenId4VpTransportProtocol.charSubmitVcUuid -> {
				val response = characteristic.value
				if (response != null) {
					// The wallet has transmitted the document, let the verifier process it
					onMessageReceived.invoke(response)
					GattRequestResult(isSuccessful = true)
				} else {
					GattRequestResult(isSuccessful = false)
				}
			}
			OpenId4VpTransportProtocol.charTransferSummaryRequestUuid -> {
				// TODO What data does the transfer summary report contain?
				gattServer.writeCharacteristic(
					charUuid = OpenId4VpTransportProtocol.charTransferSummaryReportUuid,
					data = TransportProtocol.EMPTY_MESSAGE
				)
				GattRequestResult(isSuccessful = true)
			}
			else -> GattRequestResult(isSuccessful = false)
		}
	}
}
