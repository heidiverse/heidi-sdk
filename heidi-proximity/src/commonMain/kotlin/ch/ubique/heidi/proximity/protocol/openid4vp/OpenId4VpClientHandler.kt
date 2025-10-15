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

import ch.ubique.heidi.proximity.ble.client.BleGattClient
import ch.ubique.heidi.proximity.ble.client.BleGattClientListener
import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.proximity.ble.gatt.BleGattService
import ch.ubique.heidi.proximity.protocol.TransportProtocol
import kotlin.uuid.Uuid

internal class OpenId4VpClientHandler(
	private val gattClient: BleGattClient,
	private val serviceUuid: Uuid,
	private val onConnecting: () -> Unit,
	private val onConnected: () -> Unit,
	private val onSessionTermination: () -> Unit,
	private val onDisconnected: () -> Unit,
	private val onMessageReceived: (ByteArray) -> Unit,
	private val onError: (Throwable) -> Unit,
) : BleGattClientListener {

	/** The size in bytes of the document request the verifier wants to transmit */
	private var documentRequestSize: Int? = null

	override fun onServicesDiscovered(services: List<BleGattService>): List<BleGattCharacteristic> {
		val service = services.singleOrNull { it.uuid == serviceUuid }
		if (service != null) {
			val uuids = listOf(
				OpenId4VpTransportProtocol.charRequestSizeUuid,
				OpenId4VpTransportProtocol.charRequestUuid,
				OpenId4VpTransportProtocol.charIdentifyUuid,
				OpenId4VpTransportProtocol.charContentSizeUuid,
				OpenId4VpTransportProtocol.charSubmitVcUuid,
				OpenId4VpTransportProtocol.charTransferSummaryRequestUuid,
				OpenId4VpTransportProtocol.charTransferSummaryReportUuid,
				OpenId4VpTransportProtocol.charDisconnectUuid,
			)
			return uuids.mapNotNull { uuid -> service.characteristics.singleOrNull { it.uuid == uuid } }
		} else {
			onError.invoke(Error("Service not found"))
			return emptyList()
		}
	}

	override fun onPeerConnecting() {
		onConnecting.invoke()
	}

	override fun onPeerConnected() {
		documentRequestSize = null

		onConnected.invoke()
		// TODO Establish session encryption first
		gattClient.readCharacteristic(OpenId4VpTransportProtocol.charRequestSizeUuid)
	}

	override fun onPeerDisconnected() {
		documentRequestSize = null

		onDisconnected.invoke()
	}

	override fun onError(error: Throwable) {
		onError.invoke(error)
	}

	override fun onCharacteristicRead(characteristic: BleGattCharacteristic) {
		when (characteristic.uuid) {
			OpenId4VpTransportProtocol.charRequestSizeUuid -> {
				// The verifier document request size was successfully read, we can now read the request itself
				documentRequestSize = characteristic.value?.decodeToString()?.toIntOrNull() ?: 0
				gattClient.readCharacteristic(OpenId4VpTransportProtocol.charRequestUuid)
			}
			OpenId4VpTransportProtocol.charRequestUuid -> {
				val request = characteristic.value ?: TransportProtocol.EMPTY_MESSAGE
				if (request.size != documentRequestSize) {
					onError.invoke(Error("Request size mismatch"))
				} else {
					// The verifier document request was successfully read, let the wallet process it
					onMessageReceived.invoke(request)
				}
			}
		}
	}

	override fun onCharacteristicWrite(characteristic: BleGattCharacteristic) {
		when (characteristic.uuid) {
			OpenId4VpTransportProtocol.charSubmitVcUuid -> {
				gattClient.writeCharacteristic(
					OpenId4VpTransportProtocol.charTransferSummaryRequestUuid,
					TransportProtocol.EMPTY_MESSAGE
				)
			}
		}
	}

	override fun onCharacteristicChanged(characteristic: BleGattCharacteristic) {
		when (characteristic.uuid) {
			OpenId4VpTransportProtocol.charTransferSummaryReportUuid -> {
				// The verifier has confirmed the transfer, send an empty message to the wallet to notify it
				// TODO Sending an empty message relies on the wallet keeping track of the correct state and interpreting it accordingly
				onMessageReceived.invoke(TransportProtocol.EMPTY_MESSAGE)
			}
			OpenId4VpTransportProtocol.charDisconnectUuid -> {
				onSessionTermination.invoke()
			}
		}
	}
}
