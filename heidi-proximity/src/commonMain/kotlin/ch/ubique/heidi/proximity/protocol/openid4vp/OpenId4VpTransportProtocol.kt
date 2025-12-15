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

import ch.ubique.heidi.proximity.ble.BleGattFactory
import ch.ubique.heidi.proximity.ble.client.BleGattClient
import ch.ubique.heidi.proximity.ble.client.BleScannerListener
import ch.ubique.heidi.proximity.ble.server.BleAdvertiserListener
import ch.ubique.heidi.proximity.ble.server.BleGattServer
import ch.ubique.heidi.proximity.di.HeidiProximityKoinComponent
import ch.ubique.heidi.proximity.documents.DocumentRequester
import ch.ubique.heidi.proximity.protocol.BleTransportProtocol
import org.koin.core.component.inject
import kotlin.uuid.Uuid

/**
 * Steps:
 * 1. The verifier (server) advertises the service
 * 2. The wallet (client) scans for the service
 * 3. The wallet connects to the verifier
 * 4. TODO: The wallet and verifier do a key exchange for session encryption
 * 5. The wallet reads the request size characteristic
 * 6. The wallet reads the request characteristic (repeatedly, to get the full request data)
 * 7. The wallet writes to the response size characteristic
 * 8. The wallet writes to the response data characteristic
 * 9. The wallet writes to the transfer summary request characteristic
 * 10. The verifier writes to the transfer summary response characteristic
 * 11. The wallet closes the connection
 */
internal class OpenId4VpTransportProtocol(
	role: Role,
	private val serviceUuid: Uuid,
	private val requester: DocumentRequester<*>? = null,
) : BleTransportProtocol(role), HeidiProximityKoinComponent {

	companion object {
		const val OPENID4VP_SCHEME = "openid4vp"
		const val OPENID4VP_PATH = "connect"

		// See https://openid.net/specs/openid-4-verifiable-presentations-over-ble-1_0.html#name-uuid-for-service-definition
		internal val charRequestSizeUuid = Uuid.parse("00000004-5026-444A-9E0E-D6F2450F3A77")
		internal val charRequestUuid = Uuid.parse("00000005-5026-444A-9E0E-D6F2450F3A77")
		internal val charIdentifyUuid = Uuid.parse("00000006-5026-444A-9E0E-D6F2450F3A77")
		internal val charContentSizeUuid = Uuid.parse("00000007-5026-444A-9E0E-D6F2450F3A77")
		internal val charSubmitVcUuid = Uuid.parse("00000008-5026-444A-9E0E-D6F2450F3A77")
		internal val charTransferSummaryRequestUuid = Uuid.parse("00000009-5026-444A-9E0E-D6F2450F3A77")
		internal val charTransferSummaryReportUuid = Uuid.parse("0000000A-5026-444A-9E0E-D6F2450F3A77")
		internal val charDisconnectUuid = Uuid.parse("0000000B-5026-444A-9E0E-D6F2450F3A77")
	}

	private val gattFactory by inject<BleGattFactory>()
	private val characteristicsFactory by inject<OpenId4VpCharacteristicsFactory>()

	private var gattServer: BleGattServer? = null
	private var gattClient: BleGattClient? = null

	override suspend fun connect() {
		when (role) {
			Role.WALLET -> connectAsClient()
			Role.VERIFIER -> connectAsServer(requester)
		}
	}

	override fun disconnect() {
		inhibitCallbacks()

		gattServer?.apply {
			stopAdvertising()
			setListener(null)
			stop()
			gattServer = null
		}

		gattClient?.apply {
			stopScanning()
			setListener(null)
			disconnect()
			gattClient = null
		}
	}

	override fun sendMessage(data: ByteArray, onProgress: ((sent: Int, total: Int) -> Unit)?) {
		// TODO This only works if there is only a single characteristic that can/should be written to
		val charUuid = when (role) {
			Role.WALLET -> charSubmitVcUuid
			Role.VERIFIER -> return // The verifier never needs to send data to the wallet, it only gets read
		}

		when {
			gattServer != null -> gattServer?.writeCharacteristic(charUuid, data, onProgress)
			gattClient != null -> gattClient?.writeCharacteristic(charUuid, data, onProgress)
			else -> throw IllegalStateException("No Gatt Server or Gatt Client available")
		}
	}

	override fun sendTransportSpecificTerminationMessage() {
		// Only the server (verifier) can disconnect and there is no value specified
		gattServer?.writeCharacteristic(charDisconnectUuid, EMPTY_MESSAGE)
	}

	override fun supportsTransportSpecificTerminationMessage(): Boolean {
		return true
	}

	private fun connectAsClient() {
		gattClient = gattFactory.createClient(serviceUuid).apply {
			val listener = OpenId4VpClientHandler(
				gattClient = this,
				serviceUuid = serviceUuid,
				onConnecting = { reportConnecting() },
				onConnected = { reportConnected() },
				onSessionTermination = { reportTransportSpecificSessionTermination() },
				onDisconnected = { reportDisconnected() },
				onMessageReceived = { reportMessageReceived(it) },
				onError = { reportError(it) },
			)
			setListener(listener)

			startScanning(
				object : BleScannerListener {
					override fun onError(msg: String) {
						reportError(Error(msg))
					}
				}
			)
		}
	}

	private suspend fun connectAsServer(requester: DocumentRequester<*>?) {
		if (requester == null) {
			reportError(Error("No requester provided for the server side of the protocol"))
			return
		}

		gattServer = gattFactory.createServer(serviceUuid).apply {
			val request = requester.createDocumentRequest()

			val listener = OpenId4VpServerHandler(
				gattServer = this,
				documentRequest = request,
				onConnecting = { reportConnecting() },
				onConnected = { reportConnected() },
				onDisconnected = { reportDisconnected() },
				onMessageReceived = { reportMessageReceived(it) },
				onError = { reportError(it) },
			)

			setListener(listener)

			val characteristics = characteristicsFactory.createServerCharacteristics()
			if (!start(characteristics)) {
				reportError(Error("Error starting Gatt Server"))
				stop()
				gattServer = null
				return
			}

			startAdvertising(
				object : BleAdvertiserListener {
					override fun onError(msg: String) {
						reportError(Error(msg))
					}
				}
			)
		}
	}

}
