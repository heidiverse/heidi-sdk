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
package ch.ubique.heidi.proximity.protocol.mdl

import ch.ubique.heidi.proximity.ProximityError
import ch.ubique.heidi.proximity.ble.BleGattFactory
import ch.ubique.heidi.proximity.ble.client.BleGattClient
import ch.ubique.heidi.proximity.ble.client.BleGattClientListener
import ch.ubique.heidi.proximity.ble.client.BleScannerListener
import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristicDescriptor
import ch.ubique.heidi.proximity.ble.gatt.BleGattService
import ch.ubique.heidi.proximity.ble.server.BleAdvertiserListener
import ch.ubique.heidi.proximity.ble.server.BleGattServer
import ch.ubique.heidi.proximity.ble.server.BleGattServerListener
import ch.ubique.heidi.proximity.ble.server.GattRequestResult
import ch.ubique.heidi.proximity.di.HeidiProximityKoinComponent
import ch.ubique.heidi.proximity.protocol.BleTransportProtocol
import ch.ubique.heidi.util.extensions.asBytes
import ch.ubique.heidi.util.extensions.asOrderedObject
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.toCbor
import ch.ubique.heidi.util.log.Logger
import org.koin.core.component.inject
import uniffi.heidi_crypto_rust.EphemeralKey
import uniffi.heidi_crypto_rust.SessionCipher
import uniffi.heidi_util_rust.JsonNumber
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.decodeCbor
import uniffi.heidi_util_rust.encodeCbor
import kotlin.uuid.Uuid

internal class MdlCentralClientModeTransportProtocol(
	role: Role,
	private val serviceUuid: Uuid,
	private val ephemeralKey: EphemeralKey,
	private val deviceMacAddress: String? = null,
) : BleTransportProtocol(role), HeidiProximityKoinComponent, MdlTransportProtocolExtensions {
	companion object {
		// ISO-18013-5 Table 12
		val characteristicStateUuid = Uuid.parse("00000005-A123-48CE-896B-4C76973373E6")
		val characteristicClient2ServerUuid = Uuid.parse("00000006-A123-48CE-896B-4C76973373E6")
		val characteristicServer2ClientUuid = Uuid.parse("00000007-A123-48CE-896B-4C76973373E6")
		val characteristicIdentUuid = Uuid.parse("00000008-A123-48CE-896B-4C76973373E6")
	}

	private val gattFactory by inject<BleGattFactory>()
	private val characteristicsFactory by inject<MdlCharacteristicsFactory>()

	private var gattServer: BleGattServer? = null
	private var gattClient: BleGattClient? = null
	override var sessionTranscript: Value? = null

	fun isSupported(): Boolean {
		if (this.role == Role.VERIFIER) {
			return gattFactory.isBleAdvSupported()
		}
		return true
	}

	/*
	* Get the session cipher struct, for session encryption. In the case of the mDl (wallet) we only use eReaderKeyBytes
	* as they are part of the session transcript and also the peer public key.
	* For the mDl reader we need the public key, which was presented in the QR-Code.
	* */
	override fun getSessionCipher(engagementBytes: ByteArray, eReaderKeyBytes: ByteArray, peerCoseKey: ByteArray?): SessionCipher? {
		sessionTranscript = listOf(24 to engagementBytes, 24 to eReaderKeyBytes, Value.Null).toCbor()
		val sessionTranscriptBs = encodeCbor(sessionTranscript!!)
		val sessionTranscriptBytes = encodeCbor(
			(24 to sessionTranscriptBs).toCbor()
		)
		// Use the peerKey if we are the mdl reader
		val coseKey = decodeCbor(peerCoseKey ?: eReaderKeyBytes)
		val x = coseKey.asOrderedObject()?.get(Value.Number(JsonNumber.Integer(-2)))!!.asBytes() ?: return null
		val y = coseKey.asOrderedObject()?.get(Value.Number(JsonNumber.Integer(-3)))!!.asBytes() ?: return null
		val publicKey = byteArrayOf(0x04) + x + y
		return this.ephemeralKey.getSessionCipher(sessionTranscriptBytes, publicKey)
	}

	override suspend fun connect() {
		// In central client mode, the wallet (or mDL) acts as the client (scanning) and the verifier (or mDL reader) acts as the server (advertising)
		when (role) {
			Role.WALLET -> connectAsClient()
			Role.VERIFIER -> connectAsServer()
		}
	}

	override fun disconnect() {
		reportDisconnected()
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
		val charUuid = when (role) {
			Role.WALLET -> characteristicClient2ServerUuid
			Role.VERIFIER -> characteristicServer2ClientUuid
		}

		when {
			gattServer != null -> gattServer?.writeCharacteristic(charUuid, data, onProgress)
			gattClient != null -> gattClient?.writeCharacteristic(charUuid, data, onProgress)
			else -> throw IllegalStateException("No Gatt Server or Gatt Client available")
		}
	}

	override fun sendTransportSpecificTerminationMessage() {
		val terminationCode = byteArrayOf(0x02.toByte())
		when {
			gattServer != null -> gattServer?.writeCharacteristic(characteristicStateUuid, terminationCode)
			gattClient != null -> gattClient?.writeCharacteristic(characteristicStateUuid, terminationCode)
			else -> throw IllegalStateException("No Gatt Server or Gatt Client available")
		}
	}

	override fun supportsTransportSpecificTerminationMessage(): Boolean {
		return when {
			gattServer != null -> gattServer?.supportsSessionTermination() ?: false
			gattClient != null -> gattClient?.supportsSessionTermination() ?: false
			else -> false
		}
	}

	private fun connectAsServer() {
		gattServer = gattFactory.createServer(serviceUuid).apply {
			setListener(serverListener)
			val characteristics = characteristicsFactory.createServerVerifierCharacteristics()
			if (!start(characteristics)) {
				reportError(ProximityError.Unknown("Error starting Gatt Server"))
				stop()
				gattServer = null
				return
			}

			startAdvertising(
				object : BleAdvertiserListener {
					override fun onError(msg: String) {
						reportError(ProximityError.Unknown(msg))
					}
				}
			)
		}
	}

	private fun connectAsClient() {
		gattClient = gattFactory.createClient(serviceUuid).apply {
			setListener(clientListener)

			if (!deviceMacAddress.isNullOrEmpty()) {
				connect(deviceMacAddress)
			} else {
				startScanning(
					object : BleScannerListener {
						override fun onError(msg: String) {
							reportError(ProximityError.Unknown(msg))
						}
					}
				)
			}
		}
	}

	private val serverListener = object : BleGattServerListener {
		override fun onPeerConnecting() {
			reportConnecting()
		}

		override fun onPeerConnected() {
			gattServer?.stopAdvertising()
		}

		override fun onPeerDisconnected() {
			reportDisconnected()
		}

		override fun onError(error: ProximityError) {
			reportError(error)
		}

		override fun onDescriptorWriteRequest(descriptor: BleGattCharacteristicDescriptor): GattRequestResult {
			print("test")
			return super.onDescriptorWriteRequest(descriptor)
		}

		override fun onCharacteristicReadRequest(characteristic: BleGattCharacteristic): GattRequestResult {
			return super.onCharacteristicReadRequest(characteristic)
		}

		override fun onMtuChanged(mtu: Int) {
			super.onMtuChanged(mtu)
			// after the mtu was negotiated we can start sending data.
//			reportConnected()
		}

		override fun onCharacteristicWriteRequest(characteristic: BleGattCharacteristic): GattRequestResult {
			if (characteristic.uuid == characteristicStateUuid) {
				val value = characteristic.value
				return when {
					value == null -> {
						reportError(ProximityError.Unknown("Value is null"))
						GattRequestResult(isSuccessful = false)
					}
					value.size != 1 -> {
						reportError(ProximityError.Unknown("Value has invalid size (${value.size})"))
						GattRequestResult(isSuccessful = false)
					}
					value[0] == 0x02.toByte() -> {
						reportTransportSpecificSessionTermination()
						GattRequestResult(isSuccessful = true)
					}
					value[0] == 0x01.toByte() -> {
						reportConnected()
						GattRequestResult(isSuccessful = true)
					}
					else -> {
						reportError(ProximityError.Unknown("Invalid value for state characteristic ${value.toHexString()}"))
						GattRequestResult(isSuccessful = false)
					}
				}
			} else {
				characteristic.value?.let { reportMessageReceived(it) }
				return GattRequestResult(isSuccessful = true)
			}
		}

	}

	private val clientListener = object : BleGattClientListener {
		override fun onPeerConnecting() {
			reportConnecting()
		}

		override fun onPeerConnected() {
			// We report connected as soon as we start writing
			// the on the state characteristic (or rather when we receive the callback)
			gattClient?.writeCharacteristicNonChunked(characteristicStateUuid, byteArrayOf(0x01));
		}

		override fun onPeerDisconnected() {
			gattClient?.apply {
				setListener(null)
				disconnect()
				gattClient = null
			}
			reportDisconnected()
		}

		override fun onMtuChanged(mtu: Int) {
			print(mtu)
			// TODO Read Ident characteristic
		}

		override fun onError(error: ProximityError) {
			reportError(error)
		}

		override fun onServicesDiscovered(services: List<BleGattService>): List<BleGattCharacteristic> {
			val service = services.singleOrNull { it.uuid == serviceUuid }
			Logger("MdlCentralClientModeTransportProtocol").debug("onServicesDiscovered")
			if (service != null) {
				val stateCharacteristic = service.characteristics.singleOrNull { it.uuid == characteristicStateUuid }
				if (stateCharacteristic == null) {
					reportError(ProximityError.Unknown("State characteristic not found"))
					return emptyList()
				}

				val client2ServerCharacteristic =
					service.characteristics.singleOrNull { it.uuid == characteristicClient2ServerUuid }
				if (client2ServerCharacteristic == null) {
					reportError(ProximityError.Unknown("Client2Server characteristic not found"))
					return emptyList()
				}

				val server2ClientCharacteristic =
					service.characteristics.singleOrNull { it.uuid == characteristicServer2ClientUuid }
				if (server2ClientCharacteristic == null) {
					reportError(ProximityError.Unknown("Server2Client characteristic not found"))
					return emptyList()
				}

				val identCharacteristic = service.characteristics.singleOrNull { it.uuid == characteristicIdentUuid }
				if (identCharacteristic == null) {
					reportError(ProximityError.Unknown("Ident characteristic not found"))
					return emptyList()
				}
				Logger("MdlCentralClientModeTransportProtocol").debug("found needed chars")
				return listOf(
					stateCharacteristic,
					client2ServerCharacteristic,
					server2ClientCharacteristic,
					identCharacteristic
				)
			} else {
				reportError(ProximityError.Unknown("Service not found"))
				return emptyList()
			}
		}

		override fun onCharacteristicRead(characteristic: BleGattCharacteristic) {
			// TODO Protocol specific stuff (handle Ident)
			characteristic.value?.let { reportMessageReceived(it) }
		}

		override fun onCharacteristicWrite(characteristic: BleGattCharacteristic) {
			if (characteristic.uuid == characteristicStateUuid) {
				reportConnected()
			}
		}

		override fun onCharacteristicChanged(characteristic: BleGattCharacteristic) {
			if (characteristic.uuid == characteristicStateUuid) {
				val value = characteristic.value
				when {
					value == null -> reportError(ProximityError.Unknown("Value is null"))
					value.size != 1 -> reportError(ProximityError.Unknown("Value has invalid size (${value.size})"))
					value[0] == 0x02.toByte() -> reportTransportSpecificSessionTermination()
					else -> reportError(ProximityError.Unknown("Invalid value for state characteristic"))
				}
			} else {
				characteristic.value?.let { reportMessageReceived(it) }
			}
		}

		override fun onDescriptorWrite(descriptor: BleGattCharacteristicDescriptor) {
			print("on descriptor write")
		}
	}
}
