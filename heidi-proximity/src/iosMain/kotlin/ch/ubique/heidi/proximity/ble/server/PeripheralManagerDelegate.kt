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
package ch.ubique.heidi.proximity.ble.server

import ch.ubique.heidi.proximity.ble.client.toByteArray
import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.proximity.protocol.mdl.MdlCentralClientModeTransportProtocol
import ch.ubique.heidi.util.extensions.toData
import ch.ubique.heidi.util.log.Logger
import kotlinx.cinterop.ObjCSignatureOverride
import platform.CoreBluetooth.CBATTErrorSuccess
import platform.CoreBluetooth.CBATTRequest
import platform.CoreBluetooth.CBCentral
import platform.CoreBluetooth.CBCharacteristic
import platform.CoreBluetooth.CBManagerState
import platform.CoreBluetooth.CBPeripheralManager
import platform.CoreBluetooth.CBPeripheralManagerDelegateProtocol
import platform.CoreBluetooth.CBService
import platform.CoreBluetooth.CBUUID
import platform.Foundation.NSData
import platform.Foundation.NSError
import platform.Foundation.NSMutableData
import platform.Foundation.appendData
import platform.Foundation.data
import platform.darwin.NSObject

internal class GattServerDelegate(
	public var listener: BleGattServerListener?,
	private val isReady: (Boolean) -> Unit
) : NSObject(), CBPeripheralManagerDelegateProtocol {

	private val incomingBuffers = mutableMapOf<String, NSMutableData>() // key = characteristic UUID string

	private fun bufferFor(uuidString: String): NSMutableData =
		incomingBuffers.getOrPut(uuidString) { NSMutableData.data().mutableCopy() as NSMutableData }


	override fun peripheralManager(peripheral: CBPeripheralManager, didReceiveReadRequest: CBATTRequest) {
		Logger.debug("Peripheral Manager didReceiveReadRequest")
		listener?.onCharacteristicReadRequest(BleGattCharacteristic(didReceiveReadRequest.characteristic))
	}

	override fun peripheralManager(peripheral: CBPeripheralManager, didReceiveWriteRequests: List<*>) {
		Logger.debug("Peripheral Manager didReceiveWriteRequests $didReceiveWriteRequests")

		didReceiveWriteRequests.forEach { anyReq ->
			val request = anyReq as CBATTRequest
			val char = request.characteristic
			val uuidStr = (char?.UUID?.UUIDString) ?: return@forEach

			val value = request.value?.toByteArray() ?: byteArrayOf()

			if (value.isEmpty()) {
				// Nothing to do; ack to keep iOS happy
				peripheral.respondToRequest(request, CBATTErrorSuccess)
				return@forEach
			}

			if (char.UUID == CBUUID.UUIDWithString(MdlCentralClientModeTransportProtocol.characteristicStateUuid.toString())) {
				Logger.debug("Peripheral Manager didReceiveWriteRequests status")
				listener?.onCharacteristicWriteRequest(
					BleGattCharacteristic(char!!, value)
				)
				peripheral.respondToRequest(request, CBATTErrorSuccess)
				return@forEach
			}

			val header = value.first().toInt()
			val payload = if (value.size > 1) value.copyOfRange(1, value.size) else byteArrayOf()

			when (header) {
				0x01 -> {
					Logger.debug("Peripheral Manager didReceiveWriteRequests 0x01")
					// More chunks to come: append and ACK
					bufferFor(uuidStr).appendData(payload.toData())
					peripheral.respondToRequest(request, CBATTErrorSuccess)
				}
				0x00 -> {
					Logger.debug("Peripheral Manager didReceiveWriteRequests 0x00")
					// Last chunk: append, then deliver the FULL message to the listener
					val buf = bufferFor(uuidStr)
					buf.appendData(payload.toData())
					val full = (buf.copy() as NSData).toByteArray()
					buf.setLength(0u) // reset buffer

					listener?.onCharacteristicWriteRequest(
						BleGattCharacteristic(char!!, full)
					)
					peripheral.respondToRequest(request, CBATTErrorSuccess)
				}
				else -> {
					Logger.debug("Peripheral Manager didReceiveWriteRequests ${header.toHexString()}")
					// Unknown header -> treat as non-chunked, deliver directly
					listener?.onCharacteristicWriteRequest(
						BleGattCharacteristic(char!!, value)
					)
					peripheral.respondToRequest(request, CBATTErrorSuccess)
				}
			}
		}
	}


	override fun peripheralManagerDidUpdateState(peripheral: CBPeripheralManager) {
		Logger.debug("Peripheral Manager did update state ${peripheral.state} / ${peripheral.isAdvertising()} ")
		isReady(peripheral.state == 5L)
	}

	override fun peripheralManagerDidStartAdvertising(peripheral: CBPeripheralManager, error: NSError?) {
		Logger.debug("Peripheral Manager did start advertising error: ${error}")
	}

	override fun peripheralManager(peripheral: CBPeripheralManager, didAddService: CBService, error: NSError?) {
		Logger.debug("Peripheral Manager didAddService advertising error: ${error}")
	}

	override fun peripheralManagerIsReadyToUpdateSubscribers(peripheral: CBPeripheralManager) {
		Logger.debug("Peripheral Manager peripheralManagerIsReadyToUpdateSubscribers")
	}

	@ObjCSignatureOverride
	override fun peripheralManager(
		peripheral: CBPeripheralManager,
		central: CBCentral,
		didSubscribeToCharacteristic: CBCharacteristic
	) {
		Logger.debug("Peripheral Manager did didSubscribeToCharacteristic: ${didSubscribeToCharacteristic.UUID.UUIDString}")

//		listener?.onPeerConnected()
	}

//	@ObjCSignatureOverride
//	override fun peripheralManager(
//		peripheral: CBPeripheralManager,
//		central: CBCentral,
//		didUnsubscribeFromCharacteristic: CBCharacteristic
//	) {
//		Logger.debug("Peripheral Manager did didUnsubscribeFromCharacteristic")
//		listener?.onPeerDisconnected()
//	}

	fun peripheralManagerIsReady(toUpdateSubscribers: CBPeripheralManager) {
		Logger.debug("Peripheral Manager peripheralManagerIsReady")
	}

}
