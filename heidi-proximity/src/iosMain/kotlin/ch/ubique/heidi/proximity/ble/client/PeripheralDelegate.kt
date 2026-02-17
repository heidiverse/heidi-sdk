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
package ch.ubique.heidi.proximity.ble.client

import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.proximity.ble.gatt.BleGattService
import ch.ubique.heidi.util.log.Logger
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ObjCSignatureOverride
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.CoreBluetooth.*
import platform.Foundation.NSError
import platform.darwin.NSObject
import platform.posix.memcpy
import platform.Foundation.NSData

internal class PeripheralDelegate(
	private val gattClient: GattClient
) : NSObject(), CBPeripheralDelegateProtocol {

	override fun peripheral(peripheral: CBPeripheral, didDiscoverServices: NSError?) {
		Logger("PeripheralDelegate").debug("peripheral did discover services")
		peripheral.services?.forEach { service ->
			peripheral.discoverCharacteristics(null, service as CBService)
		}
	}

	override fun peripheral(peripheral: CBPeripheral, didDiscoverCharacteristicsForService: CBService, error: NSError?) {
		Logger("PeripheralDelegate").debug("chars for ${didDiscoverCharacteristicsForService.UUID.UUIDString.lowercase()} (${gattClient.serviceUuid.toString().lowercase()})")
		if(didDiscoverCharacteristicsForService.UUID.UUIDString.lowercase() == gattClient.serviceUuid.toString().lowercase()) {
			val characteristics = didDiscoverCharacteristicsForService.characteristics?.map { BleGattCharacteristic(it as CBCharacteristic) } ?: emptyList()
			gattClient.peripheralCharacteristics[peripheral] = characteristics
			characteristics.forEach {
				Logger("PeripheralDelegate").debug("didDiscoverDescriptorsForCharacteristic ${it.uuid} (${it.supportsNotifications})")
				peripheral.setNotifyValue(it.supportsNotifications, it.characteristic)
			}
			Logger("PeripheralDelegate").debug("set state as connected")
			gattClient.listener?.onServicesDiscovered(listOf(BleGattService(didDiscoverCharacteristicsForService)))
			gattClient.onPeerConnectedReady()
			gattClient.listener?.onPeerConnected()
		}
		// TODO BM: connect to service uuid
	}

//	override fun peripheral(peripheral: CBPeripheral, didDiscoverDescriptorsForCharacteristic: CBCharacteristic, error: NSError?) {
//		Logger("PeripheralDelegate").debug("didDiscoverDescriptorsForCharacteristic: $didDiscoverDescriptorsForCharacteristic")
//		val descriptors = didDiscoverDescriptorsForCharacteristic.descriptors?.map { it as CBDescriptor } ?: emptyList()
//		gattClient.characteristicDescriptors[BleGattCharacteristic(didDiscoverDescriptorsForCharacteristic)] = descriptors
//	}

	@ObjCSignatureOverride
	override fun peripheral(peripheral: CBPeripheral, didUpdateValueForCharacteristic: CBCharacteristic, error: NSError?) {
		val value = didUpdateValueForCharacteristic.value()?.toByteArray()
		val characteristic = BleGattCharacteristic(didUpdateValueForCharacteristic)
		val charUuid = characteristic.uuid!!
		when (value?.firstOrNull()?.toInt()) {
			0x00 -> {
				// First byte indicates that this is the last chunk of the message
				gattClient.incomingMessages.getOrPut(charUuid) { okio.Buffer() }.write(value, 1, value.size - 1)
				val entireMessage = gattClient.incomingMessages.getValue(charUuid).readByteArray()
				gattClient.listener?.onCharacteristicRead(BleGattCharacteristic(didUpdateValueForCharacteristic, entireMessage))
			}
			0x01 -> {
				// First byte indicates that more chunks are coming
				gattClient.incomingMessages.getOrPut(charUuid) { okio.Buffer() }.write(value, 1, value.size - 1)
			}
			else -> {
				// Unknown if this message is chunked or not, so just send it in the callback
				gattClient.listener?.onCharacteristicRead(BleGattCharacteristic(didUpdateValueForCharacteristic, value))
			}
		}

		Logger("PeripheralDelegate").debug("didUpdateValueForCharacteristic: $didUpdateValueForCharacteristic")
	}

	override fun peripheralIsReadyToSendWriteWithoutResponse(peripheral: CBPeripheral) {
//		Logger("PeripheralDelegate").debug("peripheralIsReadyToSendWriteWithoutResponse")
		gattClient.notifyReadyToSend(peripheral)
	}

	override fun peripheral(peripheral: CBPeripheral, didWriteValueForDescriptor: CBDescriptor, error: NSError?) {
//		Logger("PeripheralDelegate").debug("didWriteValueForDescriptor: $didWriteValueForDescriptor")
	}


}

@OptIn(ExperimentalForeignApi::class)
internal fun NSData.toByteArray(): ByteArray {
	return ByteArray(length.toInt()).apply {
		usePinned {
			memcpy(it.addressOf(0), bytes, length)
		}
	}
}
