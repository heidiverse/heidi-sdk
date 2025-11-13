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
package ch.ubique.heidi.proximity.ble.gatt

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.CoreBluetooth.CBCharacteristic
import platform.CoreBluetooth.CBCharacteristicPropertyNotify
import platform.CoreBluetooth.CBDescriptor
import platform.posix.memcpy
import kotlin.uuid.Uuid

@Suppress("UNCHECKED_CAST")
@OptIn(ExperimentalForeignApi::class)
internal actual class BleGattCharacteristic(val characteristic: CBCharacteristic, private val internalValue: ByteArray? = null) {

	actual val uuid: Uuid?
		get() = Uuid.parse(characteristic.UUID.UUIDString)

	actual val value: ByteArray?
		get() = internalValue ?: characteristic.value?.let { data ->
			ByteArray(data.length.toInt()).apply {
				usePinned { memcpy(it.addressOf(0), data.bytes, data.length) }
			}
		}

	actual val descriptors: List<BleGattCharacteristicDescriptor>
		get() = characteristic.descriptors as List<BleGattCharacteristicDescriptor>

	actual val supportsNotifications: Boolean
		get() = characteristic.properties and CBCharacteristicPropertyNotify != 0uL

}

internal actual typealias BleGattCharacteristicDescriptor = CBDescriptor
