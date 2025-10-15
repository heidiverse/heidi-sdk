/* Copyright 2025 Ubique Innovation AG

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

import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.proximity.protocol.openid4vp.OpenId4VpTransportProtocol
import platform.CoreBluetooth.CBAttributePermissionsReadable
import platform.CoreBluetooth.CBAttributePermissionsWriteable
import platform.CoreBluetooth.CBCharacteristicPropertyNotify
import platform.CoreBluetooth.CBCharacteristicPropertyRead
import platform.CoreBluetooth.CBCharacteristicPropertyWrite
import platform.CoreBluetooth.CBCharacteristicPropertyWriteWithoutResponse
import platform.CoreBluetooth.CBMutableCharacteristic
import platform.CoreBluetooth.CBMutableDescriptor
import platform.CoreBluetooth.CBUUID

internal actual class MdlCharacteristicsFactory {
	internal actual fun createServerWalletCharacteristics(): List<BleGattCharacteristic> {
		var stateChar = CBMutableCharacteristic(
			CBUUID.UUIDWithString(MdlPeripheralServerModeTransportProtocol.characteristicStateUuid.toString()),
			CBCharacteristicPropertyWriteWithoutResponse or CBCharacteristicPropertyWrite,
			null,
			CBAttributePermissionsWriteable
		)

		val serverToClientChar = CBMutableCharacteristic(
			CBUUID.UUIDWithString(MdlPeripheralServerModeTransportProtocol.characteristicServer2ClientUuid.toString()),
			CBCharacteristicPropertyNotify,
			null,
			CBAttributePermissionsReadable
		)

		return listOf(
			stateChar,
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(MdlPeripheralServerModeTransportProtocol.characteristicClient2ServerUuid.toString()),
				CBCharacteristicPropertyWriteWithoutResponse or CBCharacteristicPropertyWrite,
				null,
				CBAttributePermissionsWriteable
			),
			serverToClientChar
			,
		).map { BleGattCharacteristic(it) }
	}

	internal actual fun createServerVerifierCharacteristics(): List<BleGattCharacteristic> {
		return listOf(
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(MdlCentralClientModeTransportProtocol.characteristicStateUuid.toString()),
				CBCharacteristicPropertyWriteWithoutResponse or CBCharacteristicPropertyWrite,
				null,
				CBAttributePermissionsWriteable
			),
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(MdlCentralClientModeTransportProtocol.characteristicClient2ServerUuid.toString()),
				CBCharacteristicPropertyWriteWithoutResponse or CBCharacteristicPropertyWrite,
				null,
				CBAttributePermissionsWriteable
			),
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(MdlCentralClientModeTransportProtocol.characteristicServer2ClientUuid.toString()),
				CBCharacteristicPropertyNotify,
				null,
				CBAttributePermissionsWriteable
			),
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(MdlCentralClientModeTransportProtocol.characteristicIdentUuid.toString()),
				CBCharacteristicPropertyNotify,
				null,
				CBAttributePermissionsReadable
			),
		).map { BleGattCharacteristic(it) }
	}
}
