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

import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import platform.CoreBluetooth.*

internal actual class OpenId4VpCharacteristicsFactory {

	internal actual fun createServerCharacteristics(): List<BleGattCharacteristic> {
		return listOf(
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(OpenId4VpTransportProtocol.charRequestSizeUuid.toString()),
				CBCharacteristicPropertyRead,
				null,
				CBAttributePermissionsReadable
			),
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(OpenId4VpTransportProtocol.charRequestUuid.toString()),
				CBCharacteristicPropertyRead,
				null,
				CBAttributePermissionsReadable
			),
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(OpenId4VpTransportProtocol.charIdentifyUuid.toString()),
				CBCharacteristicPropertyWrite or CBCharacteristicPropertyWriteWithoutResponse,
				null,
				CBAttributePermissionsWriteable
			),
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(OpenId4VpTransportProtocol.charContentSizeUuid.toString()),
				CBCharacteristicPropertyWrite or CBCharacteristicPropertyWriteWithoutResponse,
				null,
				CBAttributePermissionsWriteable
			),
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(OpenId4VpTransportProtocol.charSubmitVcUuid.toString()),
				CBCharacteristicPropertyWrite or CBCharacteristicPropertyWriteWithoutResponse,
				null,
				CBAttributePermissionsWriteable
			),
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(OpenId4VpTransportProtocol.charTransferSummaryRequestUuid.toString()),
				CBCharacteristicPropertyWrite or CBCharacteristicPropertyWriteWithoutResponse,
				null,
				CBAttributePermissionsWriteable
			),
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(OpenId4VpTransportProtocol.charTransferSummaryReportUuid.toString()),
				CBCharacteristicPropertyNotify,
				null,
				CBAttributePermissionsReadable
			),
			CBMutableCharacteristic(
				CBUUID.UUIDWithString(OpenId4VpTransportProtocol.charDisconnectUuid.toString()),
				CBCharacteristicPropertyNotify,
				null,
				CBAttributePermissionsReadable
			),
		).map { BleGattCharacteristic(it) }
	}

}
