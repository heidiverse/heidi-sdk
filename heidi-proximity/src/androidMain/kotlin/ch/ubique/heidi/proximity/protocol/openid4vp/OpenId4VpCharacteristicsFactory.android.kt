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

import android.bluetooth.BluetoothGattCharacteristic
import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import kotlin.uuid.toJavaUuid

internal actual class OpenId4VpCharacteristicsFactory {

	internal actual fun createServerCharacteristics(): List<BleGattCharacteristic> {
		return listOf(
			BluetoothGattCharacteristic(
				OpenId4VpTransportProtocol.charRequestSizeUuid.toJavaUuid(),
				BluetoothGattCharacteristic.PROPERTY_READ,
				BluetoothGattCharacteristic.PERMISSION_READ,
			),
			BluetoothGattCharacteristic(
				OpenId4VpTransportProtocol.charRequestUuid.toJavaUuid(),
				BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
				BluetoothGattCharacteristic.PERMISSION_READ,
			),
			BluetoothGattCharacteristic(
				OpenId4VpTransportProtocol.charIdentifyUuid.toJavaUuid(),
				BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
				BluetoothGattCharacteristic.PERMISSION_WRITE,
			),
			BluetoothGattCharacteristic(
				OpenId4VpTransportProtocol.charContentSizeUuid.toJavaUuid(),
				BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
				BluetoothGattCharacteristic.PERMISSION_WRITE,
			),
			BluetoothGattCharacteristic(
				OpenId4VpTransportProtocol.charSubmitVcUuid.toJavaUuid(),
				BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
				BluetoothGattCharacteristic.PERMISSION_WRITE,
			),
			BluetoothGattCharacteristic(
				OpenId4VpTransportProtocol.charTransferSummaryRequestUuid.toJavaUuid(),
				BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
				BluetoothGattCharacteristic.PERMISSION_WRITE,
			),
			BluetoothGattCharacteristic(
				OpenId4VpTransportProtocol.charTransferSummaryReportUuid.toJavaUuid(),
				BluetoothGattCharacteristic.PROPERTY_NOTIFY,
				BluetoothGattCharacteristic.PERMISSION_READ,
			),
			BluetoothGattCharacteristic(
				OpenId4VpTransportProtocol.charDisconnectUuid.toJavaUuid(),
				BluetoothGattCharacteristic.PROPERTY_NOTIFY,
				BluetoothGattCharacteristic.PERMISSION_READ,
			),
		).map { BleGattCharacteristic(it) }
	}

}
