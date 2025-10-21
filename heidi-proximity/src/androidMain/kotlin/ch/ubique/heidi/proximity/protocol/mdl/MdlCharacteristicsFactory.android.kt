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

import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.proximity.protocol.openid4vp.OpenId4VpTransportProtocol
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid

internal actual class MdlCharacteristicsFactory {
    internal actual fun createServerWalletCharacteristics(): List<BleGattCharacteristic> {
        val notify = BluetoothGattDescriptor(MdlPeripheralServerModeTransportProtocol.characteristicConfigurationUuid.toJavaUuid(),BluetoothGattDescriptor.PERMISSION_WRITE)
        val stateChar = BluetoothGattCharacteristic(
            MdlPeripheralServerModeTransportProtocol.characteristicStateUuid.toJavaUuid(),
            BluetoothGattCharacteristic.PROPERTY_NOTIFY or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        notify.setValue(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)
        stateChar.addDescriptor(notify)
        val server2ClientChar = BluetoothGattCharacteristic(
            MdlPeripheralServerModeTransportProtocol.characteristicServer2ClientUuid.toJavaUuid(),
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        val notify2 = BluetoothGattDescriptor(MdlPeripheralServerModeTransportProtocol.characteristicConfigurationUuid.toJavaUuid(),BluetoothGattDescriptor.PERMISSION_WRITE)
        notify2.setValue(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)
        server2ClientChar.addDescriptor(notify2)
        return listOf(
            stateChar,
            BluetoothGattCharacteristic(
                MdlPeripheralServerModeTransportProtocol.characteristicClient2ServerUuid.toJavaUuid(),
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE,
            ),
            server2ClientChar
        ).map { BleGattCharacteristic(it) }
    }

    internal actual fun createServerVerifierCharacteristics(): List<BleGattCharacteristic> {
        val notify = BluetoothGattDescriptor(MdlPeripheralServerModeTransportProtocol.characteristicConfigurationUuid.toJavaUuid(),BluetoothGattDescriptor.PERMISSION_WRITE)
        val stateChar = BluetoothGattCharacteristic(
            MdlCentralClientModeTransportProtocol.characteristicStateUuid.toJavaUuid(),
            BluetoothGattCharacteristic.PROPERTY_NOTIFY or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        notify.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
        stateChar.addDescriptor(notify)
        val server2ClientChar = BluetoothGattCharacteristic(
            MdlCentralClientModeTransportProtocol.characteristicServer2ClientUuid.toJavaUuid(),
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        val notify2 = BluetoothGattDescriptor(MdlPeripheralServerModeTransportProtocol.characteristicConfigurationUuid.toJavaUuid(),BluetoothGattDescriptor.PERMISSION_WRITE)
        notify2.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
        server2ClientChar.addDescriptor(notify2)

        val ident = BluetoothGattCharacteristic(MdlCentralClientModeTransportProtocol.characteristicIdentUuid.toJavaUuid(),
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_WRITE)

        return listOf(
            stateChar,
            BluetoothGattCharacteristic(
                MdlCentralClientModeTransportProtocol.characteristicClient2ServerUuid.toJavaUuid(),
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE,
            ),
            server2ClientChar,
            ident
        ).map { BleGattCharacteristic(it) }
    }
}
