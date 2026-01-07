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
import ch.ubique.heidi.proximity.di.HeidiProximityKoinComponent
import ch.ubique.heidi.proximity.protocol.BleTransportProtocol
import ch.ubique.heidi.proximity.protocol.TransportProtocol
import uniffi.heidi_crypto_rust.EphemeralKey
import uniffi.heidi_crypto_rust.SessionCipher
import uniffi.heidi_util_rust.Value
import kotlin.uuid.Uuid

internal class MdlTransportProtocol(
    role: Role,
    private val serviceUuidCentralMode: Uuid?,
    private val serviceUuidPeripheralMode: Uuid?,
    private val ephemeralKey: EphemeralKey,
    private val deviceMacAddress: String? = null
) : BleTransportProtocol(role), HeidiProximityKoinComponent, MdlTransportProtocolExtensions {
    var centralClientModeTransportProtocol: MdlCentralClientModeTransportProtocol?
    var peripheralServerModeTransportProtocol: MdlPeripheralServerModeTransportProtocol?
    override var sessionTranscript: Value?
        get() {
            if(centralClientModeTransportProtocol?.isConnected == true) {
                return centralClientModeTransportProtocol?.sessionTranscript
            }
            return peripheralServerModeTransportProtocol?.sessionTranscript
        }
        set(value) {
            TODO("Session Transcript should not be overridden")
        }
    init {
        centralClientModeTransportProtocol = if (serviceUuidCentralMode != null) { MdlCentralClientModeTransportProtocol(role, serviceUuidCentralMode, ephemeralKey, deviceMacAddress) } else { null }
        peripheralServerModeTransportProtocol = if(serviceUuidPeripheralMode != null){ MdlPeripheralServerModeTransportProtocol(role, serviceUuidPeripheralMode, ephemeralKey, deviceMacAddress) } else {
            null
        }
        if(centralClientModeTransportProtocol?.isSupported() == false) {
            centralClientModeTransportProtocol = null
        }
        if(peripheralServerModeTransportProtocol?.isSupported() == false) {
            peripheralServerModeTransportProtocol = null
        }
        if (peripheralServerModeTransportProtocol != null && centralClientModeTransportProtocol != null) {
            peripheralServerModeTransportProtocol = null
        }
    }

    override fun getMessage(): ByteArray? {
        if(centralClientModeTransportProtocol?.isConnected == true) {
            return centralClientModeTransportProtocol?.getMessage()
        }
        if(peripheralServerModeTransportProtocol?.isConnected == true) {
            return peripheralServerModeTransportProtocol?.getMessage()
        }
        return null
    }
    override fun setListener(listener: Listener) {
        centralClientModeTransportProtocol?.setListener(listener)
        peripheralServerModeTransportProtocol?.setListener(listener)
    }
    override suspend fun connect() {
        centralClientModeTransportProtocol?.connect()
        peripheralServerModeTransportProtocol?.connect()
    }

    override fun disconnect() {
        if(centralClientModeTransportProtocol?.isConnected == true) {
            centralClientModeTransportProtocol?.disconnect()
        }
        if(peripheralServerModeTransportProtocol?.isConnected == true) {
            peripheralServerModeTransportProtocol?.disconnect()
        }
    }

    override fun sendMessage(data: ByteArray, onProgress: ((sent: Int, total: Int) -> Unit)?) {
        if(centralClientModeTransportProtocol?.isConnected == true) {
            centralClientModeTransportProtocol?.sendMessage(data, onProgress)
        }
        if(peripheralServerModeTransportProtocol?.isConnected == true) {
            peripheralServerModeTransportProtocol?.sendMessage(data, onProgress)
        }
    }

    override fun sendTransportSpecificTerminationMessage() {
        if(centralClientModeTransportProtocol?.isConnected == true && centralClientModeTransportProtocol?.supportsTransportSpecificTerminationMessage() == true) {
            centralClientModeTransportProtocol?.sendTransportSpecificTerminationMessage()
        }
        if(peripheralServerModeTransportProtocol?.isConnected == true && peripheralServerModeTransportProtocol?.supportsTransportSpecificTerminationMessage() == true) {
            peripheralServerModeTransportProtocol?.sendTransportSpecificTerminationMessage()
        }
    }

    override fun supportsTransportSpecificTerminationMessage(): Boolean {
       return centralClientModeTransportProtocol?.supportsTransportSpecificTerminationMessage() == true || peripheralServerModeTransportProtocol?.supportsTransportSpecificTerminationMessage() == true
    }

    override fun getSessionCipher(
        engagementBytes: ByteArray,
        eReaderKeyBytes: ByteArray,
        peerCoseKey: ByteArray?
    ): SessionCipher {
//        if(centralClientModeTransportProtocol?.isConnected == true) {
//            return centralClientModeTransportProtocol!!.getSessionCipher(engagementBytes, eReaderKeyBytes, peerCoseKey)
//        }
        if(centralClientModeTransportProtocol != null) {
            return centralClientModeTransportProtocol!!.getSessionCipher(engagementBytes, eReaderKeyBytes, peerCoseKey)
        }
        return peripheralServerModeTransportProtocol!!.getSessionCipher(engagementBytes, eReaderKeyBytes, peerCoseKey)
    }

}
