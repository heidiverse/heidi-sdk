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

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.proximity.ble.gatt.BleGattService
import ch.ubique.heidi.proximity.protocol.BleTransportProtocol
import ch.ubique.heidi.proximity.protocol.TransportProtocol
import ch.ubique.heidi.proximity.protocol.mdl.MdlCentralClientModeTransportProtocol
import ch.ubique.heidi.proximity.protocol.mdl.MdlPeripheralServerModeTransportProtocol
import ch.ubique.heidi.util.log.Logger
import java.io.ByteArrayOutputStream
import java.lang.reflect.InvocationTargetException
import java.util.ArrayDeque
import java.util.Queue
import java.util.UUID
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid

@SuppressLint("MissingPermission")
internal class GattClient(
    private val context: Context,
    private val bluetoothManager: BluetoothManager,
    private val serviceUuid: UUID,
    private val encodedEphemeralDeviceKey: ByteArray?, // TODO Use for session encryption
) : BluetoothGattCallback(), BleGattClient {

    companion object {
        private const val TAG = "GattClient"

        private val SHUTDOWN_UUID = Uuid.random()
    }

    private var clearCache = false

    private var listener: BleGattClientListener? = null
    private var inhibitCallbacks = false

    private var characteristics: List<BleGattCharacteristic> = emptyList()

    private var isConnecting = false
    private var gatt: BluetoothGatt? = null
    private var negotiatedMtu = 0

    private val incomingMessages = mutableMapOf<UUID, ByteArrayOutputStream>().withDefault { ByteArrayOutputStream() }
    private val writingQueues = mutableMapOf<UUID, Queue<ByteArray>>().withDefault { ArrayDeque() }

    private var mCharacteristicValueSize = 0
    override val characteristicValueSize: Int
        get() {
            if (mCharacteristicValueSize > 0) {
                return mCharacteristicValueSize
            }
            var mtuSize = negotiatedMtu
            if (mtuSize == 0) {
                Logger(TAG).warn("MTU not negotiated, defaulting to 23. Performance will suffer.")
                mtuSize = 23
            }
            mCharacteristicValueSize = BleTransportProtocol.bleCalculateAttributeValueSize(mtuSize)
            return mCharacteristicValueSize
        }

    private var scanner: BluetoothLeScanner? = null
    private var scannerListener: BleScannerListener? = null
    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            // Ignore scan results if we're already connecting or connected
            if (isConnecting || gatt != null) {
                return
            }

            isConnecting = true
            val device = result.device
            connectToDevice(device)

            stopScanning()
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>?) {}

        override fun onScanFailed(errorCode: Int) {
            reportError(Error("BLE scan failed with error code $errorCode"))
        }
    }

    override fun setListener(listener: BleGattClientListener?) {
        this.listener = listener
    }

    override fun connect(deviceMacAddress: String) {
        try {
            isConnecting = true
            val bluetoothAdapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
            val device = bluetoothAdapter.getRemoteDevice(deviceMacAddress)
            connectToDevice(device)
        } catch (e: Exception) {
            isConnecting = false
            reportError(e)
        }
    }

    override fun startScanning(listener: BleScannerListener) {
        scannerListener = listener

        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(serviceUuid))
            .build()
        val settings = ScanSettings.Builder()
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        try {
            scanner = bluetoothManager.adapter.bluetoothLeScanner.also {
                it.startScan(listOf(filter), settings, scanCallback)
            }
        } catch (e: Exception) {
            scannerListener?.onError(e.message ?: e.javaClass.simpleName)
        }
    }

    override fun stopScanning() {
        isConnecting = false
        try {
            scanner?.stopScan(scanCallback)
        } catch (e: Exception) {
            scannerListener?.onError(e.message ?: e.javaClass.simpleName)
        } finally {
            scanner = null
        }
    }

    override fun supportsSessionTermination(): Boolean {
        return true
    }

    override fun disconnect() {
        inhibitCallbacks = true
        if (gatt != null) {
            // used to convey we want to shutdown once all writes are done.
            writeCharacteristicNonChunked(SHUTDOWN_UUID, TransportProtocol.SHUTDOWN_MESSAGE)
        }
    }

    override fun readCharacteristic(charUuid: Uuid) {
        val characteristic = requireGatt().getService(serviceUuid)?.getCharacteristic(charUuid.toJavaUuid())
        if (characteristic == null) {
            reportError(Error("Characteristic $charUuid not found"))
            return
        }

        try {
            if (!requireGatt().readCharacteristic(characteristic)) {
                reportError(Error("Error reading characteristic $charUuid"))
            }
        } catch (e: SecurityException) {
            reportError(e)
        }
    }

    override fun writeCharacteristic(charUuid: Uuid, data: ByteArray) {
        // Only initiate the write if no other write was outstanding.
        val queueNeedsDraining = writingQueues.getValue(charUuid.toJavaUuid()).size == 0

        chunkMessage(data) { chunk ->
            writingQueues.getOrPut(charUuid.toJavaUuid()) { ArrayDeque() }.add(chunk)
        }

        if (queueNeedsDraining) {
            drainWritingQueue(charUuid.toJavaUuid())
        }
    }
    override fun writeCharacteristicNonChunked(charUuid: Uuid, data: ByteArray) {
        // Only initiate the write if no other write was outstanding.
        val queueNeedsDraining = writingQueues.getValue(charUuid.toJavaUuid()).size == 0

        writingQueues.getOrPut(charUuid.toJavaUuid()) { ArrayDeque() }.add(data)

        if (queueNeedsDraining) {
            drainWritingQueue(charUuid.toJavaUuid())
        }
    }

    override fun readDescriptor(charUuid: Uuid, descriptorUuid: Uuid) {
        val characteristic = requireGatt().getService(serviceUuid)?.getCharacteristic(charUuid.toJavaUuid())
        if (characteristic == null) {
            reportError(Error("Characteristic $charUuid not found"))
            return
        }

        val descriptor = characteristic.getDescriptor(descriptorUuid.toJavaUuid())
        if (descriptor == null) {
            reportError(Error("Descriptor $descriptorUuid not found"))
            return
        }

        requireGatt().readDescriptor(descriptor)
    }

    @Suppress("DEPRECATION")
    override fun writeDescriptor(charUuid: Uuid, descriptorUuid: Uuid, data: ByteArray) {
        val characteristic = requireGatt().getService(serviceUuid)?.getCharacteristic(charUuid.toJavaUuid())
        if (characteristic == null) {
            reportError(Error("Characteristic $charUuid not found"))
            return
        }

        val descriptor = characteristic.getDescriptor(descriptorUuid.toJavaUuid())
        if (descriptor == null) {
            reportError(Error("Descriptor $descriptorUuid not found"))
            return
        }

		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requireGatt().writeDescriptor(descriptor, data)
        } else {
            descriptor.setValue(data)
            requireGatt().writeDescriptor(descriptor)
        }
	}

    override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
        when (newState) {
            BluetoothProfile.STATE_CONNECTED -> {
                try {
                    if (clearCache) {
                        clearCache(gatt)
                    }

                    gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
                    gatt.discoverServices()
                } catch (e: SecurityException) {
                    reportError(e)
                }
            }
            BluetoothProfile.STATE_DISCONNECTED -> {
                reportPeerDisconnected()
            }
        }
    }

    private val cccdQueue: ArrayDeque<Pair<BluetoothGattDescriptor, ByteArray>> = ArrayDeque()
    private var cccdInFlight = false
    private var mtuRequested = false
    private var deferMtuUntilCccdDone = false

    // Start by bumping MTU, callback in onMtuChanged()...
    //
    // Which MTU should we choose? On Android the maximum MTU size is said to be 517.
    //
    // Also 18013-5 section 8.3.3.1.1.6 Data retrieval says to write attributes to
    // Client2Server and Server2Client characteristics of a size which 3 less the
    // MTU size. If we chose an MTU of 517 then the attribute we'd write would be
    // 514 bytes long.
    //
    // Also note that Bluetooth Core specification Part F section 3.2.9 Long attribute
    // values says "The maximum length of an attribute value shall be 512 octets." ... so
    // with an MTU of 517 we'd blow through that limit. An MTU limited to 515 bytes
    // will work though.
    //
    // ... so we request 515 bytes for the MTU. We might not get such a big MTU, the way
    // it works is that the requestMtu() call will trigger a negotiation between the client (us)
    // and the server (the remote device).
    //
    // We'll get notified in BluetoothGattCallback.onMtuChanged() below.
    //
    // The server will also be notified about the new MTU - if it's running Android
    // it'll be via BluetoothGattServerCallback.onMtuChanged(), see GattServer.java
    // for that in our implementation.
    private fun requestMtuSafely(gatt: BluetoothGatt, size: Int = 515) {
        if (mtuRequested) return
        try {
            if (!gatt.requestMtu(size)) {
                reportError(Error("Error requesting MTU"))
            } else {
                mtuRequested = true
            }
        } catch (e: SecurityException) {
            reportError(e)
        }
    }

    private fun enqueueCccd(descriptor: BluetoothGattDescriptor, value: ByteArray) {
        cccdQueue.add(descriptor to value)
    }

    private fun writeNextCccd(gatt: BluetoothGatt) {
        val next = cccdQueue.poll()
        if (next == null) {
            cccdInFlight = false
            // All CCCDs done → now request MTU if we were deferring it
            if (deferMtuUntilCccdDone && !mtuRequested) {
                requestMtuSafely(gatt)
            }
            return
        }

        cccdInFlight = true
        val (desc, value) = next
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gatt.writeDescriptor(desc, value)
        } else {
            @Suppress("DEPRECATION")
            run {
                desc.value = value
                gatt.writeDescriptor(desc)
            }
        }
    }


    override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
        if (status != BluetoothGatt.GATT_SUCCESS) return
        val service = gatt.services.any { it.uuid == serviceUuid }
        if (!service) { reportError(Error("Service $serviceUuid not discovered")); return }

        characteristics = requireListener().onServicesDiscovered(gatt.services.map { BleGattService(it) })

        // Prepare CCCD writes
        characteristics.forEach { c ->
            val ch = c.characteristic
            val supportsNotify   = (ch.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY) != 0
            val supportsIndicate = (ch.properties and BluetoothGattCharacteristic.PROPERTY_INDICATE) != 0
            val shouldEnable = c.supportsNotifications && (supportsNotify || supportsIndicate)

            gatt.setCharacteristicNotification(ch, shouldEnable)

            val cccd = ch.getDescriptor(
                MdlPeripheralServerModeTransportProtocol.characteristicConfigurationUuid.toJavaUuid()
            )

            if (cccd != null && shouldEnable) {
                val v = if (supportsIndicate)
                    BluetoothGattDescriptor.ENABLE_INDICATION_VALUE
                else
                    BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE

                enqueueCccd(cccd, v)
            }
        }

        // If there are CCCDs to write, defer MTU until they’re done.
        deferMtuUntilCccdDone = cccdQueue.isNotEmpty()

        // Kick off CCCD writes (one at a time) or request MTU immediately if none.
        if (deferMtuUntilCccdDone) {
            writeNextCccd(gatt)
        } else {
            requestMtuSafely(gatt) // no CCCDs to write
        }

        this.gatt = gatt
    }


    override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
        if (status != BluetoothGatt.GATT_SUCCESS) {
            reportError(Error("Error changing MTU, status: $status"))
            return
        }

        negotiatedMtu = mtu
        requireListener().onMtuChanged(mtu)

        // Once the MTU is changed, consider the connection as established
        reportPeerConnected()
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onCharacteristicRead(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        status: Int
    ) {
        this.onCharacteristicRead(gatt, characteristic, characteristic.value, status)
    }

    override fun onCharacteristicRead(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
        status: Int
    ) {
        val charUuid = characteristic.uuid
        when (value.firstOrNull()?.toInt()) {
            0x00 -> {
                // First byte indicates that this is the last chunk of the message
                incomingMessages.getOrPut(charUuid) { ByteArrayOutputStream() }.write(value, 1, value.size - 1)
                val entireMessage = incomingMessages.getValue(charUuid).toByteArray()
                incomingMessages.getValue(charUuid).reset()

                requireListener().onCharacteristicRead(BleGattCharacteristic(characteristic, entireMessage))
            }
            0x01 -> {
                // First byte indicates that more chunks are coming
                incomingMessages.getOrPut(charUuid) { ByteArrayOutputStream() }.write(value, 1, value.size - 1)

                // Trigger a read of the next chunk
                gatt.readCharacteristic(characteristic)
            }
            else -> {
                // Unknown if this message is chunked or not, so just send it in the callback
                requireListener().onCharacteristicRead(BleGattCharacteristic(characteristic, value))
            }
        }
    }

    override fun onCharacteristicWrite(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        status: Int
    ) {
        // If the characteristic write was completed, check if this characteristic has more chunks in the writing queue or else notify the listener about a successful write
        val charUuid = characteristic.uuid
        val isWritingQueueEmpty = writingQueues.getValue(charUuid).isEmpty()
        if (isWritingQueueEmpty) {
            requireListener().onCharacteristicWrite(BleGattCharacteristic(characteristic))
        } else {
            drainWritingQueue(characteristic.uuid)
        }

    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onCharacteristicChanged(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic
    ) {
        this.onCharacteristicChanged(gatt, characteristic, characteristic.value)
    }

    override fun onCharacteristicChanged(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray
    ) {
        val charUuid = characteristic.uuid
        when (value.firstOrNull()?.toInt()){
            0x00 -> {
                // First byte indicates that this is the last chunk of the message
                incomingMessages.getOrPut(charUuid) { ByteArrayOutputStream() } .write(value, 1, value.size - 1)
                val entireMessage = incomingMessages.getValue(charUuid).toByteArray()
                incomingMessages.getValue(charUuid).reset()

                requireListener().onCharacteristicChanged(BleGattCharacteristic(characteristic, entireMessage))
            }
            0x01 -> {
                // First byte indicates that more chunks are coming
                incomingMessages.getOrPut(charUuid) { ByteArrayOutputStream() }.write(value, 1, value.size - 1)
            }
             else -> {
                 // Unknown if this message is chunked or not, so just send it in the callback
                 requireListener().onCharacteristicChanged(BleGattCharacteristic(characteristic, value))
             }
        }
    }

    override fun onDescriptorRead(
        gatt: BluetoothGatt,
        descriptor: BluetoothGattDescriptor,
        status: Int,
        value: ByteArray,
    ) {
        requireListener().onDescriptorRead(descriptor)
    }

    override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
        requireListener().onDescriptorWrite(descriptor)
        // Continue the CCCD queue; when it empties, MTU will be requested.
        writeNextCccd(gatt)
    }

    private fun reportPeerConnecting() {
        if (inhibitCallbacks) return
        requireListener().onPeerConnecting()
    }

    private fun reportPeerConnected() {
        if (inhibitCallbacks) return
        requireListener().onPeerConnected()
    }

    private fun reportPeerDisconnected() {
        if (inhibitCallbacks) return
        requireListener().onPeerDisconnected()
    }

    private fun reportError(error: Throwable) {
        if (inhibitCallbacks) return
        requireListener().onError(error)
    }

    private fun requireGatt(): BluetoothGatt {
        return gatt ?: throw IllegalStateException("Gatt not set")
    }

    private fun requireListener(): BleGattClientListener {
        return listener ?: throw IllegalStateException("Listener not set")
    }

    private fun connectToDevice(device: BluetoothDevice) {
        reportPeerConnecting()

        try {
            gatt = device.connectGatt(context, false, this, BluetoothDevice.TRANSPORT_LE)
        } catch (e: SecurityException) {
            reportError(e)
        } finally {
            isConnecting = false
        }
    }

    private fun clearCache(gatt: BluetoothGatt) {
        Logger(TAG).debug("Application requested clearing BLE Service Cache")
        // BluetoothGatt.refresh() is not public API but can be accessed via introspection...
        try {
            val refreshMethod = gatt.javaClass.getMethod("refresh")
            var result = false
            if (refreshMethod != null) {
                result = refreshMethod.invoke(gatt) as Boolean
            }
            if (result) {
                Logger(TAG).debug("BluetoothGatt.refresh() invoked successfully")
            } else {
                Logger(TAG).error("BluetoothGatt.refresh() invoked but returned false")
            }
        } catch (e: NoSuchMethodException) {
            Logger(TAG).error("Getting BluetoothGatt.refresh() failed with NoSuchMethodException", e)
        } catch (e: IllegalAccessException) {
            Logger(TAG).error("Getting BluetoothGatt.refresh() failed with IllegalAccessException", e)
        } catch (e: InvocationTargetException) {
            Logger(TAG).error("Getting BluetoothGatt.refresh() failed with InvocationTargetException", e)
        }
    }

//    private fun chunkMessage(data: ByteArray, emitChunk: (ByteArray) -> Unit) {
//        // Also need room for the leading 0x00 or 0x01.
//        val maxDataSize = characteristicValueSize - 1
//        var offset = 0
//        do {
//            val moreDataComing = offset + maxDataSize < data.size
//            var size = data.size - offset
//            if (size > maxDataSize) {
//                size = maxDataSize
//            }
//            val chunk = ByteArray(size + 1)
//            chunk[0] = if (moreDataComing) 0x01.toByte() else 0x00.toByte()
//            System.arraycopy(data, offset, chunk, 1, size)
//            emitChunk(chunk)
//            offset += size
//        } while (offset < data.size)
//    }

    @Suppress("DEPRECATION")
    private fun drainWritingQueue(charUuid: UUID) {
        val chunk = writingQueues.getValue(charUuid).poll() ?: return

        if (chunk.size == 1 && chunk.single() == TransportProtocol.SHUTDOWN_MESSAGE.single()) {
            Logger(TAG).debug("Chunk is length 0, shutting down GattClient in 1000ms")
            // TODO: On some devices we lose messages already sent if we don't have a delay like
            //  this. Need to properly investigate if this is a problem in our stack or the
            //  underlying BLE subsystem.
            Thread.sleep(1000)
            Logger(TAG).debug("Shutting down GattClient now")

            try {
                /*
                [https://medium.com/android-news/lessons-for-first-time-android-bluetooth-le-developers-i-learned-the-hard-way-fee07646624]
                calling bluetoothDevice.disconnect() right before bluetoothDevice.close() is redundant and can result in issues in some devices. Try using only close() instead.
                 */
//                requireGatt().disconnect()
                requireGatt().close()
            } catch (e: SecurityException) {
                Logger(TAG).error("Caught SecurityException while shutting down", e)
            } finally {
            	gatt = null
            }
        } else {
            val characteristic = characteristics.singleOrNull { it.uuid?.toJavaUuid() == charUuid }?.characteristic
            if (characteristic == null) {
                reportError(Error("No characteristic found for UUID $charUuid"))
                return
            }

            try {
                val success = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val result = requireGatt().writeCharacteristic(characteristic, chunk, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
                    result == BluetoothStatusCodes.SUCCESS
				} else {
                    characteristic.setValue(chunk)
                    requireGatt().writeCharacteristic(characteristic)
				}

				if (!success) {
                    reportError(Error("Error writing characteristic $charUuid"))
                    return
                }
            } catch (e: SecurityException) {
                reportError(e)
            }
        }
    }
}
