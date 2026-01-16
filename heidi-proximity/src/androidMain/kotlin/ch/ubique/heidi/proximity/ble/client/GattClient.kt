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
import ch.ubique.heidi.proximity.protocol.mdl.MdlPeripheralServerModeTransportProtocol
import ch.ubique.heidi.proximity.ble.server.ChunkAccumulator
import ch.ubique.heidi.proximity.ble.server.ChunkProcessingResult
import ch.ubique.heidi.util.log.Logger
import java.lang.reflect.InvocationTargetException
import java.util.ArrayDeque
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

    private val chunkAccumulator = ChunkAccumulator<UUID>()
    private val writeQueues = WriteQueueManager()

    private var cachedCharacteristicValueSize = 0
    override val characteristicValueSize: Int
        get() {
            if (cachedCharacteristicValueSize > 0) {
                return cachedCharacteristicValueSize
            }
            var mtuSize = negotiatedMtu
            if (mtuSize == 0) {
                Logger(TAG).warn("MTU not negotiated, defaulting to 23. Performance will suffer.")
                mtuSize = 23
            }
            cachedCharacteristicValueSize = BleTransportProtocol.bleCalculateAttributeValueSize(mtuSize)
            return cachedCharacteristicValueSize
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

    override fun writeCharacteristic(
        charUuid: Uuid,
        data: ByteArray,
        onProgress: ((sent: Int, total: Int) -> Unit)?
    ) {
        val targetUuid = charUuid.toJavaUuid()
        val shouldDrain = writeQueues.wasEmpty(targetUuid)

        val progress = onProgress?.let { WriteProgress(total = data.size, onProgress = it) }
        chunkMessage(data) { chunk ->
            val payloadSize = (chunk.size - 1).coerceAtLeast(0)
            writeQueues.enqueue(targetUuid, PendingWrite(chunk, progress, payloadSize))
        }

        if (shouldDrain) {
            drainWritingQueue(targetUuid)
        }
    }

    override fun writeCharacteristicNonChunked(
        charUuid: Uuid,
        data: ByteArray,
        onProgress: ((sent: Int, total: Int) -> Unit)?
    ) {
        val targetUuid = charUuid.toJavaUuid()
        val shouldDrain = writeQueues.wasEmpty(targetUuid)

        val progress = onProgress?.let { WriteProgress(total = data.size, onProgress = it) }
        writeQueues.enqueue(targetUuid, PendingWrite(data, progress, data.size))

        if (shouldDrain) {
            drainWritingQueue(targetUuid)
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

        requireGatt().writeDescriptorCompat(descriptor, data)
    }

    override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
        when (newState) {
            BluetoothProfile.STATE_CONNECTED -> {
                try {
                    if (clearCache) {
                        clearCache(gatt)
                    }

                    mtuRequested = false
                    cachedCharacteristicValueSize = 0

                    gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
                    gatt.discoverServices()
                } catch (e: SecurityException) {
                    reportError(e)
                }
            }
            BluetoothProfile.STATE_DISCONNECTED -> {
                chunkAccumulator.clear()
                writeQueues.clear()
                coordinator.reset()
                mtuRequested = false
                cachedCharacteristicValueSize = 0
                reportPeerDisconnected()
            }
        }
    }

    private val coordinator = Coordinator { gatt -> requestMtuSafely(gatt) }
    private var mtuRequested = false

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


    override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
        if (status != BluetoothGatt.GATT_SUCCESS) return
        val service = gatt.services.any { it.uuid == serviceUuid }
        if (!service) { reportError(Error("Service $serviceUuid not discovered")); return }

        characteristics = requireListener().onServicesDiscovered(gatt.services.map { BleGattService(it) })

        coordinator.reset()

        characteristics.forEach { c ->
            val characteristic = c.characteristic
            val supportsNotify = (characteristic.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY) != 0
            val supportsIndicate = (characteristic.properties and BluetoothGattCharacteristic.PROPERTY_INDICATE) != 0
            val shouldEnable = c.supportsNotifications && (supportsNotify || supportsIndicate)

            gatt.setCharacteristicNotification(characteristic, shouldEnable)

            val cccd = characteristic.getDescriptor(
                MdlPeripheralServerModeTransportProtocol.characteristicConfigurationUuid.toJavaUuid()
            )

            if (cccd != null && shouldEnable) {
                val value = if (supportsIndicate) {
                    BluetoothGattDescriptor.ENABLE_INDICATION_VALUE
                } else {
                    BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                }
                coordinator.enqueue(cccd, value)
            }
        }

        if (coordinator.hasPendingDescriptors()) {
            coordinator.deferMtuUntilComplete()
            coordinator.flush(gatt)
        } else {
            requestMtuSafely(gatt)
        }

        this.gatt = gatt
    }


    override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
        if (status != BluetoothGatt.GATT_SUCCESS) {
            reportError(Error("Error changing MTU, status: $status"))
            return
        }
        Logger(TAG).debug("Successfully changed MTU, reporting to listeners")
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
        when (val result = chunkAccumulator.consume(characteristic.uuid, value)) {
            is ChunkProcessingResult.Complete -> {
                requireListener().onCharacteristicRead(
                    BleGattCharacteristic(characteristic, result.payload)
                )
            }
            ChunkProcessingResult.Waiting -> {
                gatt.readCharacteristic(characteristic)
            }
            is ChunkProcessingResult.Single -> {
                requireListener().onCharacteristicRead(
                    BleGattCharacteristic(characteristic, result.payload)
                )
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
        if (writeQueues.isEmpty(charUuid)) {
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
        when (val result = chunkAccumulator.consume(characteristic.uuid, value)) {
            is ChunkProcessingResult.Complete -> {
                requireListener().onCharacteristicChanged(
                    BleGattCharacteristic(characteristic, result.payload)
                )
            }
            ChunkProcessingResult.Waiting -> Unit
            is ChunkProcessingResult.Single -> {
                requireListener().onCharacteristicChanged(
                    BleGattCharacteristic(characteristic, result.payload)
                )
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
        coordinator.onDescriptorWriteComplete(gatt)
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

    private fun findCharacteristic(charUuid: UUID): BluetoothGattCharacteristic? {
        return characteristics.singleOrNull { it.uuid?.toJavaUuid() == charUuid }?.characteristic
    }

    private fun drainWritingQueue(charUuid: UUID) {
        Logger(TAG).debug("Some commands are not finished yet:  ${coordinator.hasPendingDescriptors()}")
        val chunk = writeQueues.poll(charUuid) ?: return

        if (chunk.isShutdownMessage()) {
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
                chunkAccumulator.clear()
                writeQueues.clear()
                coordinator.reset()
                mtuRequested = false
                cachedCharacteristicValueSize = 0
            }
        } else {
            val characteristic = findCharacteristic(charUuid)
            if (characteristic == null) {
                reportError(Error("No characteristic found for UUID $charUuid"))
                return
            }

            try {
                val success = requireGatt().writeCharacteristicCompat(characteristic, chunk.payload)

                if (!success) {
                    reportError(Error("Error writing characteristic $charUuid"))
                    return
                }
                chunk.progress?.advance(chunk.payloadSize)
            } catch (e: SecurityException) {
                reportError(e)
            }
        }
    }

    private fun BluetoothGatt.writeDescriptorCompat(descriptor: BluetoothGattDescriptor, data: ByteArray) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            writeDescriptor(descriptor, data)
        } else {
            @Suppress("DEPRECATION")
            run {
                descriptor.setValue(data)
                writeDescriptor(descriptor)
            }
        }
    }

    private fun BluetoothGatt.writeCharacteristicCompat(
        characteristic: BluetoothGattCharacteristic,
        data: ByteArray
    ): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            writeCharacteristic(
                characteristic,
                data,
                BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            ) == BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            run {
                characteristic.setValue(data)
                writeCharacteristic(characteristic)
            }
        }
    }

    private class WriteQueueManager {
        private val queues = mutableMapOf<UUID, ArrayDeque<PendingWrite>>()

        fun wasEmpty(uuid: UUID): Boolean = queues[uuid]?.isEmpty() ?: true

        fun enqueue(uuid: UUID, data: PendingWrite) {
            queues.getOrPut(uuid) { ArrayDeque() }.addLast(data)
        }

        fun poll(uuid: UUID): PendingWrite? {
            val queue = queues[uuid] ?: return null
            val result = if (queue.isEmpty()) null else queue.removeFirst()
            if (queue.isEmpty()) {
                queues.remove(uuid)
            }
            return result
        }

        fun isEmpty(uuid: UUID): Boolean = queues[uuid]?.isEmpty() ?: true

        fun clear() {
            queues.clear()
        }
    }

    private data class PendingWrite(
        val payload: ByteArray,
        val progress: WriteProgress? = null,
        val payloadSize: Int = payload.size
    ) {
        fun isShutdownMessage(): Boolean {
            return payload.size == 1 && payload.single() == TransportProtocol.SHUTDOWN_MESSAGE.single()
        }
    }

    private class WriteProgress(
        private val total: Int,
        private val onProgress: ((sent: Int, total: Int) -> Unit)?
    ) {
        private var sent: Int = 0

        fun advance(by: Int) {
            if (total <= 0) {
                onProgress?.invoke(1, 1)
                return
            }
            sent = (sent + by).coerceAtMost(total)
            onProgress?.invoke(sent, total)
        }
    }

    private data class PendingDescriptor(
        val descriptor: BluetoothGattDescriptor,
        val value: ByteArray
    )

    private inner class Coordinator(
        private val onAllDescriptorsWritten: (BluetoothGatt) -> Unit
    ) {
        private val queue = ArrayDeque<PendingDescriptor>()
        private var inFlight = false
        private var mtuDeferred = false

        fun reset() {
            queue.clear()
            inFlight = false
            mtuDeferred = false
        }

        fun enqueue(descriptor: BluetoothGattDescriptor, value: ByteArray) {
            queue.addLast(PendingDescriptor(descriptor, value))
        }

        fun hasPendingDescriptors(): Boolean = queue.isNotEmpty()

        fun deferMtuUntilComplete() {
            mtuDeferred = true
        }

        fun flush(gatt: BluetoothGatt) {
            if (inFlight) return
            val next = if (queue.isEmpty()) null else queue.removeFirst()
            if (next == null) {
                if (mtuDeferred) {
                    mtuDeferred = false
                    onAllDescriptorsWritten(gatt)
                }
                return
            }

            inFlight = true
            gatt.writeDescriptorCompat(next.descriptor, next.value)
        }

        fun onDescriptorWriteComplete(gatt: BluetoothGatt) {
            inFlight = false
            flush(gatt)
        }
    }
}
