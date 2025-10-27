package ch.ubique.heidi.proximity.ble.server

import kotlinx.cinterop.ObjCSignatureOverride
import platform.CoreBluetooth.CBATTRequest
import platform.CoreBluetooth.CBCentral
import platform.CoreBluetooth.CBCharacteristic
import platform.CoreBluetooth.CBPeripheralManager
import platform.CoreBluetooth.CBPeripheralManagerDelegateProtocol
import platform.CoreBluetooth.CBService
import platform.Foundation.NSError
import platform.darwin.NSObject

internal class GattServerDelegate(
    private val handler: Handler
) : NSObject(), CBPeripheralManagerDelegateProtocol {

    internal interface Handler {
        fun onStateUpdated(peripheral: CBPeripheralManager)
        fun onRead(peripheral: CBPeripheralManager, request: CBATTRequest)
        fun onWrite(peripheral: CBPeripheralManager, requests: List<*>)
        fun onStartAdvertising(peripheral: CBPeripheralManager, error: NSError?)
        fun onAddService(peripheral: CBPeripheralManager, service: CBService, error: NSError?)
        fun onReadyToUpdateSubscribers(peripheral: CBPeripheralManager)
        fun onSubscribe(peripheral: CBPeripheralManager, central: CBCentral, characteristic: CBCharacteristic)
    }

    override fun peripheralManagerDidUpdateState(peripheral: CBPeripheralManager) {
        handler.onStateUpdated(peripheral)
    }

    override fun peripheralManager(
        peripheral: CBPeripheralManager,
        didReceiveReadRequest: CBATTRequest
    ) {
        handler.onRead(peripheral, didReceiveReadRequest)
    }

    override fun peripheralManager(
        peripheral: CBPeripheralManager,
        didReceiveWriteRequests: List<*>
    ) {
        handler.onWrite(peripheral, didReceiveWriteRequests)
    }

    override fun peripheralManagerDidStartAdvertising(
        peripheral: CBPeripheralManager,
        error: NSError?
    ) {
        handler.onStartAdvertising(peripheral, error)
    }

    override fun peripheralManager(
        peripheral: CBPeripheralManager,
        didAddService: CBService,
        error: NSError?
    ) {
        handler.onAddService(peripheral, didAddService, error)
    }

    override fun peripheralManagerIsReadyToUpdateSubscribers(peripheral: CBPeripheralManager) {
        handler.onReadyToUpdateSubscribers(peripheral)
    }

    @ObjCSignatureOverride
    override fun peripheralManager(
        peripheral: CBPeripheralManager,
        central: CBCentral,
        didSubscribeToCharacteristic: CBCharacteristic
    ) {
        handler.onSubscribe(peripheral, central, didSubscribeToCharacteristic)
    }

    fun peripheralManagerIsReady(toUpdateSubscribers: CBPeripheralManager) {
        handler.onReadyToUpdateSubscribers(toUpdateSubscribers)
    }
}

