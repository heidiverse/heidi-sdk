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

import ch.ubique.heidi.util.log.Logger
import platform.CoreBluetooth.CBCharacteristic
import platform.CoreBluetooth.CBService
import kotlin.uuid.Uuid

internal actual class BleGattService(val service: CBService) {

	actual val uuid: Uuid?
		get()  {
			Logger("BleGattService").debug("serviceUUID: ${service.UUID.UUIDString}")
			val uuid = service.UUID.UUIDString
			if(uuid.length == 4) {
				return runCatching { Uuid.parse("0000$uuid-0000-1000-8000-00805F9B34FB") }.getOrNull()
			}
			return runCatching { Uuid.parse(service.UUID.UUIDString) }.getOrNull() }

	actual val characteristics: List<BleGattCharacteristic>
		get() = service.characteristics?.map {
			BleGattCharacteristic(it as CBCharacteristic)
		} ?: emptyList()

}
