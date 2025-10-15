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
package ch.ubique.heidi.proximity.protocol

import ch.ubique.heidi.util.log.Logger

abstract class BleTransportProtocol(role: Role) : TransportProtocol(role) {

	companion object {

		private const val TAG = "BleTransportProtocol"

		internal fun bleCalculateAttributeValueSize(mtuSize: Int): Int {
			val characteristicValueSize: Int
			if (mtuSize > 515) {
				// Bluetooth Core specification Part F section 3.2.9 says "The maximum length of
				// an attribute value shall be 512 octets". ... this is enforced in Android as
				// of Android 13 with the effect being that the application only sees the first
				// 512 bytes.
				Logger(TAG).warn("MTU size is $mtuSize, using 512 as characteristic value size")
				characteristicValueSize = 512
			} else {
				characteristicValueSize = mtuSize - 3
				Logger(TAG).warn("MTU size is $mtuSize, using $characteristicValueSize as characteristic value size")
			}
			return characteristicValueSize
		}

	}
}
