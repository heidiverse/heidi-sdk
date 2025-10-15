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

package ch.ubique.heidi.wallet.crypto

import android.content.Context
import ch.ubique.heidi.wallet.crypto.factories.HardwareSignerFactory
import uniffi.heidi_wallet_rust.NativeSigner

internal class AndroidHardwareSignerFactory(private val context: Context) : HardwareSignerFactory {

	override fun getHardwareSigner(dataRepresenation: ByteArray): NativeSigner? {
		val alias = dataRepresenation.decodeToString()
		val keyPair = KeyRepository.getKeyPair(alias)

		return keyPair?.let { Signer(it, alias) }
	}

	override fun newHardwareSigner(accessControl: SecureHardwareAccessControl): NativeSigner {
		return Signer.createHardwareBound(context, accessControl)
	}
}
