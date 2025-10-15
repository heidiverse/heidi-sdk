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
import ch.ubique.heidi.wallet.extensions.extractRawSignature
import ch.ubique.heidi.wallet.extensions.toFixedLength
import uniffi.heidi_wallet_rust.NativeSigner
import uniffi.heidi_wallet_rust.SigningException
import uniffi.heidi_wallet_rust.bytesToEcJwk
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey

internal class Signer(private val keyPair: KeyPair, private val alias: String) : NativeSigner {
	override fun keyReference(): ByteArray {
		return alias.encodeToByteArray()
	}

	override fun privateKey(): ByteArray {
		throw SigningException.InvalidSecret()
	}

	override fun sign(msg: String): ByteArray {
		val bytes = msg.toByteArray(charset = Charsets.UTF_8)
		return signBytes(bytes)
	}

	override fun signBytes(msg: ByteArray): ByteArray {
		val ecdsa = Signature.getInstance("SHA256withECDSA")
		ecdsa.initSign(keyPair.private)
		ecdsa.update(msg)
		return ecdsa.sign().extractRawSignature()
	}

	override fun publicKey(): ByteArray {
		val publicKey = keyPair.public as ECPublicKey
		val x = publicKey.w.affineX.toByteArray().toFixedLength(32)
		val y = publicKey.w.affineY.toByteArray().toFixedLength(32)
		return byteArrayOf(4) + x + y
	}

	override fun keyId(): String = "HardwareKey"

	override fun jwtHeader(): String {
		val jwk = bytesToEcJwk(this.publicKey())
		return "{\"typ\":\"openid4vci-proof+jwt\",\"alg\":\"ES256\", \"jwk\" : $jwk}"
	}

	override fun alg(): String = "ES256"
	override fun publicKeyJwk(): String {
		return bytesToEcJwk(this.publicKey()) ?: "{}"
	}

	override fun privateKeyExportable(): Boolean {
		return false
	}

	override fun keyAttestation(): String? {
		return KeyRepository.getKeyAttestation(this.alias)
	}

	companion object {
		fun generateLocal(): Signer = Signer(KeyRepository.generateES256KeyPair(), "localKey")
		fun fromKeyPair(keyPair: KeyPair, alias: String): Signer = Signer(keyPair, alias)
		fun createHardwareBound(context: Context, accessControl: SecureHardwareAccessControl): Signer {
			val (keyPair, alias) = KeyRepository.createKeyPair(context, accessControl)
			return Signer(keyPair, alias)
		}
	}
}
