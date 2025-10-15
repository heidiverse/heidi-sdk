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

package ch.ubique.heidi.wallet.process.presentation

import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.presentation.model.DocumentDigest
import ch.ubique.heidi.presentation.model.TransactionData
import okio.internal.commonToUtf8String
import uniffi.heidi_crypto_rust.base64UrlDecodePad
import uniffi.heidi_crypto_rust.sha256Rs

@OptIn(ExperimentalStdlibApi::class)
private fun validateHash(data: ByteArray, hash: String?, hashAlgorithmOID: String?): Boolean {
	if (hash == null) return false

	val hashString = when (hashAlgorithmOID) {
		"2.16.840.1.101.3.4.2.1" -> sha256Rs(data).toHexString() // SHA-256
		else -> {
			Logger.error("Unsupported hash algorithm OID: $hashAlgorithmOID")
			return false
		}
	}

	Logger.debug("Document hash: $hashString")

	val documentHash = base64UrlDecodePad(hash).commonToUtf8String()
	return hashString == documentHash
}


fun DocumentDigest.validate(data: ByteArray): Boolean {
	return validateHash(data, hash, hashAlgorithmOID) || validateHash(data, dtbs, dtbsHashAlgorithmOid)
}

fun TransactionData.validate(data: ByteArray): Boolean {
	return validateHash(data, qcHash, qcHashAlgorithmOid)
}
