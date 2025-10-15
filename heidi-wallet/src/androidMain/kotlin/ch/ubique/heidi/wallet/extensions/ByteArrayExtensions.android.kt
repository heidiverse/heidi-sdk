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

package ch.ubique.heidi.wallet.extensions

import java.math.BigInteger
import java.util.Arrays

fun ByteArray.extractRawSignature(): ByteArray {
	fun extractR(signature: ByteArray): BigInteger {
		val startR = if ((signature[1].toInt() and 0x80) != 0) 3 else 2
		val lengthR = signature[startR + 1].toInt()
		return BigInteger(Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR))
	}

	fun extractS(signature: ByteArray): BigInteger {
		val startR = if ((signature[1].toInt() and 0x80) != 0) 3 else 2
		val lengthR = signature[startR + 1].toInt()
		val startS = startR + 2 + lengthR
		val lengthS = signature[startS + 1].toInt()
		return BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS))
	}

	val r = extractR(this).toByteArray().toFixedLength(32)
	val s = extractS(this).toByteArray().toFixedLength(32)
	return r + s
}
