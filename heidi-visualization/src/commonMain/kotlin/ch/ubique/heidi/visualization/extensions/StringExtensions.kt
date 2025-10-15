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

package ch.ubique.heidi.visualization.extensions
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Return the first substring between two delimiters. If the string does not contain one of the delimiters, returns [missingDelimiterValue] which defaults to [this]
 */
internal fun String.substringBetween(startDelimiter: String, endDelimiter: String, missingDelimiterValue: String = this): String {
	val startIndex = indexOf(startDelimiter) + startDelimiter.length
	val endIndex = lastIndexOf(endDelimiter)
	return if (startIndex != -1 && endIndex != -1) {
		substring(startIndex, endIndex)
	} else {
		missingDelimiterValue
	}
}
fun String.isPng() : Boolean {
	return this.startsWith("iVBOR")
}
@OptIn(ExperimentalEncodingApi::class)
fun String?.tryDecodeBase64() : ByteArray? {
	return this?.let {
		(runCatching {  Base64.UrlSafe.decode(it) }.getOrNull()
			?: runCatching { Base64.Default.decode(it) }.getOrNull())
	}
}
