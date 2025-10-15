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

package ch.ubique.heidi.visualization.oca.model

import ch.ubique.heidi.visualization.oca.model.overlay.Overlay
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_crypto_rust.blake3Hash
import uniffi.heidi_crypto_rust.sha256Rs

const val SAID_HASH_PLACEHOLDER : String = "############################################"
@Serializable
data class OcaBundleJson(
	@SerialName("capture_base") val captureBase: CaptureBase,
	@SerialName("overlays") val overlays: List<Overlay>,
)

val json = Json{
	ignoreUnknownKeys = true
	encodeDefaults = true
}

private fun hash(digest: String, stringifiedObject: String) : ByteArray {
	return when(digest) {
		"I" -> sha256Rs(stringifiedObject.encodeToByteArray())
		"E" -> blake3Hash(stringifiedObject.encodeToByteArray())
		else -> sha256Rs(stringifiedObject.encodeToByteArray())
	}
}

fun computeCesrEncodedDigest(captureBase: CaptureBase, digest: String = "I") : String {
	// Set the digest dummy (44 '#' for SHA-256 digest)
	val replacedCaptureBase = captureBase.copy(digest = SAID_HASH_PLACEHOLDER)
	val stringifiedObject = canonicalize(replacedCaptureBase)
	var hashresult = hash(digest, stringifiedObject).toMutableList()
	hashresult.add(0, 0)
	val hash = base64UrlEncode(hashresult.toByteArray())
	return hash.replaceRange(0,1,digest)
}
fun  computeCesrEncodedDigest(layer: Overlay, digest: String = "I") : String {
	// Set the digest dummy (44 '#' for SHA-256 digest)
	val replacedCaptureBase = layer.updateDigest(SAID_HASH_PLACEHOLDER)
	val stringifiedObject = canonicalize(json.encodeToString(replacedCaptureBase))
	var hashresult = hash(digest, stringifiedObject).toMutableList()
	hashresult.add(0, 0)
	val hash = base64UrlEncode(hashresult.toByteArray())
	return hash.replaceRange(0,1,digest)
}
fun  computeBundleDigest(ocaBundle: OcaBundleJson, digest: String = "I") : String {
	val stringifiedObject = canonicalize(json.encodeToString(ocaBundle))
	var hashresult = hash(digest, stringifiedObject).toMutableList()
	hashresult.add(0, 0)
	val hash = base64UrlEncode(hashresult.toByteArray())
	return hash.replaceRange(0,1,digest)
}

/**
 * Simple implementation following https://www.rfc-editor.org/rfc/rfc8785.html
 */
fun canonicalize(captureBase: CaptureBase) : String {
	return canonicalizeObject(json.encodeToJsonElement(captureBase).jsonObject)
}
/**
 * Simple implementation following https://www.rfc-editor.org/rfc/rfc8785.html
 */
fun canonicalize(input: String) : String {
	val inputObject : JsonObject = json.decodeFromString(input)
	return canonicalizeObject(inputObject)
}
/**
 * Simple implementation following https://www.rfc-editor.org/rfc/rfc8785.html
 */
fun canonicalize(input: JsonObject) : String {
	return canonicalizeObject(input)
}
/**
 * Simple implementation following https://www.rfc-editor.org/rfc/rfc8785.html
 */
fun canonicalize(ocaBundle: OcaBundleJson) : String {
	return canonicalizeObject(json.encodeToJsonElement(ocaBundle).jsonObject)
}

private fun canonicalizeObject(obj: JsonObject) : String {
	var outputString = "{"
	var orderedAttributes = obj.keys.sorted()
	for(key in orderedAttributes) {
		val value = obj[key]
		// we know the value exists as it is a key (see above)
		val stringifiedValue = stringifyJsonElement(value!!)
		outputString += "\"$key\":$stringifiedValue,"
	}
	if(outputString.contains(",")) {
		outputString = outputString.substring(0,outputString.length-1)
	}
	outputString += "}"
	return outputString
}
private fun canonicalizeArray(arr: JsonArray) : String {
	var outputString = "["
	for(element in arr) {
		outputString += stringifyJsonElement(element) + ","
	}
	if(outputString.contains(",")) {
		outputString = outputString.substring(0,outputString.length-1)
	}
	outputString += "]"
	return outputString
}
//TODO: actually implement canonicalization of values according to https://www.rfc-editor.org/rfc/rfc8785.html#name-serialization-of-primitive-
// We ignore it here as we expect primitive types to be somewhat according to the canonicalized forms already
private fun canonicalizePrimitive(primitive: JsonPrimitive) : String {
	return Json.encodeToString(primitive).trim()
}

private fun stringifyJsonElement(value: JsonElement) : String {
	return when (value) {
		is JsonObject -> canonicalizeObject(value)
		is JsonPrimitive -> canonicalizePrimitive(value)
		is JsonArray -> canonicalizeArray(value)
	}
}
