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

package ch.ubique.heidi.util.json

import ch.ubique.heidi.util.extensions.jsonPrimitiveOrNull
import kotlinx.serialization.json.*

/**
 * Basic implementation of JsonPointers as per RFC 6901
 */
class JsonPointer(
	private val path: String,
	private val lenient: Boolean = true,
) {

	private val refTokens = path.trim('/')
		.split('/')
		.map {
			it.replace("~0", "~").replace("~1", "/") // Special character handling
		}

	fun resolveString(json: JsonElement): String? {
		if (path.isEmpty()) return json.toString()

		return when (val resolved = resolveElement(json)) {
			null -> if (lenient) null else throw JsonPointerException("Path '$path' could not be resolved")
			is JsonPrimitive -> resolved.content
			is JsonArray -> if (lenient) {
				resolved.joinToString(", ") { it.jsonPrimitiveOrNull()?.content ?: it.toString() }
			} else {
				throw JsonPointerException("Path '$path' resolved to JsonArray '$resolved'")
			}
			is JsonObject -> if (lenient) null else throw JsonPointerException("Path '$path' resolved to JsonObject '$resolved'")
		}
	}

	private fun resolveElement(json: JsonElement): JsonElement? {
		var currentElement: JsonElement = json

		for (refToken in refTokens) {
			currentElement = when (currentElement) {
				is JsonObject -> {
					// If the current element is a JsonObject, access by key
					currentElement[refToken] ?: return null
				}
				is JsonArray -> {
					// If the current element is a JsonArray, access by index
					val index = refToken.toIntOrNull() ?: return null
					if (index in 0 until currentElement.size) {
						currentElement[index]
					} else {
						return null
					}
				}
				else -> {
					// If it's neither JsonObject nor JsonArray, the path is invalid
					return null
				}
			}
		}

		return currentElement
	}

}
