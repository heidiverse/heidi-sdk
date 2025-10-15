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

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class JsonPointerTest {
	private val rfcPayload = """
			{
				"foo": ["bar", "baz"],
				"": 0,
				"a/b": 1,
				"c%d": 2,
				"e^f": 3,
				"g|h": 4,
				"i\\j": 5,
				"k\"l": 6,
				" ": 7,
				"m~n": 8
			}
		""".trimIndent()

	private val normalPayload = """
			{
				"user": {
					"id": 12345,
					"name": "John Doe",
					"email": "john.doe@example.com",
					"address": {
						"street": "Limmatquai 122",
						"city": "Zürich",
						"zipcode": "8001"
					},
					"friends": [
						{
							"id": 23456,
							"name": "Jane Doe"
						},
						{
							"id": 34567,
							"name": "JSON Bourne"
						}
					]
				}
			}
		""".trimIndent()

	private val json = Json.Default

	/**
	 * See: https://datatracker.ietf.org/doc/html/rfc6901#section-5
	 */
	@Test
	fun `Test RFC 6901 example`() {
		val jsonElement = json.parseToJsonElement(rfcPayload)
		val inputToExpected = mapOf(
			"" to jsonElement.toString(),
			"/foo" to "bar, baz",
			"/foo/0" to "bar",
			"/" to "0",
			"/a~1b" to "1",
			"/c%d" to "2",
			"/e^f" to "3",
			"/g|h" to "4",
			"/i\\j" to "5",
			"/k\"l" to "6",
			"/ " to "7",
			"/m~0n" to "8",
		)

		inputToExpected.forEach { (input, expected) ->
			val pointer = JsonPointer(input, lenient = true)
			val actual = pointer.resolveString(jsonElement)
			assertEquals(expected, actual, "Input '$input' didn't resolve as expected")
		}
	}

	@Test
	fun `Test normal payload`() {
		val jsonElement = json.parseToJsonElement(normalPayload)
		val inputToExpected = mapOf(
			"/user/id" to "12345",
			"/user/name" to "John Doe",
			"/user/email" to "john.doe@example.com",
			"/user/address/street" to "Limmatquai 122",
			"/user/address/city" to "Zürich",
			"/user/address/zipcode" to "8001",
			"/user/friends/0/id" to "23456",
			"/user/friends/0/name" to "Jane Doe",
			"/user/friends/1/id" to "34567",
			"/user/friends/1/name" to "JSON Bourne",
			"/some-other-property" to null,
		)

		inputToExpected.forEach { (input, expected) ->
			val pointer = JsonPointer(input, lenient = true)
			val actual = pointer.resolveString(jsonElement)
			assertEquals(expected, actual, "Input '$input' didn't resolve as expected")
		}
	}

	@Test
	fun `Test non-lenient parsing`() {
		val jsonElement = json.parseToJsonElement(normalPayload)

		val invalidInputs = listOf(
			"/id", // Non-existent property
			"/address/country", // Non-existent nested property
			"/address/street/number", // Nested property on non-object
			"/user/friends", // Property is an array
		)

		invalidInputs.forEach { input ->
			val pointer = JsonPointer(input, lenient = false)
			assertFailsWith(JsonPointerException::class, "Input '$input' should have failed") {
				val actual = pointer.resolveString(jsonElement)
				println("Actual: $actual")
			}
		}
	}

}
