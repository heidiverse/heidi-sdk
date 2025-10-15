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

package ch.ubique.heidi.visualization.stylejson.template

import kotlin.test.Test
import kotlin.test.assertEquals

class StyleJsonTemplateTest {

	private val data = mapOf(
		"given_name" to "John",
		"family_name" to "Doe",
	)

	@Test
	fun `Test replacing a single placeholder`() {
		val inputToExpected = mapOf(
			"{{unknown}}" to "{{unknown}}",
			"{{ unknown }}" to "{{ unknown }}",
			"{{given_name}}" to "John",
			"{{ given_name }}" to "John",
			"My first name is {{ given_name }}" to "My first name is John",
			"{{family_name}}" to "Doe",
			"{{ family_name }}" to "Doe",
			"{{ family_name }} is my last name" to "Doe is my last name",
		)

		inputToExpected.forEach { (input, expected) ->
			val actual = StyleJsonTemplate(input).interpolate { data[it] }
			assertEquals(expected, actual, "Input '$input' didn't interpolate as expected")
		}
	}

	@Test
	fun `Test replacing multiple placeholders`() {
		val inputToExpected = mapOf(
			"{{ given_name }} {{ family_name }}" to "John Doe",
			"{{ given_name }}{{ family_name }}" to "JohnDoe",
			"My name is {{ given_name }} {{ family_name }}" to "My name is John Doe",
			"{{ given_name }} {{ family_name }} is my name" to "John Doe is my name",
			"{{ given_name }} is my first name and my last name is {{ family_name }}" to "John is my first name and my last name is Doe",
			"One {{ given_name }} Two {{ family_name }} Three" to "One John Two Doe Three",
		)

		inputToExpected.forEach { (input, expected) ->
			val actual = StyleJsonTemplate(input).interpolate { data[it] }
			assertEquals(expected, actual, "Input '$input' didn't interpolate as expected")
		}
	}

}