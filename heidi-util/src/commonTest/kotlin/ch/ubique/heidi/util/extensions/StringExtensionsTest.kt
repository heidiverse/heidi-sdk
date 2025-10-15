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

package ch.ubique.heidi.util.extensions

import kotlin.test.Test
import kotlin.test.assertEquals

class StringExtensionsTest {

	@Test
	fun testHexShortRGB() {
		val color = "#3A5".toArgb()
		assertEquals(0xFF33AA55, color)
	}

	@Test
	fun testHexShortARGB() {
		val color = "#4F5A".toArgb()
		assertEquals(0x44FF55AA, color)
	}

	@Test
	fun testHexFullRGB() {
		val color = "#32674E".toArgb()
		assertEquals(0xFF32674E, color)
	}

	@Test
	fun testHexFullARGB() {
		val color = "#FF32674E".toArgb()
		assertEquals(0xFF32674E, color)
	}

	@Test
	fun testRgb() {
		val color = "rgb(50, 103, 78)".toArgb()
		assertEquals(0xFF32674E, color)
	}

	@Test
	fun testRgba() {
		val color = "rgba(50, 103, 78, 0.5)".toArgb()
		assertEquals(0x8032674E, color)
	}

	@Test
	fun testArgb() {
		val color = "argb(0.5, 50, 103, 78)".toArgb()
		assertEquals(0x8032674E, color)
	}

	@Test
	fun testInvalidHexLength() {
		val color = "#12345".toArgb(default = 0xFFFFFFFF)
		assertEquals(0xFFFFFFFF, color)
	}

	@Test
	fun testInvalidPrefix() {
		val color = "invalidColor".toArgb(default = 0xFFFFFFFF)
		assertEquals(0xFFFFFFFF, color)
	}

}