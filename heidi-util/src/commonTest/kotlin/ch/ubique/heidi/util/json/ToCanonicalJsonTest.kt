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

import ch.ubique.heidi.util.extensions.fromJsonElement
import ch.ubique.heidi.util.extensions.isSame
import ch.ubique.heidi.util.extensions.toCanonicalJson
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonPrimitive
import uniffi.heidi_util_rust.JsonNumber
import uniffi.heidi_util_rust.MapEntry
import uniffi.heidi_util_rust.OrderedMap
import uniffi.heidi_util_rust.Value
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Tests for [toCanonicalJson], following the escaping and property ordering rules of
 * JSON Canonicalization Scheme (RFC 8785).
 */
class ToCanonicalJsonTest {

	private fun parse(json: String): Value = Value.fromJsonElement(Json.decodeFromString<JsonElement>(json))

	private fun obj(vararg entries: Pair<String, Value>): Value = Value.Object(mapOf(*entries))

	private fun str(value: String): Value = Value.String(value)

	private fun num(value: Long): Value = Value.Number(JsonNumber.Integer(value))

	private fun num(value: Double): Value = Value.Number(JsonNumber.Float(value))

	// region basics

	@Test
	fun simpleObject() {
		val json = parse(
			"""
				{
					"test": 123
				}
			""".trimIndent()
		)

		assertEquals("{\"test\":123}", json.toCanonicalJson())
	}

	@Test
	fun primitives() {
		assertEquals("null", Value.Null.toCanonicalJson())
		assertEquals("true", Value.Boolean(true).toCanonicalJson())
		assertEquals("false", Value.Boolean(false).toCanonicalJson())
		assertEquals("42", Value.Number(JsonNumber.Integer(42)).toCanonicalJson())
		assertEquals("-42", Value.Number(JsonNumber.Integer(-42)).toCanonicalJson())
		assertEquals("\"\"", str("").toCanonicalJson())
	}

	@Test
	fun emptyContainers() {
		assertEquals("{}", parse("{}").toCanonicalJson())
		assertEquals("[]", parse("[]").toCanonicalJson())
		assertEquals("{\"a\":{},\"b\":[]}", parse("""{"b":[],"a":{}}""").toCanonicalJson())
	}

	// endregion

	// region string escaping

	@Test
	fun quotesAreEscaped() {
		assertEquals("\"\\\"\"", str("\"").toCanonicalJson())
		assertEquals("\"he said \\\"hi\\\"\"", str("he said \"hi\"").toCanonicalJson())
	}

	@Test
	fun backslashesAreEscaped() {
		assertEquals("\"\\\\\"", str("\\").toCanonicalJson())
		assertEquals("\"C:\\\\path\\\\to\\\\file\"", str("C:\\path\\to\\file").toCanonicalJson())
	}

	@Test
	fun literalBackslashNIsNotConfusedWithNewline() {
		// A two character string: backslash followed by 'n'. It must not collapse into a newline escape.
		assertEquals("\"\\\\n\"", str("\\n").toCanonicalJson())
		// while an actual newline must
		assertEquals("\"\\n\"", str("\n").toCanonicalJson())
	}

	@Test
	fun controlCharactersWithShortEscapes() {
		assertEquals("\"\\b\"", str("\u0008").toCanonicalJson())
		assertEquals("\"\\t\"", str("\u0009").toCanonicalJson())
		assertEquals("\"\\n\"", str("\u000A").toCanonicalJson())
		assertEquals("\"\\f\"", str("\u000C").toCanonicalJson())
		assertEquals("\"\\r\"", str("\u000D").toCanonicalJson())
		assertEquals("\"line1\\nline2\\r\\n\\ttabbed\"", str("line1\nline2\r\n\ttabbed").toCanonicalJson())
	}

	@Test
	fun remainingControlCharactersUseUnicodeEscapes() {
		// Every other C0 control character has to be escaped as \u00xx with lowercase hex digits.
		assertEquals("\"\\u0000\"", str("\u0000").toCanonicalJson())
		assertEquals("\"\\u0001\"", str("\u0001").toCanonicalJson())
		assertEquals("\"\\u000b\"", str("\u000B").toCanonicalJson()) // vertical tab has no short escape
		assertEquals("\"\\u000e\"", str("\u000E").toCanonicalJson())
		assertEquals("\"\\u001f\"", str("\u001F").toCanonicalJson())
	}

	@Test
	fun allControlCharactersAreEscaped() {
		for (code in 0x00..0x1F) {
			val canonical = str(Char(code).toString()).toCanonicalJson()
			assertTrue(
				canonical.startsWith("\"\\") && canonical.length <= 8,
				"control character U+${code.toString(16).padStart(4, '0')} was not escaped: $canonical",
			)
		}
	}

	@Test
	fun charactersThatMustNotBeEscaped() {
		// The solidus may be escaped but does not have to be, and canonical output keeps it literal.
		assertEquals("\"a/b\"", str("a/b").toCanonicalJson())
		// DEL is not a JSON control character.
		assertEquals("\"\u007F\"", str("\u007F").toCanonicalJson())
		// Single quotes and the remaining ASCII punctuation stay as is.
		assertEquals("\"it's {a} [b] <c>\"", str("it's {a} [b] <c>").toCanonicalJson())
	}

	@Test
	fun nonAsciiCharactersArePassedThrough() {
		assertEquals("\"Grüezi\"", str("Grüezi").toCanonicalJson())
		assertEquals("\"日本語\"", str("日本語").toCanonicalJson())
		assertEquals("\"\u00E9\"", str("\u00E9").toCanonicalJson())
		// Combining characters must not be normalized away.
		assertEquals("\"e\u0301\"", str("e\u0301").toCanonicalJson())
		// Non characters / BOM stay literal as well.
		assertEquals("\"\uFEFF\"", str("\uFEFF").toCanonicalJson())
	}

	@Test
	fun surrogatePairsArePassedThrough() {
		assertEquals("\"😀\"", str("😀").toCanonicalJson())
		assertEquals("\"a😀b\"", str("a\uD83D\uDE00b").toCanonicalJson())
	}

	@Test
	fun mixedEscapesInOneString() {
		val value = str("\"quote\" \\ backslash\n\ttab \u0000 nul é 😀 /slash/")
		assertEquals(
			"\"\\\"quote\\\" \\\\ backslash\\n\\ttab \\u0000 nul é 😀 /slash/\"",
			value.toCanonicalJson(),
		)
	}

	// endregion

	// region key escaping

	@Test
	fun objectKeysAreEscaped() {
		assertEquals("{\"a\\\"b\":1}", obj("a\"b" to Value.Number(JsonNumber.Integer(1))).toCanonicalJson())
		assertEquals("{\"a\\\\b\":1}", obj("a\\b" to Value.Number(JsonNumber.Integer(1))).toCanonicalJson())
		assertEquals("{\"a\\nb\":1}", obj("a\nb" to Value.Number(JsonNumber.Integer(1))).toCanonicalJson())
		assertEquals("{\"a\\u0000b\":1}", obj("a\u0000b" to Value.Number(JsonNumber.Integer(1))).toCanonicalJson())
		assertEquals("{\"\":1}", obj("" to Value.Number(JsonNumber.Integer(1))).toCanonicalJson())
	}

	@Test
	fun keysAndValuesAreEscapedInNestedStructures() {
		val value = obj(
			"outer\"key" to Value.Array(
				listOf(
					str("a\nb"),
					obj("inner\\key" to str("\u0001")),
				)
			)
		)

		assertEquals(
			"{\"outer\\\"key\":[\"a\\nb\",{\"inner\\\\key\":\"\\u0001\"}]}",
			value.toCanonicalJson(),
		)
	}

	// endregion

	// region key ordering

	@Test
	fun keysAreSortedByUtf16CodeUnit() {
		val value = obj(
			"b" to str("2"),
			"A" to str("1"),
			"a" to str("3"),
			"1" to str("0"),
			"" to str("empty"),
		)

		assertEquals(
			"{\"\":\"empty\",\"1\":\"0\",\"A\":\"1\",\"a\":\"3\",\"b\":\"2\"}",
			value.toCanonicalJson(),
		)
	}

	@Test
	fun keysAreSortedBeforeEscaping() {
		// U+001F sorts before '!' by code unit, but its escaped form "\u001f" starts with a
		// backslash (U+005C) and would sort after it. Ordering must be based on the raw key.
		val value = obj(
			"!" to str("bang"),
			"\u001F" to str("control"),
		)

		assertEquals("{\"\\u001f\":\"control\",\"!\":\"bang\"}", value.toCanonicalJson())
	}

	@Test
	fun keysAreSortedRecursively() {
		val value = parse("""{"b":{"z":1,"a":2},"a":[{"y":1,"x":2}]}""")

		assertEquals("{\"a\":[{\"x\":2,\"y\":1}],\"b\":{\"a\":2,\"z\":1}}", value.toCanonicalJson())
	}

	// endregion

	// region round tripping

	@Test
	fun outputCanBeParsedBackIntoAnEqualValue() {
		val original = obj(
			"quote\"" to str("\"'"),
			"back\\slash" to str("\\\\"),
			"控制" to str("\u0000\u0001\u001F\b\t\n\u000B\u000C\r"),
			"emoji" to Value.Array(listOf(str("😀"), str("é"), str("a/b"))),
			"nested" to obj("empty" to str("")),
		)

		val reparsed = Value.fromJsonElement(Json.decodeFromString<JsonElement>(original.toCanonicalJson()))

		assertTrue(original.isSame(reparsed), "round trip changed the value: ${original.toCanonicalJson()}")
	}

	@Test
	fun canonicalOutputIsStable() {
		val value = obj("a\nb" to str("\"x\""), "a" to str("\\"))
		val once = value.toCanonicalJson()
		val twice = Value.fromJsonElement(Json.decodeFromString<JsonElement>(once)).toCanonicalJson()

		assertEquals(once, twice)
	}

	// endregion

	// region numbers

	// The ignored tests below specify RFC 8785 compliant number formatting, which the current
	// Double.toString() based implementation does not provide.

	@Test
	fun integersAreSerializedVerbatim() {
		assertEquals("0", num(0L).toCanonicalJson())
		assertEquals("1", num(1L).toCanonicalJson())
		assertEquals("-1", num(-1L).toCanonicalJson())
		// Integers keep full precision, even beyond what a Double could represent exactly
		assertEquals("9007199254740993", num(9007199254740993L).toCanonicalJson()) // 2^53 + 1
		assertEquals("9223372036854775807", num(Long.MAX_VALUE).toCanonicalJson())
		assertEquals("-9223372036854775808", num(Long.MIN_VALUE).toCanonicalJson())
	}

	@Test
	fun integralDoublesDropTheFractionalPart() {
		assertEquals("1", num(1.0).toCanonicalJson())
		assertEquals("-1", num(-1.0).toCanonicalJson())
		assertEquals("0", num(0.0).toCanonicalJson())
		assertEquals("100", num(100.0).toCanonicalJson())
		assertEquals("9007199254740992", num(9007199254740992.0).toCanonicalJson()) // 2^53
	}

	@Test
	fun negativeZeroIsSerializedAsZero() {
		assertEquals("0", num(-0.0).toCanonicalJson())
	}

	@Test
	@Ignore // Doubles are serialized with Double.toString(), see the note on JsonElement.toCanonicalJson
	fun fractionalDoubles() {
		assertEquals("1.5", num(1.5).toCanonicalJson())
		assertEquals("0.5", num(0.5).toCanonicalJson())
		assertEquals("-2.25", num(-2.25).toCanonicalJson())
		assertEquals("333333333.3333333", num(333333333.33333329).toCanonicalJson())
	}

	@Test
	@Ignore // Doubles are serialized with Double.toString(), see the note on JsonElement.toCanonicalJson
	fun shortestRoundTrippingRepresentationIsUsed() {
		assertEquals("0.1", num(0.1).toCanonicalJson())
		assertEquals("0.30000000000000004", num(0.1 + 0.2).toCanonicalJson())
		assertEquals("2.220446049250313e-16", num(2.220446049250313e-16).toCanonicalJson())
	}

	@Test
	@Ignore // Doubles are serialized with Double.toString(), see the note on JsonElement.toCanonicalJson
	fun plainNotationBelowTheExponentialThresholds() {
		// ES6 only switches to exponential notation from 1e21 upwards and below 1e-6,
		// unlike Double.toString which switches at 1e7 and 1e-3.
		assertEquals("10000000", num(1e7).toCanonicalJson())
		assertEquals("100000000000000000000", num(1e20).toCanonicalJson())
		assertEquals("0.0001", num(1e-4).toCanonicalJson())
		assertEquals("0.000001", num(1e-6).toCanonicalJson())
	}

	@Test
	@Ignore // Doubles are serialized with Double.toString(), see the note on JsonElement.toCanonicalJson
	fun exponentialNotationForLargeValues() {
		assertEquals("1e+21", num(1e21).toCanonicalJson())
		assertEquals("1e+22", num(1e22).toCanonicalJson())
		assertEquals("1e+23", num(1e23).toCanonicalJson())
		assertEquals("1.7976931348623157e+308", num(Double.MAX_VALUE).toCanonicalJson())
	}

	@Test
	@Ignore // Doubles are serialized with Double.toString(), see the note on JsonElement.toCanonicalJson
	fun exponentialNotationForSmallValues() {
		assertEquals("1e-7", num(1e-7).toCanonicalJson())
		assertEquals("5e-324", num(Double.MIN_VALUE).toCanonicalJson())
	}

	@Test
	fun nonFiniteNumbersAreRejected() {
		// JSON has no notation for these, "NaN" / "Infinity" would not be parseable
		assertFailsWith<Exception> { num(Double.NaN).toCanonicalJson() }
		assertFailsWith<Exception> { num(Double.POSITIVE_INFINITY).toCanonicalJson() }
		assertFailsWith<Exception> { num(Double.NEGATIVE_INFINITY).toCanonicalJson() }
	}

	@Test
	fun integerAndDoubleOfTheSameValueAgree() {
		// "1" is parsed into an Integer and "1.0" into a Float, both must canonicalize identically
		assertEquals("1", parse("1").toCanonicalJson())
		assertEquals("1", parse("1.0").toCanonicalJson())
	}

	@Test
	@Ignore // Doubles are serialized with Double.toString(), see the note on JsonElement.toCanonicalJson
	fun numbersInsideStructures() {
		val value = obj(
			"a" to Value.Array(listOf(num(1.0), num(1e21), num(-0.0))),
			"b" to num(2L),
		)

		assertEquals("{\"a\":[1,1e+21,0],\"b\":2}", value.toCanonicalJson())
	}

	@Test
	fun canonicalNumbersCanBeParsedBack() {
		val values = listOf(1.0, -1.0, 0.5, 1e7, 1e20, 1e21, 1e23, 1e-6, 1e-7, Double.MAX_VALUE, Double.MIN_VALUE)

		for (value in values) {
			val canonical = num(value).toCanonicalJson()
			val reparsed = Json.decodeFromString<JsonElement>(canonical)
			assertEquals(value, reparsed.jsonPrimitive.double, "round trip changed $value (canonical: $canonical)")
		}
	}

	// endregion

	// region unsupported values

	@Test
	fun bytesCannotBeCanonicalized() {
		assertFailsWith<Exception> { Value.Bytes(byteArrayOf(1, 2, 3)).toCanonicalJson() }
	}

	@Test
	fun orderedObjectCannotBeCanonicalized() {
		val ordered = Value.OrderedObject(OrderedMap(listOf(MapEntry(str("a"), str("b")))))
		assertFailsWith<Exception> { ordered.toCanonicalJson() }
	}

	@Test
	fun tagCannotBeCanonicalized() {
		assertFailsWith<Exception> { Value.Tag(0u, listOf(str("a"))).toCanonicalJson() }
	}

	@Test
	fun unsupportedValuesAreRejectedWhenNested() {
		val value = obj("bytes" to Value.Bytes(byteArrayOf(1)))
		assertFailsWith<Exception> { value.toCanonicalJson() }
	}

	// endregion
}
