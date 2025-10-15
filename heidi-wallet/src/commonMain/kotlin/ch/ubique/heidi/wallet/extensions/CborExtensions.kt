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

import ch.ubique.heidi.visualization.oca.processing.AttributeValue
import com.android.identity.cbor.*
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Convert a [DataItem] to an [AttributeValue] for display in the UI
 */
@OptIn(ExperimentalTime::class)
internal fun DataItem.toAttributeValue(): AttributeValue<*> = when (this) {
	is Bstr -> AttributeValue.Text(value.decodeToString())
	is CborArray -> AttributeValue.Array(items.map { it.toAttributeValue() })
	is CborDouble -> AttributeValue.Text(value.toString())
	is CborFloat -> AttributeValue.Text(value.toString())
	is CborInt -> when (this) {
		is Nint -> AttributeValue.Text((-value.toLong()).toString())
		is Uint -> AttributeValue.Text(value.toString())
		else -> throw IllegalArgumentException("Invalid CborInt type")
	}
	is CborMap -> AttributeValue.Raw(items.values.joinToString(separator = ", ") {  it.toAttributeValue().asString() })
	is IndefLengthBstr -> AttributeValue.Text(chunks.joinToString("") { it.decodeToString() })
	is IndefLengthTstr -> AttributeValue.Text(chunks.joinToString(""))
	is RawCbor -> throw IllegalArgumentException("RawCbor should never be returned when decoding")
	is Simple -> when (this) {
		Simple.TRUE -> AttributeValue.Bool(true)
		Simple.FALSE -> AttributeValue.Bool(false)
		Simple.NULL -> AttributeValue.Raw("null")
		Simple.UNDEFINED -> AttributeValue.Raw("undefined")
		else -> AttributeValue.Raw("Simple($value)")
	}
	is Tagged -> when (tagNumber) {
		// RFC 3339 date-time string
		Tagged.DATE_TIME_STRING -> AttributeValue.DateTime(this.asDateTimeString.toLocalDateTime(TimeZone.UTC))

		// Epoch timestamp in seconds
		Tagged.DATE_TIME_NUMBER -> when (val tagValue = taggedItem) {
			is CborInt -> AttributeValue.Timestamp(Instant.fromEpochSeconds(tagValue.asNumber))
			is CborFloat -> AttributeValue.Timestamp(Instant.fromEpochMilliseconds((tagValue.value * 1000).toLong()))
			is CborDouble -> AttributeValue.Timestamp(Instant.fromEpochMilliseconds((tagValue.value * 1000).toLong()))
			else -> throw IllegalArgumentException("Invalid date time number tag")
		}

		// Nested CBOR data item
		Tagged.ENCODED_CBOR -> Cbor.decode(taggedItem.asBstr).toAttributeValue()

		// RFC 8943 date string
		Tagged.FULL_DATE_STRING -> AttributeValue.Date(this.asDateString)
		else -> taggedItem.toAttributeValue()
	}
	is Tstr -> AttributeValue.Text(value)
}
