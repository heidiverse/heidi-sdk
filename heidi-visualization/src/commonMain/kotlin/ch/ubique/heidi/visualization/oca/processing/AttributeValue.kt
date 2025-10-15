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

@file:OptIn(ExperimentalTime::class)

package ch.ubique.heidi.visualization.oca.processing

import kotlinx.datetime.*
import kotlinx.datetime.format.FormatStringsInDatetimeFormats
import kotlinx.datetime.format.byUnicodePattern
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

sealed interface AttributeValue<T> {
	val value: T

	@OptIn(ExperimentalEncodingApi::class, FormatStringsInDatetimeFormats::class)
	fun asString(): String = when (this) {
		is Bool -> value.toString()
		is Date -> value.format(LocalDate.Format { byUnicodePattern("dd.MM.yyyy") })
		is DateTime -> value.format(LocalDateTime.Format { byUnicodePattern("dd.MM.yyyy HH:mm") })
		is Image -> Base64.encode(value)
		is Array<*> -> value.joinToString(",") { it.asString() }
		is Raw -> value
		is Text -> value
		is Timestamp -> value.toLocalDateTime(TimeZone.currentSystemDefault())
			.format(LocalDateTime.Format { byUnicodePattern("dd.MM.yyyy HH:mm") })
		is Link -> value
	}

	data class Text(override val value: String) : AttributeValue<String>
	data class Bool(override val value: Boolean) : AttributeValue<Boolean>
	data class Image(override val value: ByteArray, val format: String? = null) : AttributeValue<ByteArray>
	data class Array<T : AttributeValue<*>>(override val value: List<T>) : AttributeValue<List<T>>
	data class Timestamp(override val value: Instant) : AttributeValue<Instant>
	data class Date(override val value: LocalDate) : AttributeValue<LocalDate>
	data class DateTime(override val value: LocalDateTime) : AttributeValue<LocalDateTime>
	data class Raw(override val value: String, val format: String? = null) : AttributeValue<String>
	enum class LinkType { Mail, Phone, Web, Download }
	data class Link(override val value: String, val linkType: LinkType) : AttributeValue<String>
}
