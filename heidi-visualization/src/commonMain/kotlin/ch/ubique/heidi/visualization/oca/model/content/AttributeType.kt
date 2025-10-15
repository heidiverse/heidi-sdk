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

package ch.ubique.heidi.visualization.oca.model.content

import ch.ubique.heidi.visualization.oca.serialization.AttributeTypeSerializer
import kotlinx.serialization.Serializable

@Serializable(with = AttributeTypeSerializer::class)
sealed interface AttributeType {
	@Serializable
	data object Text : AttributeType

	@Serializable
	data object Numeric : AttributeType

	@Serializable
	data object Reference : AttributeType

	@Serializable
	data object Boolean : AttributeType

	@Serializable
	data object Binary : AttributeType

	@Serializable
	data object DateTime : AttributeType

	@Serializable
	data class Array(val contentType: AttributeType) : AttributeType

	@Serializable
	data object Unknown : AttributeType
}
