/*
 * Copyright 2025 Ubique Innovation AG
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package ch.ubique.heidi.issuance.extensions

import ch.ubique.heidi.issuance.metadata.data.Display

fun List<Display>?.getLocalizedLabel(locale: String): String? {
	if (this == null) return null
	firstOrNull { it.locale.equals(locale, ignoreCase = true) && !it.name.isNullOrBlank() }?.name?.let { return it }

	firstOrNull { it.locale.equals("en", ignoreCase = true) && !it.name.isNullOrBlank() }?.name?.let { return it }

	return firstOrNull { !it.name.isNullOrBlank() }?.name
}