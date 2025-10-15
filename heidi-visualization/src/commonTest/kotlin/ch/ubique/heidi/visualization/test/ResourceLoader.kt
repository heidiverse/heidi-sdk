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

package ch.ubique.heidi.visualization.test

import ch.ubique.heidi.visualization.Res
import org.jetbrains.compose.resources.ExperimentalResourceApi

/**
 * Note:
 * With Compose Multiplatform 1.6.11, Compose Resources in Unit Tests would work for Android and iOS, but not for JVM.
 * With Compose Multiplatform 1.7.3, Compose Resources in Unit Tests work for JVM and iOS, but not for Android.
 * See: https://youtrack.jetbrains.com/issue/CMP-6612/Support-non-compose-UI-tests-with-resources
 */
@OptIn(ExperimentalResourceApi::class)
suspend fun readResourceAsString(resourcePath: String): String {
	return Res.readBytes(resourcePath).decodeToString()
}