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

package ch.ubique.heidi.visualization.stylejson.template

import ch.ubique.heidi.visualization.oca.model.content.AttributeName

internal class StyleJsonTemplate(private val template: String) {

	companion object {
		private val regex = "\\{\\{\\s*(\\S+)\\s*\\}\\}".toRegex()
	}

	fun interpolate(
		valueProvider: (AttributeName) -> String?,
	): String {
		return template.replace(regex) { matchResult ->
			val matchGroup = matchResult.groups[1]
			val key = matchGroup?.value
			if (key == null) {
				matchResult.value
			} else {
				valueProvider.invoke(key) ?: matchResult.value
			}
		}
	}
}
