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
package ch.ubique.heidi.sample.wallet.extensions

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * Does not emit the current value if the last value was emitted more recently than now - duration and the condition is true.
 * Otherwise the values are passed on as usual.
 */
fun <T> Flow<T>.throttleIf(duration: Long, condition: (T) -> Boolean): Flow<T> = flow {
	var lastEmissionTime = 0L
	collect { value ->
		if (!condition(value)) {
			emit(value)
		} else {
			val currentTime = System.currentTimeMillis()
			val mayEmit = currentTime - lastEmissionTime > duration
			if (mayEmit) {
				lastEmissionTime = currentTime
				emit(value)
			}
		}
	}
}
