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
package ch.ubique.heidi.util.log

class Logger(val tag: String) {

	companion object {
		private const val DEFAULT_TAG = "Heidi"
		fun debug(msg: String) = Logger(DEFAULT_TAG).debug(msg)
		fun info(msg: String) = Logger(DEFAULT_TAG).info(msg)
		fun warn(msg: String) = Logger(DEFAULT_TAG).warn(msg)
		fun error(msg: String) = Logger(DEFAULT_TAG).error(msg)
		fun error(msg: String, throwable: Throwable) = Logger(DEFAULT_TAG).error(msg, throwable)
	}

	fun debug(msg: String) = this.d(msg)
	fun info(msg: String) = this.i(msg)
	fun warn(msg: String) = this.w(msg)
	fun error(msg: String) = this.e(msg)
	fun error(msg: String, throwable: Throwable) = this.e(msg, throwable)
}

expect fun Logger.d(msg: String)

expect fun Logger.i(msg: String)

expect fun Logger.w(msg: String)

expect fun Logger.e(msg: String)

expect fun Logger.e(msg: String, throwable: Throwable)
