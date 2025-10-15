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

import android.util.Log

actual fun Logger.d(msg: String) {
	Log.d(this.tag, msg)
}

actual fun Logger.i(msg: String) {
	Log.i(this.tag, msg)
}

actual fun Logger.w(msg: String) {
	Log.w(this.tag, msg)
}

actual fun Logger.e(msg: String) {
	Log.e(this.tag, msg)
}

actual fun Logger.e(msg: String, throwable: Throwable) {
	Log.e(this.tag, msg, throwable)
}
