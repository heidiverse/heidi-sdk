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

package ch.ubique.heidi.wallet.process

interface ProcessStep {

	/**
	 * Generic loading step for all processes
	 */
	data object Loading : ProcessStep

	/**
	 * Indicator that the entire process has been completed
	 */
	data object ProcessCompleted : ProcessStep

	/**
	 * Converts the current step to an intermediary loading step based on the input [event].
	 * Defaults to [Loading] but can be overridden for a process specific loading state with more information.
	 * May be overridden by any [ProcessStep] to transform to a more specific loading state.
	 */
	fun toLoading(event: ProcessEvent): ProcessStep = Loading

}
