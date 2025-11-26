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
package ch.ubique.heidi.sample.verifier.feature.proximity

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import ch.ubique.heidi.proximity.verifier.ProximityVerifierState
import ch.ubique.heidi.sample.verifier.compose.components.QrCodeImage
import ch.ubique.heidi.sample.verifier.data.model.VerificationDisclosureResult
import ch.ubique.heidi.sample.verifier.feature.network.ProofTemplate

@Composable
fun ProximityVerifierScreen(
	proofTemplate: State<ProofTemplate>,
	proximityState: State<ProximityVerifierState>,
	onProofTemplateChanged: (ProofTemplate) -> Unit,
	onStartVerificationClicked: () -> Unit,
	onRestartClicked: () -> Unit,
) {
	Scaffold(
		containerColor = MaterialTheme.colorScheme.surface,
	) { innerPadding ->
		AnimatedContent(
			modifier = Modifier.padding(innerPadding),
			targetState = proximityState.value,
			contentKey = { it.javaClass.simpleName },
			transitionSpec = {
				fadeIn(animationSpec = tween(220, delayMillis = 90)) togetherWith fadeOut(animationSpec = tween(90))
			}
		) { state ->
			Box(Modifier.fillMaxSize()) {
				when (state) {
					is ProximityVerifierState.Initial -> {
						Column(
							modifier = Modifier.align(Alignment.Center),
						) {
							Row(
								verticalAlignment = Alignment.CenterVertically,
								modifier = Modifier
									.clickable { onProofTemplateChanged.invoke(ProofTemplate.IDENTITY_CARD_CHECK) }
									.padding(vertical = 8.dp)
							) {
								RadioButton(selected = proofTemplate.value == ProofTemplate.IDENTITY_CARD_CHECK, onClick = null)
								Spacer(Modifier.width(4.dp))
								Text("Identity Card Check")
							}
							Row(
								verticalAlignment = Alignment.CenterVertically,
								modifier = Modifier
									.clickable { onProofTemplateChanged.invoke(ProofTemplate.AGE_OVER_16) }
									.padding(vertical = 8.dp)
							) {
								RadioButton(selected = proofTemplate.value == ProofTemplate.AGE_OVER_16, onClick = null)
								Spacer(Modifier.width(4.dp))
								Text("Age over 16")
							}
							Row(
								verticalAlignment = Alignment.CenterVertically,
								modifier = Modifier
									.clickable { onProofTemplateChanged.invoke(ProofTemplate.AGE_OVER_18) }
									.padding(vertical = 8.dp)
							) {
								RadioButton(selected = proofTemplate.value == ProofTemplate.AGE_OVER_18, onClick = null)
								Spacer(Modifier.width(4.dp))
								Text("Age over 18")
							}
							Row(
								verticalAlignment = Alignment.CenterVertically,
								modifier = Modifier
									.clickable { onProofTemplateChanged.invoke(ProofTemplate.AGE_OVER_65) }
									.padding(vertical = 8.dp)
							) {
								RadioButton(selected = proofTemplate.value == ProofTemplate.AGE_OVER_65, onClick = null)
								Spacer(Modifier.width(4.dp))
								Text("Age over 65")
							}

							Spacer(Modifier.height(12.dp))

							Button(
								onClick = onStartVerificationClicked,
								modifier = Modifier.align(Alignment.CenterHorizontally)
							) {
								Text("Start Verification")
							}
						}
					}
					is ProximityVerifierState.PreparingEngagement -> {
						Column(
							modifier = Modifier.align(Alignment.Center),
							horizontalAlignment = Alignment.CenterHorizontally
						) {
							CircularProgressIndicator()
							Spacer(Modifier.height(8.dp))
							Text("Loading verification request")
						}
					}
					is ProximityVerifierState.ReadyForEngagement -> {
						QrCodeImage(
							state.qrCodeData, modifier = Modifier
								.fillMaxWidth()
								.aspectRatio(1f)
						)
					}
					is ProximityVerifierState.Connecting -> {
						Column(
							modifier = Modifier.align(Alignment.Center),
							horizontalAlignment = Alignment.CenterHorizontally
						) {
							CircularProgressIndicator()
							Spacer(Modifier.height(8.dp))
							Text("Connecting with Wallet")
						}
					}
					is ProximityVerifierState.Connected -> {
						Column(
							modifier = Modifier.align(Alignment.Center),
							horizontalAlignment = Alignment.CenterHorizontally
						) {
							CircularProgressIndicator()
							Spacer(Modifier.height(8.dp))
							Text("Connection established")
						}
					}
					is ProximityVerifierState.AwaitingDocuments -> {
						Column(
							modifier = Modifier.align(Alignment.Center),
							horizontalAlignment = Alignment.CenterHorizontally
						) {
							Text("Awaiting documents from wallet")
						}
					}
					is ProximityVerifierState.VerificationResult<*> -> {
						Column(
							horizontalAlignment = Alignment.CenterHorizontally,
							modifier = Modifier
								.align(Alignment.Center)
								.fillMaxHeight()
								.padding(horizontal = 16.dp, vertical = 32.dp),
						) {
//							val icon = if (state.result.isVerificationSuccessful) Icons.Default.Check else Icons.Default.Clear
//
//							Icon(
//								icon,
//								contentDescription = null,
//								tint = MaterialTheme.colorScheme.surface,
//								modifier = Modifier
//									.size(48.dp)
//									.background(if (state.result.isVerificationSuccessful) Color.Green else Color.Red, CircleShape)
//									.padding(4.dp),
//							)
//
//							Spacer(Modifier.height(12.dp))
//
//							state.result.disclosures?.let { disclosures ->
//								Column(
//									verticalArrangement = Arrangement.spacedBy(8.dp),
//									modifier = Modifier.verticalScroll(rememberScrollState())
//								) {
//									disclosures.forEach { (namespace, data) ->
//										Text(namespace, style = MaterialTheme.typography.headlineMedium)
//										data.forEach { (key, values) ->
//											Text(key, style = MaterialTheme.typography.bodySmall)
//											values.forEach { value ->
//												Text(value.toString(), style = MaterialTheme.typography.bodyMedium)
//											}
//										}
//									}
//								}
//							}

							Spacer(Modifier.height(12.dp))

							Button(onClick = onRestartClicked) {
								Text("Restart Verification")
							}
						}
					}
					is ProximityVerifierState.Disconnected -> {
						Column(
							modifier = Modifier.align(Alignment.Center),
							horizontalAlignment = Alignment.CenterHorizontally
						) {
							Text("Disconnected from wallet")
							Spacer(Modifier.height(8.dp))
							Button(onClick = onRestartClicked) {
								Text("Restart Verification")
							}
						}
					}
					is ProximityVerifierState.Terminated -> {
						Column(
							modifier = Modifier.align(Alignment.Center),
							horizontalAlignment = Alignment.CenterHorizontally
						) {
							Text("Session terminated (${state.reason})")
							Spacer(Modifier.height(8.dp))
							Button(onClick = onRestartClicked) {
								Text("Restart Verification")
							}
						}
					}
					is ProximityVerifierState.Error -> {
						Text(state.throwable.stackTraceToString())
					}
				}
			}
		}
	}
}
