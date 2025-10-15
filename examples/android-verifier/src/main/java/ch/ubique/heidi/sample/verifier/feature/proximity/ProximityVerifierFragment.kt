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

import android.Manifest
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.fragment.app.Fragment
import ch.ubique.heidi.sample.verifier.compose.theme.HeidiTheme
import ch.ubique.heidi.sample.verifier.databinding.FragmentComposeBinding
import org.koin.androidx.viewmodel.ext.android.viewModel
import org.koin.core.component.KoinComponent

class ProximityVerifierFragment : Fragment(), KoinComponent {

	companion object {
		val TAG = "ProximityFragment"

		fun newInstance() = ProximityVerifierFragment()
	}

	private val viewModel by viewModel<ProximityVerifierViewModel>()

	private var _binding: FragmentComposeBinding? = null
	private val binding get() = _binding!!

	private val launcher = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { permissions ->
		if (permissions.all { it.value }) {
			// TODO Handle permissions properly?
		}
	}

	override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
		_binding = FragmentComposeBinding.inflate(inflater, container, false)
		return binding.root
	}

	override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
		super.onViewCreated(view, savedInstanceState)

		launcher.launch(
			arrayOf(
				Manifest.permission.BLUETOOTH,
				Manifest.permission.BLUETOOTH_SCAN,
				Manifest.permission.BLUETOOTH_ADVERTISE,
				Manifest.permission.BLUETOOTH_CONNECT,
			)
		)

		binding.composeView.setContent {
			HeidiTheme {
				ProximityVerifierScreen(
					proofTemplate = viewModel.proofTemplate.collectAsState(),
					proximityState = viewModel.proximityState.collectAsState(),
					onProofTemplateChanged = viewModel::setProofTemplate,
					onStartVerificationClicked = viewModel::startEngagement,
					onRestartClicked = viewModel::reset,
				)
			}
		}
	}

	override fun onDestroyView() {
		super.onDestroyView()
		_binding = null
	}

}
