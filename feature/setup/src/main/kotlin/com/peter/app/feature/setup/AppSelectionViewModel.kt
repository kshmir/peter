package com.peter.app.feature.setup

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.peter.app.core.datastore.UserPreferences
import com.peter.app.core.model.InstalledApp
import com.peter.app.core.repository.AppRepository
import com.peter.app.core.service.AppBlockerAccessibilityService
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class AppSelectionViewModel @Inject constructor(
    private val appRepository: AppRepository,
    private val userPreferences: UserPreferences,
) : ViewModel() {

    val installedApps: StateFlow<List<InstalledApp>> =
        appRepository.getAllInstalledApps()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun toggleApp(packageName: String, displayName: String, enabled: Boolean) {
        viewModelScope.launch {
            if (enabled) {
                appRepository.addToWhitelist(packageName, displayName)
            } else {
                appRepository.removeFromWhitelist(packageName)
            }
        }
    }

    fun finishSetup() {
        viewModelScope.launch {
            userPreferences.setFirstRunComplete()
            AppBlockerAccessibilityService.settingsTemporarilyAllowed = false
        }
    }
}
