package com.peter.app.feature.admin

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.peter.app.core.repository.SettingsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class SecurityFiltersState(
    val isNotificationFilterEnabled: Boolean = true,
    val isConversationScanEnabled: Boolean = true,
    val isCallScreeningEnabled: Boolean = true,
)

@HiltViewModel
class SecurityFiltersViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(SecurityFiltersState())
    val state: StateFlow<SecurityFiltersState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            settingsRepository.getAdminSettings().collect { settings ->
                settings?.let {
                    _state.update { s ->
                        s.copy(
                            isNotificationFilterEnabled = it.isNotificationFilterEnabled,
                            isConversationScanEnabled = it.isConversationScanEnabled,
                            isCallScreeningEnabled = it.isCallScreeningEnabled,
                        )
                    }
                }
            }
        }
    }

    fun toggleNotificationFilter(enabled: Boolean) {
        _state.update { it.copy(isNotificationFilterEnabled = enabled) }
        viewModelScope.launch {
            val current = settingsRepository.getAdminSettingsSync() ?: return@launch
            settingsRepository.saveAdminSettings(current.copy(isNotificationFilterEnabled = enabled))
        }
    }

    fun toggleConversationScan(enabled: Boolean) {
        _state.update { it.copy(isConversationScanEnabled = enabled) }
        viewModelScope.launch {
            val current = settingsRepository.getAdminSettingsSync() ?: return@launch
            settingsRepository.saveAdminSettings(current.copy(isConversationScanEnabled = enabled))
        }
    }

    fun toggleCallScreening(enabled: Boolean) {
        _state.update { it.copy(isCallScreeningEnabled = enabled) }
        viewModelScope.launch {
            val current = settingsRepository.getAdminSettingsSync() ?: return@launch
            settingsRepository.saveAdminSettings(current.copy(isCallScreeningEnabled = enabled))
        }
    }
}
