package com.peter.app.feature.admin

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.peter.app.core.repository.SettingsRepository
import com.peter.app.core.util.PinHasher
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class SecurityState(
    val isMonitoringEnabled: Boolean = true,
    val isPinChangeMode: Boolean = false,
    val pinDigitsEntered: Int = 0,
    val isConfirming: Boolean = false,
    val pinError: Boolean = false,
    val pinChangeSuccess: Boolean = false,
)

@HiltViewModel
class SecurityViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(SecurityState())
    val state: StateFlow<SecurityState> = _state.asStateFlow()

    private val digits = mutableListOf<Int>()
    private var firstPin: String? = null

    init {
        viewModelScope.launch {
            settingsRepository.getAdminSettings().collect { settings ->
                _state.update {
                    it.copy(isMonitoringEnabled = settings?.isMonitoringEnabled ?: true)
                }
            }
        }
    }

    fun toggleMonitoring(enabled: Boolean) {
        viewModelScope.launch {
            settingsRepository.updateMonitoring(enabled)
        }
    }

    fun startPinChange() {
        digits.clear()
        firstPin = null
        _state.update {
            it.copy(
                isPinChangeMode = true,
                pinDigitsEntered = 0,
                isConfirming = false,
                pinError = false,
                pinChangeSuccess = false,
            )
        }
    }

    fun cancelPinChange() {
        digits.clear()
        firstPin = null
        _state.update {
            it.copy(isPinChangeMode = false, pinDigitsEntered = 0, isConfirming = false)
        }
    }

    fun onPinDigit(digit: Int) {
        if (digits.size >= 4) return
        digits.add(digit)
        _state.update { it.copy(pinDigitsEntered = digits.size, pinError = false) }

        if (digits.size == 4) {
            val pin = digits.joinToString("")
            if (firstPin == null) {
                firstPin = pin
                digits.clear()
                _state.update { it.copy(pinDigitsEntered = 0, isConfirming = true) }
            } else {
                if (pin == firstPin) {
                    viewModelScope.launch {
                        settingsRepository.updatePin(PinHasher.hash(pin))
                        _state.update {
                            it.copy(
                                isPinChangeMode = false,
                                pinChangeSuccess = true,
                                pinDigitsEntered = 0,
                                isConfirming = false,
                            )
                        }
                        delay(2000)
                        _state.update { it.copy(pinChangeSuccess = false) }
                    }
                } else {
                    firstPin = null
                    digits.clear()
                    _state.update {
                        it.copy(pinDigitsEntered = 0, isConfirming = false, pinError = true)
                    }
                    viewModelScope.launch {
                        delay(1500)
                        _state.update { it.copy(pinError = false) }
                    }
                }
            }
        }
    }

    fun onPinDelete() {
        if (digits.isNotEmpty()) {
            digits.removeAt(digits.lastIndex)
            _state.update { it.copy(pinDigitsEntered = digits.size, pinError = false) }
        }
    }
}
