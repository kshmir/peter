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

data class PinEntryState(
    val enteredDigits: Int = 0,
    val isError: Boolean = false,
    val isCorrect: Boolean = false,
    val isLocked: Boolean = false,
    val lockSecondsRemaining: Int = 0,
    val failedAttempts: Int = 0,
    val isConfirming: Boolean = false,
)

@HiltViewModel
class PinEntryViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(PinEntryState())
    val state: StateFlow<PinEntryState> = _state.asStateFlow()

    private val digits = mutableListOf<Int>()
    private var firstPin: String? = null

    fun onDigitEntered(digit: Int) {
        if (_state.value.isLocked) return
        if (digits.size >= 4) return

        digits.add(digit)
        _state.update { it.copy(enteredDigits = digits.size, isError = false) }

        if (digits.size == 4) {
            verifyPin()
        }
    }

    fun onDigitEnteredForCreate(digit: Int) {
        if (digits.size >= 4) return

        digits.add(digit)
        _state.update { it.copy(enteredDigits = digits.size, isError = false) }

        if (digits.size == 4) {
            val pin = digits.joinToString("")
            if (firstPin == null) {
                // First entry — save and ask for confirmation
                firstPin = pin
                digits.clear()
                _state.update { it.copy(enteredDigits = 0, isConfirming = true) }
            } else {
                // Confirmation entry
                if (pin == firstPin) {
                    viewModelScope.launch {
                        val hash = PinHasher.hash(pin)
                        settingsRepository.saveAdminSettings(
                            com.peter.app.core.database.entity.AdminSettingsEntity(pinHash = hash)
                        )
                        _state.update { it.copy(isCorrect = true) }
                    }
                } else {
                    firstPin = null
                    digits.clear()
                    _state.update {
                        it.copy(enteredDigits = 0, isError = true, isConfirming = false)
                    }
                    viewModelScope.launch {
                        delay(1500)
                        _state.update { it.copy(isError = false) }
                    }
                }
            }
        }
    }

    fun onDelete() {
        if (digits.isNotEmpty()) {
            digits.removeAt(digits.lastIndex)
            _state.update { it.copy(enteredDigits = digits.size, isError = false) }
        }
    }

    private fun verifyPin() {
        viewModelScope.launch {
            val pin = digits.joinToString("")
            val hash = PinHasher.hash(pin)
            val correct = settingsRepository.verifyPin(hash)

            if (correct) {
                _state.update { it.copy(isCorrect = true) }
            } else {
                val attempts = _state.value.failedAttempts + 1
                digits.clear()

                if (attempts >= 3) {
                    _state.update {
                        it.copy(
                            enteredDigits = 0,
                            isError = true,
                            isLocked = true,
                            lockSecondsRemaining = 30,
                            failedAttempts = attempts,
                        )
                    }
                    // Countdown
                    for (i in 30 downTo 1) {
                        _state.update { it.copy(lockSecondsRemaining = i) }
                        delay(1000)
                    }
                    _state.update {
                        it.copy(isError = false, isLocked = false, failedAttempts = 0)
                    }
                } else {
                    _state.update {
                        it.copy(
                            enteredDigits = 0,
                            isError = true,
                            failedAttempts = attempts,
                        )
                    }
                    delay(1500)
                    _state.update { it.copy(isError = false) }
                }
            }
        }
    }
}
