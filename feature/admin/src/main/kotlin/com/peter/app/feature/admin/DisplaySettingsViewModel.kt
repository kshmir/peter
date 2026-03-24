package com.peter.app.feature.admin

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.peter.app.core.datastore.UserPreferences
import com.peter.app.core.repository.SettingsRepository
import com.peter.app.core.util.FontScaleHelper
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class DisplaySettingsViewModel @Inject constructor(
    private val userPreferences: UserPreferences,
    private val settingsRepository: SettingsRepository,
    @ApplicationContext private val context: Context,
) : ViewModel() {

    val fontScale: StateFlow<Float> = userPreferences.fontScale
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 1.0f)

    private val _appsPerRow = MutableStateFlow(3)
    val appsPerRow: StateFlow<Int> = _appsPerRow.asStateFlow()

    init {
        viewModelScope.launch {
            settingsRepository.getAdminSettings().collect { settings ->
                settings?.let {
                    _appsPerRow.value = it.maxAppsPerRow
                }
            }
        }
    }

    fun setFontScale(scale: Float) {
        viewModelScope.launch {
            userPreferences.setFontScale(scale)
            FontScaleHelper.setScale(context, scale)
        }
    }

    fun setAppsPerRow(count: Int) {
        _appsPerRow.value = count
        viewModelScope.launch {
            settingsRepository.updateMaxAppsPerRow(count)
        }
    }
}
