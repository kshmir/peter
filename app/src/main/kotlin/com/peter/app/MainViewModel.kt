package com.peter.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.peter.app.core.datastore.UserPreferences
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    userPreferences: UserPreferences,
) : ViewModel() {

    val isFirstRun: StateFlow<Boolean> = userPreferences.isFirstRun
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)
}
