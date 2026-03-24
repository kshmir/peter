package com.peter.app.core.datastore

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.floatPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class UserPreferences @Inject constructor(
    private val dataStore: DataStore<Preferences>,
) {
    val isFirstRun: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[IS_FIRST_RUN] ?: true
    }

    val fontScale: Flow<Float> = dataStore.data.map { prefs ->
        prefs[FONT_SCALE] ?: 1.0f
    }

    val isMonitoringEnabled: Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[MONITORING_ENABLED] ?: true
    }

    val localeOverride: Flow<String> = dataStore.data.map { prefs ->
        prefs[LOCALE_OVERRIDE] ?: ""
    }

    suspend fun setFirstRunComplete() {
        dataStore.edit { it[IS_FIRST_RUN] = false }
    }

    suspend fun setFontScale(scale: Float) {
        dataStore.edit { it[FONT_SCALE] = scale }
    }

    suspend fun setMonitoringEnabled(enabled: Boolean) {
        dataStore.edit { it[MONITORING_ENABLED] = enabled }
    }

    suspend fun setLocaleOverride(locale: String) {
        dataStore.edit { it[LOCALE_OVERRIDE] = locale }
    }

    companion object {
        private val IS_FIRST_RUN = booleanPreferencesKey("is_first_run")
        private val FONT_SCALE = floatPreferencesKey("font_scale")
        private val MONITORING_ENABLED = booleanPreferencesKey("monitoring_enabled")
        private val LOCALE_OVERRIDE = stringPreferencesKey("locale_override")
    }
}
