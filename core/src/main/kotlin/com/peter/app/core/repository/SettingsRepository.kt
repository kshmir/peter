package com.peter.app.core.repository

import com.peter.app.core.database.entity.AdminSettingsEntity
import kotlinx.coroutines.flow.Flow

interface SettingsRepository {
    fun getAdminSettings(): Flow<AdminSettingsEntity?>
    suspend fun getAdminSettingsSync(): AdminSettingsEntity?
    suspend fun saveAdminSettings(settings: AdminSettingsEntity)
    suspend fun updatePin(pinHash: String)
    suspend fun updateMonitoring(enabled: Boolean)
    suspend fun updateMaxAppsPerRow(count: Int)
    suspend fun verifyPin(pinHash: String): Boolean
}
