package com.peter.app.core.repository

import com.peter.app.core.database.dao.AdminSettingsDao
import com.peter.app.core.database.entity.AdminSettingsEntity
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SettingsRepositoryImpl @Inject constructor(
    private val adminSettingsDao: AdminSettingsDao,
) : SettingsRepository {

    override fun getAdminSettings(): Flow<AdminSettingsEntity?> {
        return adminSettingsDao.get()
    }

    override suspend fun getAdminSettingsSync(): AdminSettingsEntity? {
        return adminSettingsDao.getSync()
    }

    override suspend fun saveAdminSettings(settings: AdminSettingsEntity) {
        adminSettingsDao.upsert(settings)
    }

    override suspend fun updatePin(pinHash: String) {
        adminSettingsDao.updatePin(pinHash)
    }

    override suspend fun updateMonitoring(enabled: Boolean) {
        adminSettingsDao.updateMonitoring(enabled)
    }

    override suspend fun updateMaxAppsPerRow(count: Int) {
        adminSettingsDao.updateMaxAppsPerRow(count)
    }

    override suspend fun verifyPin(pinHash: String): Boolean {
        val settings = adminSettingsDao.getSync() ?: return false
        return settings.pinHash == pinHash
    }
}
