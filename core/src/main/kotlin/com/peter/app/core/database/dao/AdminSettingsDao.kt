package com.peter.app.core.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.peter.app.core.database.entity.AdminSettingsEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface AdminSettingsDao {
    @Query("SELECT * FROM admin_settings WHERE id = 1")
    fun get(): Flow<AdminSettingsEntity?>

    @Query("SELECT * FROM admin_settings WHERE id = 1")
    suspend fun getSync(): AdminSettingsEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(settings: AdminSettingsEntity)

    @Query("UPDATE admin_settings SET pinHash = :pinHash, updatedAt = :updatedAt WHERE id = 1")
    suspend fun updatePin(pinHash: String, updatedAt: Long = System.currentTimeMillis())

    @Query("UPDATE admin_settings SET isMonitoringEnabled = :enabled, updatedAt = :updatedAt WHERE id = 1")
    suspend fun updateMonitoring(enabled: Boolean, updatedAt: Long = System.currentTimeMillis())

    @Query("UPDATE admin_settings SET maxAppsPerRow = :count, updatedAt = :updatedAt WHERE id = 1")
    suspend fun updateMaxAppsPerRow(count: Int, updatedAt: Long = System.currentTimeMillis())
}
