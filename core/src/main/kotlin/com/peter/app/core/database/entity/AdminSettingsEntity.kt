package com.peter.app.core.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "admin_settings")
data class AdminSettingsEntity(
    @PrimaryKey
    val id: Int = 1,
    val pinHash: String,
    val isMonitoringEnabled: Boolean = true,
    val maxAppsPerRow: Int = 3,
    val showClock: Boolean = true,
    val showBatteryStatus: Boolean = true,
    val updatedAt: Long = System.currentTimeMillis(),
)
