package com.peter.app.core.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "guard_log")
data class GuardLogEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val eventType: String,
    val packageName: String,
    val detail: String = "",
    val timestamp: Long = System.currentTimeMillis(),
)
