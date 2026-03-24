package com.peter.app.core.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "whitelisted_apps")
data class WhitelistedAppEntity(
    @PrimaryKey
    val packageName: String,
    val displayName: String,
    val sortOrder: Int = 0,
    val addedAt: Long = System.currentTimeMillis(),
)
