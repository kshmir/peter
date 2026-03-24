package com.peter.app.core.repository

import com.peter.app.core.model.InstalledApp
import com.peter.app.core.model.WhitelistedApp
import kotlinx.coroutines.flow.Flow

interface AppRepository {
    fun getWhitelistedApps(): Flow<List<WhitelistedApp>>
    fun getAllInstalledApps(): Flow<List<InstalledApp>>
    suspend fun isWhitelisted(packageName: String): Boolean
    suspend fun addToWhitelist(packageName: String, displayName: String)
    suspend fun removeFromWhitelist(packageName: String)
    suspend fun getWhitelistedPackageNames(): Set<String>
}
