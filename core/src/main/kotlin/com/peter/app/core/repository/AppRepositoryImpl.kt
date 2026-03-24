package com.peter.app.core.repository

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import com.peter.app.core.database.dao.WhitelistedAppDao
import com.peter.app.core.database.entity.WhitelistedAppEntity
import com.peter.app.core.model.InstalledApp
import com.peter.app.core.model.WhitelistedApp
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context,
    private val whitelistedAppDao: WhitelistedAppDao,
) : AppRepository {

    private fun queryLaunchableApps(): List<Pair<String, String>> {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolveInfos = context.packageManager.queryIntentActivities(intent, PackageManager.MATCH_ALL)
        return resolveInfos
            .filter { it.activityInfo.packageName != context.packageName }
            .map { info ->
                val packageName = info.activityInfo.packageName
                val label = info.loadLabel(context.packageManager).toString()
                packageName to label
            }
            .distinctBy { it.first }
            .sortedBy { it.second.lowercase() }
    }

    override fun getWhitelistedApps(): Flow<List<WhitelistedApp>> {
        return whitelistedAppDao.getAll().combine(flow { emit(Unit) }) { entities, _ ->
            entities.mapNotNull { entity ->
                val icon = try {
                    context.packageManager.getApplicationIcon(entity.packageName)
                } catch (_: PackageManager.NameNotFoundException) {
                    null
                }
                WhitelistedApp(
                    packageName = entity.packageName,
                    displayName = entity.displayName,
                    icon = icon,
                    sortOrder = entity.sortOrder,
                )
            }
        }
    }

    override fun getAllInstalledApps(): Flow<List<InstalledApp>> {
        return whitelistedAppDao.getAll().combine(flow { emit(queryLaunchableApps()) }) { whitelisted, installed ->
            val whitelistedSet = whitelisted.map { it.packageName }.toSet()
            installed.map { (packageName, label) ->
                val icon = try {
                    context.packageManager.getApplicationIcon(packageName)
                } catch (_: PackageManager.NameNotFoundException) {
                    null
                }
                InstalledApp(
                    packageName = packageName,
                    displayName = label,
                    icon = icon,
                    isWhitelisted = packageName in whitelistedSet,
                )
            }.sortedWith(compareByDescending<InstalledApp> { it.isWhitelisted }.thenBy { it.displayName.lowercase() })
        }
    }

    override suspend fun isWhitelisted(packageName: String): Boolean {
        return whitelistedAppDao.isWhitelistedSync(packageName)
    }

    override suspend fun addToWhitelist(packageName: String, displayName: String) {
        whitelistedAppDao.insert(
            WhitelistedAppEntity(
                packageName = packageName,
                displayName = displayName,
            )
        )
    }

    override suspend fun removeFromWhitelist(packageName: String) {
        whitelistedAppDao.deleteByPackageName(packageName)
    }

    override suspend fun getWhitelistedPackageNames(): Set<String> {
        return whitelistedAppDao.getAllPackageNames().toSet()
    }
}
