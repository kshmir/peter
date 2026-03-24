package com.peter.app.core.permission

import android.app.AppOpsManager
import android.content.Context
import android.os.Process
import android.provider.Settings
import javax.inject.Inject
import javax.inject.Singleton

data class PermissionState(
    val hasUsageStats: Boolean = false,
    val hasOverlay: Boolean = false,
    val hasWriteSettings: Boolean = false,
)

@Singleton
class PermissionChecker @Inject constructor() {

    fun check(context: Context): PermissionState {
        return PermissionState(
            hasUsageStats = hasUsageStatsPermission(context),
            hasOverlay = Settings.canDrawOverlays(context),
            hasWriteSettings = Settings.System.canWrite(context),
        )
    }

    fun hasUsageStatsPermission(context: Context): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = appOps.checkOpNoThrow(
            AppOpsManager.OPSTR_GET_USAGE_STATS,
            Process.myUid(),
            context.packageName,
        )
        return mode == AppOpsManager.MODE_ALLOWED
    }
}
