package com.peter.app.core.permission

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import androidx.core.app.NotificationManagerCompat
import javax.inject.Inject
import javax.inject.Singleton

data class PermissionState(
    val hasAccessibility: Boolean = false,
    val hasWriteSettings: Boolean = false,
    val hasNotificationAccess: Boolean = false,
)

@Singleton
class PermissionChecker @Inject constructor() {

    fun check(context: Context): PermissionState {
        return PermissionState(
            hasAccessibility = isAccessibilityServiceEnabled(context),
            hasWriteSettings = Settings.System.canWrite(context),
            hasNotificationAccess = isNotificationListenerEnabled(context),
        )
    }

    fun isAccessibilityServiceEnabled(context: Context): Boolean {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabledServices = am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_GENERIC
        )
        return enabledServices.any {
            it.resolveInfo.serviceInfo.packageName == context.packageName
        }
    }

    fun isNotificationListenerEnabled(context: Context): Boolean {
        return NotificationManagerCompat.getEnabledListenerPackages(context)
            .contains(context.packageName)
    }
}
