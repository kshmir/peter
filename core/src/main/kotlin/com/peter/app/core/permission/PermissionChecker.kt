package com.peter.app.core.permission

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import javax.inject.Inject
import javax.inject.Singleton

data class PermissionState(
    val hasAccessibility: Boolean = false,
    val hasWriteSettings: Boolean = false,
    val hasNotificationAccess: Boolean = false,
    val hasContacts: Boolean = false,
    val hasCallLog: Boolean = false,
)

@Singleton
class PermissionChecker @Inject constructor() {

    fun check(context: Context): PermissionState {
        return PermissionState(
            hasAccessibility = isAccessibilityServiceEnabled(context),
            hasWriteSettings = Settings.System.canWrite(context),
            hasNotificationAccess = isNotificationListenerEnabled(context),
            hasContacts = ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED,
            hasCallLog = ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CALL_LOG) == PackageManager.PERMISSION_GRANTED,
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
