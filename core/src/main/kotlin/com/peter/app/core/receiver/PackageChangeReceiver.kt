package com.peter.app.core.receiver

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.core.app.NotificationCompat
import com.peter.app.core.database.PeterDatabase
import com.peter.app.core.database.entity.GuardLogEntity
import com.peter.app.core.service.AppBlockerAccessibilityService
import com.peter.app.core.util.PackageGroupResolver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class PackageChangeReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "PackageChangeReceiver"
        private const val GUARD_CHANNEL_ID = "peter_guard_alerts"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart ?: return
        val isReplacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)

        when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                if (!isReplacing) {
                    handleNewInstall(context, packageName)
                }
            }
            Intent.ACTION_PACKAGE_REMOVED -> {
                if (!isReplacing) {
                    Log.w(TAG, "App removed: $packageName")
                }
            }
        }
    }

    private fun handleNewInstall(context: Context, packageName: String) {
        Log.w(TAG, "New app installed: $packageName")

        // If admin is unlocked (caregiver is managing), allow the install
        if (AppBlockerAccessibilityService.isAdminUnlocked) {
            Log.w(TAG, "Admin unlocked — allowing install of $packageName")
            return
        }

        // Check if the package is whitelisted (including group expansion)
        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val db = PeterDatabase.getInstance(context)
                val whitelistedPackages = db.whitelistedAppDao().getAllPackageNames().toSet()

                if (PackageGroupResolver.isAllowed(packageName, whitelistedPackages)) {
                    Log.w(TAG, "$packageName is whitelisted — keeping")
                } else {
                    Log.w(TAG, "UNAUTHORIZED install: $packageName — prompting uninstall")

                    // Log the event FIRST, before any other action
                    try {
                        db.guardLogDao().insert(
                            GuardLogEntity(
                                eventType = "INSTALL_BLOCKED",
                                packageName = packageName,
                                detail = "Auto-uninstall triggered (admin locked)",
                            )
                        )
                        Log.d(TAG, "Guard log entry saved for $packageName")
                    } catch (e: Exception) {
                        Log.e(TAG, "FAILED to save guard log for $packageName", e)
                    }

                    // Notify caregiver
                    postGuardNotification(context, packageName)

                    // Prompt uninstall LAST
                    val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                        data = Uri.parse("package:$packageName")
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    context.startActivity(uninstallIntent)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error handling install of $packageName", e)
            } finally {
                pendingResult.finish()
            }
        }
    }

    private fun postGuardNotification(context: Context, packageName: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Ensure channel exists
        val channel = NotificationChannel(
            GUARD_CHANNEL_ID,
            "Alertas de protección",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Alertas cuando se bloquea una instalación no autorizada"
        }
        nm.createNotificationChannel(channel)

        val notification = NotificationCompat.Builder(context, GUARD_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Instalación bloqueada")
            .setContentText("Se bloqueó la instalación de: $packageName")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        nm.notify(packageName.hashCode(), notification)
    }
}
