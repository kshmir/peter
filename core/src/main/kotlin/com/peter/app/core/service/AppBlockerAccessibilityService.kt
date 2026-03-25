package com.peter.app.core.service

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import com.peter.app.core.database.PeterDatabase
import com.peter.app.core.util.PackageGroupResolver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

class AppBlockerAccessibilityService : AccessibilityService() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /** Cached expanded whitelist (includes package group members). Updated reactively. */
    @Volatile
    private var expandedAllowlist: Set<String> = emptySet()

    /** Whether monitoring/blocking is enabled. Updated from admin settings DB. */
    @Volatile
    private var monitoringEnabled: Boolean = true

    // System packages that must never be blocked
    private val systemAllowlist = setOf(
        "com.android.systemui",
        "com.google.android.permissioncontroller",
        "com.google.android.gms",
        "com.google.android.gsf",
        "android",
        // Keyboards — blocking these breaks text input
        "com.google.android.inputmethod.latin",  // Gboard
        "com.samsung.android.honeyboard",         // Samsung keyboard
        "com.android.inputmethod.latin",          // AOSP keyboard
        // System chrome views used by other apps
        "com.android.chrome",                     // WebView fallback
        "com.google.android.webview",
    )

    override fun onServiceConnected() {
        super.onServiceConnected()
        serviceInfo = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            notificationTimeout = 200
            flags = AccessibilityServiceInfo.DEFAULT
        }
        Log.d(TAG, "Accessibility service connected")

        val db = PeterDatabase.getInstance(this@AppBlockerAccessibilityService)

        // Observe whitelist changes and rebuild the expanded allowlist
        scope.launch {
            try {
                db.whitelistedAppDao().observeAllPackageNames()
                    .map { packages -> PackageGroupResolver.expandWhitelist(packages.toSet()) }
                    .collectLatest { expanded ->
                        expandedAllowlist = expanded
                        Log.d(TAG, "Allowlist updated: ${expanded.size} packages")
                    }
            } catch (e: Exception) {
                Log.e(TAG, "Error observing whitelist", e)
            }
        }

        // Observe monitoring toggle from admin settings
        scope.launch {
            try {
                db.adminSettingsDao().get().collectLatest { settings ->
                    monitoringEnabled = settings?.isMonitoringEnabled ?: true
                    Log.d(TAG, "Monitoring enabled: $monitoringEnabled")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error observing admin settings", e)
            }
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event?.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return

        // If monitoring is disabled, don't block anything
        if (!monitoringEnabled) return

        // If admin is unlocked (caregiver is managing), don't block anything
        if (isAdminUnlocked) return

        val packageName = event.packageName?.toString() ?: return
        // Skip our own app and system UI
        if (packageName == this.packageName || packageName in systemAllowlist) return

        // During setup, temporarily allow Settings
        if (settingsTemporarilyAllowed && packageName in SETTINGS_PACKAGES) return

        // If cache not populated yet, don't block anything (fail open on startup)
        val currentAllowlist = expandedAllowlist
        if (currentAllowlist.isEmpty()) return

        // Check against the cached expanded allowlist (includes group members)
        if (packageName in currentAllowlist) return

        Log.d(TAG, "BLOCKING: $packageName")

        // For stores/installers, press BACK to return to the previous app (e.g. YouTube)
        // For everything else, go HOME
        if (packageName in STORE_PACKAGES) {
            Log.d(TAG, "Store detected — pressing BACK")
            performGlobalAction(GLOBAL_ACTION_BACK)
        } else {
            val homeIntent = Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_HOME)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                setPackage(this@AppBlockerAccessibilityService.packageName)
            }
            startActivity(homeIntent)
        }
    }

    override fun onInterrupt() {
        Log.d(TAG, "Accessibility service interrupted")
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "PeterBlocker"

        private val SETTINGS_PACKAGES = setOf(
            "com.android.settings",
            "com.google.android.settings",
        )

        /** App stores / installers — press BACK instead of HOME to return to previous app */
        private val STORE_PACKAGES = setOf(
            "com.android.vending",                  // Play Store
            "com.android.packageinstaller",          // AOSP installer
            "com.google.android.packageinstaller",   // Google installer
            "com.samsung.android.packageinstaller",  // Samsung installer
        )

        /** Set to true during setup to temporarily allow Settings. */
        @Volatile
        var settingsTemporarilyAllowed: Boolean = false

        /** Set to true when admin PIN is entered. Allows app installs. */
        @Volatile
        var isAdminUnlocked: Boolean = false
    }
}
