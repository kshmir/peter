package com.peter.app.core.service

import android.accessibilityservice.AccessibilityService
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import com.peter.app.core.database.PeterDatabase
import com.peter.app.core.database.entity.GuardLogEntity
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

    @Volatile
    private var expandedAllowlist: Set<String> = emptySet()

    @Volatile
    private var monitoringEnabled: Boolean = true

    private var packageReceiver: BroadcastReceiver? = null

    private val systemAllowlist = setOf(
        "com.android.systemui",
        "com.google.android.permissioncontroller",
        "com.google.android.gms",
        "com.google.android.gsf",
        "android",
        "com.google.android.inputmethod.latin",
        "com.samsung.android.honeyboard",
        "com.android.inputmethod.latin",
        "com.google.android.webview",
    )

    override fun onServiceConnected() {
        super.onServiceConnected()
        isAdminUnlocked = false
        settingsTemporarilyAllowed = false
        Log.w(TAG, "Service connected")

        val db = PeterDatabase.getInstance(this)

        scope.launch {
            try {
                db.whitelistedAppDao().observeAllPackageNames()
                    .map { PackageGroupResolver.expandWhitelist(it.toSet()) }
                    .collectLatest { expanded ->
                        expandedAllowlist = expanded
                        Log.w(TAG, "Allowlist: ${expanded.size} packages")
                    }
            } catch (e: Exception) {
                Log.e(TAG, "Error observing whitelist", e)
            }
        }

        scope.launch {
            try {
                db.adminSettingsDao().get().collectLatest { settings ->
                    monitoringEnabled = settings?.isMonitoringEnabled ?: true
                    Log.w(TAG, "Monitoring: $monitoringEnabled")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error observing settings", e)
            }
        }

        registerPackageReceiver(db)
    }

    private fun registerPackageReceiver(db: PeterDatabase) {
        packageReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != Intent.ACTION_PACKAGE_ADDED) return
                if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return

                val pkg = intent.data?.schemeSpecificPart ?: return
                Log.w(TAG, "PACKAGE_ADDED: $pkg (admin=$isAdminUnlocked)")

                if (isAdminUnlocked) return

                scope.launch {
                    try {
                        val whitelisted = db.whitelistedAppDao().getAllPackageNames().toSet()
                        if (!PackageGroupResolver.isAllowed(pkg, whitelisted)) {
                            Log.w(TAG, "Unauthorized install detected: $pkg")
                            db.guardLogDao().insert(
                                GuardLogEntity(
                                    eventType = "INSTALL_DETECTED",
                                    packageName = pkg,
                                    detail = "Unauthorized app installed while admin locked",
                                )
                            )
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error checking install: $pkg", e)
                    }
                }
            }
        }

        val filter = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply {
            addDataScheme("package")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(packageReceiver, filter, RECEIVER_EXPORTED)
        } else {
            registerReceiver(packageReceiver, filter)
        }
        Log.w(TAG, "Package receiver registered")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event?.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
        if (!monitoringEnabled) return
        if (isAdminUnlocked) return

        val packageName = event.packageName?.toString() ?: return

        if (packageName == this.packageName) {
            if (settingsTemporarilyAllowed) settingsTemporarilyAllowed = false
            if (isAdminUnlocked) isAdminUnlocked = false
            return
        }

        if (packageName in systemAllowlist) return

        if (settingsTemporarilyAllowed) {
            if (packageName in SETTINGS_PACKAGES) return
            if (packageName !in systemAllowlist) settingsTemporarilyAllowed = false
        }

        val currentAllowlist = expandedAllowlist
        if (currentAllowlist.isEmpty()) return
        if (packageName in currentAllowlist) return

        Log.w(TAG, "BLOCKING: $packageName")

        scope.launch {
            try {
                PeterDatabase.getInstance(this@AppBlockerAccessibilityService)
                    .guardLogDao().insert(
                        GuardLogEntity(
                            eventType = "APP_BLOCKED",
                            packageName = packageName,
                            detail = "Blocked by accessibility service",
                        )
                    )
            } catch (_: Exception) {}
        }

        if (packageName in STORE_PACKAGES) {
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

    override fun onInterrupt() {}

    override fun onDestroy() {
        packageReceiver?.let {
            try { unregisterReceiver(it) } catch (_: Exception) {}
        }
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "PeterBlocker"

        private val SETTINGS_PACKAGES = setOf(
            "com.android.settings",
            "com.google.android.settings",
            "com.samsung.android.settings",
            "com.sec.android.app.SecSetupWizard",
        )

        private val STORE_PACKAGES = setOf(
            "com.android.vending",
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.samsung.android.packageinstaller",
        )

        @Volatile
        var settingsTemporarilyAllowed: Boolean = false

        @Volatile
        var isAdminUnlocked: Boolean = false
    }
}
