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
    @Volatile
    private var conversationScanEnabled: Boolean = true

    private var packageReceiver: BroadcastReceiver? = null

    private val PHONE_REGEX = Regex("""^\+?\d[\d\s\-()]{6,}$""")

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
        // OEM launchers (handle recents/window switcher)
        "com.motorola.launcher3",
        "com.sec.android.app.launcher",
        "com.google.android.apps.nexuslauncher",
        "com.android.launcher3",
    )

    override fun onServiceConnected() {
        super.onServiceConnected()
        isAdminUnlocked = false
        // Always allow Settings on service connect — the flag will be cleared
        // when user returns to Peter home screen after setup
        settingsTemporarilyAllowed = true
        Log.w(TAG, "Service connected — Settings allowed until home screen seen")

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
                    conversationScanEnabled = settings?.isConversationScanEnabled ?: true
                    Log.w(TAG, "Monitoring: $monitoringEnabled, ConversationScan: $conversationScanEnabled")
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
        val eventType = event?.eventType ?: return
        val packageName = event.packageName?.toString() ?: return

        // When WhatsApp is active, scan the screen for contact info
        if ((packageName == "com.whatsapp" || packageName == "com.whatsapp.w4b") && conversationScanEnabled) {
            scanWhatsAppScreen()
            if (eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
        } else {
            // Left WhatsApp — reset warning tracker
            if (lastWarnedContact != null) {
                lastWarnedContact = null
            }
            if (eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
        }
        if (!monitoringEnabled) return
        if (isAdminUnlocked) return

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

        // Fast path: check in-memory cache
        val currentAllowlist = expandedAllowlist
        if (currentAllowlist.isNotEmpty() && packageName in currentAllowlist) return

        // Slow path: verify against DB and block if needed
        scope.launch {
            try {
                val db = PeterDatabase.getInstance(this@AppBlockerAccessibilityService)
                val freshWhitelist = db.whitelistedAppDao().getAllPackageNames().toSet()
                val expanded = PackageGroupResolver.expandWhitelist(freshWhitelist)
                expandedAllowlist = expanded

                if (packageName in expanded) {
                    Log.w(TAG, "Allowed after DB check: $packageName")
                    return@launch
                }

                Log.w(TAG, "BLOCKING: $packageName")

                db.guardLogDao().insert(
                    GuardLogEntity(
                        eventType = "APP_BLOCKED",
                        packageName = packageName,
                        detail = "Blocked by accessibility service",
                    )
                )

                // Block on main thread
                kotlinx.coroutines.withContext(Dispatchers.Main) {
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
            } catch (e: Exception) {
                Log.e(TAG, "Error in blocking check", e)
            }
        }
    }

    /** Track last warned contact to avoid spamming */
    @Volatile
    private var lastWarnedContact: String? = null
    @Volatile
    private var lastScanTime: Long = 0

    /** Find the avatar bounds from WhatsApp's accessibility tree */
    private fun findAvatarBounds(): android.graphics.Rect? {
        val root = rootInActiveWindow ?: return null
        try {
            return findNodeBounds(root, "conversation_contact_photo")
                ?: findNodeBounds(root, "photo")
                ?: findNodeBounds(root, "avatar")
        } finally {
            root.recycle()
        }
    }

    private fun findNodeBounds(
        node: android.view.accessibility.AccessibilityNodeInfo,
        idContains: String,
    ): android.graphics.Rect? {
        val viewId = node.viewIdResourceName ?: ""
        if (viewId.contains(idContains, ignoreCase = true)) {
            val rect = android.graphics.Rect()
            node.getBoundsInScreen(rect)
            if (rect.width() > 10 && rect.height() > 10) {
                Log.w(TAG, "Found avatar node: $viewId bounds=$rect")
                return rect
            }
        }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val result = findNodeBounds(child, idContains)
            child.recycle()
            if (result != null) return result
        }
        return null
    }

    /** Extract profile pic then run callback on main thread */
    private fun extractProfilePicThen(onDone: () -> Unit) {
        val avatarBounds = findAvatarBounds()
        try {
            takeScreenshot(
                android.view.Display.DEFAULT_DISPLAY,
                mainExecutor,
                object : TakeScreenshotCallback {
                    override fun onSuccess(screenshot: ScreenshotResult) {
                        try {
                            val hwBitmap = android.graphics.Bitmap.wrapHardwareBuffer(
                                screenshot.hardwareBuffer, screenshot.colorSpace
                            )
                            if (hwBitmap != null) {
                                val softBitmap = hwBitmap.copy(android.graphics.Bitmap.Config.ARGB_8888, false)
                                if (avatarBounds != null && avatarBounds.width() > 20) {
                                    val x = avatarBounds.left.coerceIn(0, softBitmap.width - 1)
                                    val y = avatarBounds.top.coerceIn(0, softBitmap.height - 1)
                                    val w = avatarBounds.width().coerceAtMost(softBitmap.width - x)
                                    val h = avatarBounds.height().coerceAtMost(softBitmap.height - y)
                                    InterceptData.pendingProfilePic = android.graphics.Bitmap.createBitmap(softBitmap, x, y, w, h)
                                    Log.w(TAG, "Profile pic (exact): ${w}x${h}")
                                } else {
                                    val size = (softBitmap.width * 0.1f).toInt().coerceIn(80, 200)
                                    InterceptData.pendingProfilePic = android.graphics.Bitmap.createBitmap(softBitmap, (softBitmap.width * 0.12f).toInt(), (softBitmap.height * 0.03f).toInt(), size, size)
                                    Log.w(TAG, "Profile pic (estimate): ${size}x${size}")
                                }
                                softBitmap.recycle()
                                hwBitmap.recycle()
                            }
                            screenshot.hardwareBuffer.close()
                        } catch (e: Exception) {
                            Log.e(TAG, "Error cropping", e)
                        }
                        onDone()
                    }

                    override fun onFailure(errorCode: Int) {
                        Log.w(TAG, "Screenshot failed: $errorCode")
                        onDone() // still proceed even without pic
                    }
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "takeScreenshot error", e)
            onDone()
        }
    }

    /** Extract profile picture from WhatsApp conversation screen (fire and forget) */
    private fun extractProfilePic() {
        Log.w(TAG, "Attempting screenshot for profile pic...")

        // First find the exact avatar bounds from the accessibility tree
        val avatarBounds = findAvatarBounds()
        Log.w(TAG, "Avatar bounds from tree: $avatarBounds")

        try {
            takeScreenshot(
                android.view.Display.DEFAULT_DISPLAY,
                mainExecutor,
                object : TakeScreenshotCallback {
                    override fun onSuccess(screenshot: ScreenshotResult) {
                        try {
                            val hwBitmap = android.graphics.Bitmap.wrapHardwareBuffer(
                                screenshot.hardwareBuffer, screenshot.colorSpace
                            )
                            if (hwBitmap != null) {
                                val softBitmap = hwBitmap.copy(android.graphics.Bitmap.Config.ARGB_8888, false)
                                val sw = softBitmap.width
                                val sh = softBitmap.height
                                Log.w(TAG, "Screenshot: ${sw}x${sh}")

                                val cropped = if (avatarBounds != null && avatarBounds.width() > 20) {
                                    // Use exact bounds from accessibility tree
                                    val x = avatarBounds.left.coerceIn(0, sw - 1)
                                    val y = avatarBounds.top.coerceIn(0, sh - 1)
                                    val w = avatarBounds.width().coerceAtMost(sw - x)
                                    val h = avatarBounds.height().coerceAtMost(sh - y)
                                    Log.w(TAG, "Cropping with exact bounds: x=$x y=$y w=$w h=$h")
                                    android.graphics.Bitmap.createBitmap(softBitmap, x, y, w, h)
                                } else {
                                    // Fallback: estimate avatar position
                                    val size = (sw * 0.1f).toInt().coerceIn(80, 200)
                                    val x = (sw * 0.12f).toInt()
                                    val y = (sh * 0.03f).toInt()
                                    Log.w(TAG, "Cropping with estimate: x=$x y=$y size=$size")
                                    android.graphics.Bitmap.createBitmap(softBitmap, x, y, size, size)
                                }

                                InterceptData.pendingProfilePic = cropped
                                Log.w(TAG, "Profile pic extracted: ${cropped.width}x${cropped.height}")
                                softBitmap.recycle()
                                hwBitmap.recycle()
                            }
                            screenshot.hardwareBuffer.close()
                        } catch (e: Exception) {
                            Log.e(TAG, "Error cropping screenshot", e)
                        }
                    }

                    override fun onFailure(errorCode: Int) {
                        Log.w(TAG, "Screenshot failed: $errorCode")
                    }
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "takeScreenshot error: ${e.message}", e)
        }
    }

    /** Scan WhatsApp's UI to find the current conversation contact */
    private fun scanWhatsAppScreen() {
        val now = System.currentTimeMillis()
        if (now - lastScanTime < 3000) return // throttle: max once per 3s
        lastScanTime = now

        val root = rootInActiveWindow ?: return
        try {
            val allText = mutableListOf<String>()
            val allIds = mutableListOf<String>()
            collectTextNodes(root, allText, allIds, depth = 0)

            // Find the contact name from WhatsApp's toolbar
            var contactName: String? = null
            var messages = mutableListOf<String>()

            for (i in allText.indices) {
                val id = allIds.getOrElse(i) { "" }
                when {
                    id.contains("conversation_contact_name") -> contactName = allText[i]
                    id.contains("message_text") -> messages.add(allText[i])
                }
            }

            if (contactName == null) return

            // Check if this is an unknown contact (phone number as name)
            val isPhoneNumber = PHONE_REGEX.matches(contactName.trim())

            // Skip named contacts — only alert for phone numbers
            if (!isPhoneNumber) return

            // Detect group chats: if message senders contain ":" it's a group (sender: message format)
            // Also WhatsApp groups show member count in subtitle area
            val hasGroupIndicator = allText.any { it.contains("participants") || it.contains("participantes") || it.contains("membros") }
            if (hasGroupIndicator) return

            // Only warn once per contact
            if (contactName == lastWarnedContact) return

            // Check for scam FIRST — if quarantining, skip the notification
            var quarantined = false
            Log.w(TAG, "Scan: contact=$contactName messages=${messages.size} texts: ${messages.joinToString(" | ").take(200)}")
            if (messages.isNotEmpty()) {
                val fullConversation = messages.joinToString(" ")
                val analysis = com.peter.app.core.util.ScamPatternDetector.analyze(fullConversation)
                Log.w(TAG, "Scan result: suspicious=${analysis.isSuspicious} confidence=${analysis.confidence} pattern=${analysis.matchedPattern}")
                if (analysis.isSuspicious) {
                    Log.w(TAG, "WhatsApp: SCAM in conversation with $contactName (confidence=${analysis.confidence}, level=${analysis.threatLevel}): ${analysis.matchedPattern}")
                    lastWarnedContact = contactName
                    quarantined = true

                    Log.w(TAG, "QUARANTINE — step 1: screenshot")
                    val patternText = analysis.matchedPattern
                    val conf = analysis.confidence
                    val contact = contactName ?: "Desconocido"
                    val msg = fullConversation.take(200)

                    // Step 1: Screenshot while conversation is still visible
                    // Step 2: BACK + overlay happen in the callback after screenshot completes
                    extractProfilePicThen {
                        Log.w(TAG, "QUARANTINE — step 2: BACK")
                        performGlobalAction(GLOBAL_ACTION_BACK)

                        scope.launch {
                            kotlinx.coroutines.delay(400) // let BACK process
                            Log.w(TAG, "QUARANTINE — step 3: overlay")
                            val intent = Intent("com.peter.app.ACTION_INTERCEPT_NOTIFICATION").apply {
                                setPackage(packageName)
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_MULTIPLE_TASK)
                                putExtra("sender", contact)
                                putExtra("message", msg)
                                putExtra("phone", contact)
                                putExtra("threat_level", 2)
                                putExtra("threat_label", "Estafa detectada")
                                putExtra("threat_desc", "Patrones de estafa: \"$patternText\"")
                                putExtra("status", "QUARANTINED")
                            }
                            startActivity(intent)

                            try {
                                PeterDatabase.getInstance(this@AppBlockerAccessibilityService)
                                    .guardLogDao().insert(GuardLogEntity(
                                        eventType = "SCAM_QUARANTINED",
                                        packageName = "com.whatsapp",
                                        detail = "Contact: $contact | Pattern: $patternText | Confidence: $conf",
                                    ))
                            } catch (_: Exception) {}
                        }
                    }
                }
            }

            // Show floating warning for unknown contacts ONLY if not quarantined
            if (!quarantined && isPhoneNumber) {
                Log.w(TAG, "WhatsApp: chatting with UNKNOWN number: $contactName")
                lastWarnedContact = contactName
                extractProfilePic()
                showFloatingWarning(
                    contactName,
                    "Estás hablando con un número desconocido",
                    0,
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error scanning WhatsApp", e)
        } finally {
            root.recycle()
        }
    }

    private fun showFloatingWarning(contact: String, message: String, threatLevel: Int) {
        val channelId = "peter_wa_warning"
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
        nm.createNotificationChannel(
            android.app.NotificationChannel(channelId, "WhatsApp Warnings", android.app.NotificationManager.IMPORTANCE_HIGH)
        )

        val color = when (threatLevel) {
            0 -> android.graphics.Color.rgb(255, 179, 0)   // amber
            1 -> android.graphics.Color.rgb(255, 152, 0)   // orange
            else -> android.graphics.Color.rgb(244, 67, 54) // red
        }

        val notification = androidx.core.app.NotificationCompat.Builder(this, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(if (threatLevel >= 1) "⚠ Mensaje sospechoso" else "Contacto desconocido")
            .setContentText("$contact: $message")
            .setColor(color)
            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_MAX)
            .setCategory(androidx.core.app.NotificationCompat.CATEGORY_ALARM)
            .setOngoing(false)
            .setAutoCancel(true)
            .build()

        nm.notify(88888, notification)
    }

    private fun collectTextNodes(
        node: android.view.accessibility.AccessibilityNodeInfo,
        texts: MutableList<String>,
        ids: MutableList<String>,
        depth: Int,
    ) {
        val text = node.text?.toString()
        val desc = node.contentDescription?.toString()
        val viewId = node.viewIdResourceName ?: ""

        if (!text.isNullOrBlank()) {
            texts.add(text)
            ids.add(viewId)
        } else if (!desc.isNullOrBlank() && depth < 5) {
            texts.add("[desc] $desc")
            ids.add(viewId)
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectTextNodes(child, texts, ids, depth + 1)
            child.recycle()
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
