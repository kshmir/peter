package com.peter.app.core.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.os.IBinder
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.app.NotificationCompat
import com.peter.app.core.database.PeterDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class AppMonitorService : Service() {

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var monitorJob: Job? = null
    private var overlayView: LinearLayout? = null
    private var windowManager: WindowManager? = null

    // System packages that should never be blocked
    private val systemAllowlist = setOf(
        "com.android.systemui",
        "com.android.launcher3",
        "com.google.android.permissioncontroller",
        "com.android.settings", // Allow during permission grants
        "com.android.packageinstaller",
        "android",
    )

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startMonitoring()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        monitorJob?.cancel()
        removeOverlay()
        scope.cancel()
        super.onDestroy()
    }

    private fun startMonitoring() {
        monitorJob?.cancel()
        monitorJob = scope.launch {
            val usageStatsManager = getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
            val db = PeterDatabase.getInstance(this@AppMonitorService)

            while (true) {
                try {
                    val foregroundPackage = getForegroundPackage(usageStatsManager)
                    if (foregroundPackage != null &&
                        foregroundPackage != packageName &&
                        foregroundPackage !in systemAllowlist
                    ) {
                        val isWhitelisted = db.whitelistedAppDao().isWhitelistedSync(foregroundPackage)
                        if (!isWhitelisted) {
                            showOverlay()
                        } else {
                            removeOverlay()
                        }
                    } else {
                        removeOverlay()
                    }
                } catch (_: Exception) {
                    // Ignore errors in monitoring loop
                }
                delay(1500)
            }
        }
    }

    private fun getForegroundPackage(usageStatsManager: UsageStatsManager): String? {
        val now = System.currentTimeMillis()
        val events = usageStatsManager.queryEvents(now - 5000, now)
        val event = UsageEvents.Event()
        var foregroundPackage: String? = null

        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            if (event.eventType == UsageEvents.Event.ACTIVITY_RESUMED) {
                foregroundPackage = event.packageName
            }
        }
        return foregroundPackage
    }

    private fun showOverlay() {
        if (overlayView != null) return
        if (!android.provider.Settings.canDrawOverlays(this)) return

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(0xE0212121.toInt()) // Semi-transparent dark
            setPadding(48, 48, 48, 48)
        }

        val messageText = TextView(this).apply {
            text = "Esta aplicación no está\ndisponible."
            textSize = 24f
            setTextColor(0xFFFFFFFF.toInt())
            gravity = Gravity.CENTER
        }

        val button = Button(this).apply {
            text = "Volver al Inicio"
            textSize = 20f
            setPadding(48, 24, 48, 24)
            setOnClickListener {
                removeOverlay()
                val homeIntent = Intent(Intent.ACTION_MAIN).apply {
                    addCategory(Intent.CATEGORY_HOME)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    setPackage(this@AppMonitorService.packageName)
                }
                startActivity(homeIntent)
            }
        }

        layout.addView(messageText)
        layout.addView(button, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = 48 })

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT,
        )

        windowManager?.addView(layout, params)
        overlayView = layout
    }

    private fun removeOverlay() {
        overlayView?.let {
            try {
                windowManager?.removeView(it)
            } catch (_: Exception) {
                // Already removed
            }
            overlayView = null
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Peter Protección",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Mantiene la protección de aplicaciones activa"
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Peter activo")
            .setContentText("Protección de aplicaciones activa")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "peter_monitor"
        private const val NOTIFICATION_ID = 1001
    }
}
