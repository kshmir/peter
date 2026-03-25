package com.peter.app.core.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import androidx.core.app.NotificationCompat
import com.peter.app.core.database.PeterDatabase
import com.peter.app.core.database.entity.GuardLogEntity
import com.peter.app.core.util.ScamPatternDetector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class WhatsAppNotificationGuardService : NotificationListenerService() {

    companion object {
        private const val TAG = "NotifGuard"
        private const val WHATSAPP_PKG = "com.whatsapp"
        private const val WHATSAPP_BIZ_PKG = "com.whatsapp.w4b"
        private const val GUARD_CHANNEL_ID = "peter_notif_guard"
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onCreate() {
        super.onCreate()
        createChannel()
        Log.d(TAG, "WhatsApp notification guard started")
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName != WHATSAPP_PKG && sbn.packageName != WHATSAPP_BIZ_PKG) return

        val extras = sbn.notification.extras ?: return
        val sender = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
            ?: extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
            ?: ""

        if (text.isBlank()) return

        val analysis = ScamPatternDetector.analyze(text)
        if (analysis.isSuspicious) {
            Log.w(TAG, "SUSPICIOUS from '$sender': matched '${analysis.matchedPattern}'")

            // Cancel the original notification
            cancelNotification(sbn.key)

            // Post a warning
            postWarning(sender, analysis.matchedPattern)

            // Log to database
            scope.launch {
                try {
                    val db = PeterDatabase.getInstance(this@WhatsAppNotificationGuardService)
                    db.guardLogDao().insert(
                        GuardLogEntity(
                            eventType = "NOTIFICATION_BLOCKED",
                            packageName = sbn.packageName,
                            detail = "From: $sender | Match: ${analysis.matchedPattern}",
                        )
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Error logging guard event", e)
                }
            }
        }
    }

    private fun postWarning(sender: String, matchedPattern: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        val notification = NotificationCompat.Builder(this, GUARD_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Mensaje sospechoso bloqueado")
            .setContentText("Se ocultó un mensaje de \"$sender\"")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(
                        "Se ocultó un mensaje de \"$sender\" porque parecía sospechoso " +
                        "(detectado: $matchedPattern).\n\n" +
                        "Si fue un error, pida a un familiar que lo revise."
                    )
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        nm.notify(System.currentTimeMillis().toInt(), notification)
    }

    private fun createChannel() {
        val channel = NotificationChannel(
            GUARD_CHANNEL_ID,
            "Protección de notificaciones",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Alertas cuando se bloquean mensajes sospechosos de WhatsApp"
        }
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(channel)
    }
}
