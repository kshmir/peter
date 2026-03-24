package com.peter.app.core.service

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

object ServiceController {
    fun startMonitoring(context: Context) {
        val intent = Intent(context, AppMonitorService::class.java)
        ContextCompat.startForegroundService(context, intent)
    }

    fun stopMonitoring(context: Context) {
        val intent = Intent(context, AppMonitorService::class.java)
        context.stopService(intent)
    }
}
