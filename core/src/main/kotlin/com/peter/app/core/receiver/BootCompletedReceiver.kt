package com.peter.app.core.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.peter.app.core.service.ServiceController

class BootCompletedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            ServiceController.startMonitoring(context)
        }
    }
}
