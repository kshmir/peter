package com.peter.app.core.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class BootCompletedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            Log.d("PeterBoot", "Boot completed — Accessibility Service will auto-restart")
            // The Accessibility Service is managed by the system and persists across reboots
            // as long as the user has it enabled in Settings > Accessibility
        }
    }
}
