package com.peter.app.core.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class PackageChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart ?: return
        val isReplacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)

        when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                if (!isReplacing) {
                    Log.i("PackageChangeReceiver", "New app installed: $packageName")
                    // Future: notify admin about new app installation
                }
            }
            Intent.ACTION_PACKAGE_REMOVED -> {
                if (!isReplacing) {
                    Log.i("PackageChangeReceiver", "App removed: $packageName")
                }
            }
        }
    }
}
