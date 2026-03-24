package com.peter.app.core.util

import android.content.Context
import android.provider.Settings

object FontScaleHelper {
    fun getCurrentScale(context: Context): Float {
        return Settings.System.getFloat(
            context.contentResolver,
            Settings.System.FONT_SCALE,
            1.0f,
        )
    }

    fun setScale(context: Context, scale: Float): Boolean {
        return if (Settings.System.canWrite(context)) {
            Settings.System.putFloat(
                context.contentResolver,
                Settings.System.FONT_SCALE,
                scale.coerceIn(0.85f, 2.0f),
            )
            true
        } else {
            false
        }
    }

    fun canWriteSettings(context: Context): Boolean {
        return Settings.System.canWrite(context)
    }
}
