package com.peter.app.core.model

import android.graphics.drawable.Drawable

data class InstalledApp(
    val packageName: String,
    val displayName: String,
    val icon: Drawable?,
    val isWhitelisted: Boolean,
)
