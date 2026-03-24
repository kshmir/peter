package com.peter.app.core.model

import android.graphics.drawable.Drawable

data class WhitelistedApp(
    val packageName: String,
    val displayName: String,
    val icon: Drawable?,
    val sortOrder: Int,
)
