package com.peter.app.core.service

import android.graphics.Bitmap

/** Shared data between NotificationGuardService and InterceptActivity */
object InterceptData {
    @Volatile
    var pendingProfilePic: Bitmap? = null
}
