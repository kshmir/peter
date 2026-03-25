# Peter ProGuard / R8 rules

# ── Room ──
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keep @androidx.room.Dao class *

# ── Hilt ──
-keep class dagger.hilt.** { *; }
-keep class * extends dagger.hilt.android.internal.managers.ViewComponentManager$FragmentContextWrapper { *; }

# ── Kotlin Serialization ──
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.peter.app.**$$serializer { *; }
-keepclassmembers class com.peter.app.** {
    *** Companion;
}
-keepclasseswithmembers class com.peter.app.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# ── Coroutines ──
-dontwarn kotlinx.coroutines.**

# ── Accessibility Service ──
-keep class com.peter.app.core.service.AppBlockerAccessibilityService { *; }

# ── Broadcast Receivers ──
-keep class com.peter.app.core.receiver.** { *; }

# ── DataStore ──
-keepclassmembers class * extends androidx.datastore.preferences.protobuf.GeneratedMessageLite {
    <fields>;
}

# ── Keep Compose stability ──
-dontwarn androidx.compose.**
