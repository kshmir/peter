package com.peter.app.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val PeterColorScheme = lightColorScheme(
    primary = Amber600,
    onPrimary = Neutral900,
    primaryContainer = Amber100,
    onPrimaryContainer = Neutral900,
    secondary = Orange600,
    onSecondary = White,
    secondaryContainer = Orange400,
    onSecondaryContainer = Neutral900,
    tertiary = Green600,
    onTertiary = White,
    tertiaryContainer = Green600,
    onTertiaryContainer = White,
    error = Red700,
    onError = White,
    errorContainer = Red400,
    onErrorContainer = White,
    background = BackgroundWarm,
    onBackground = Neutral900,
    surface = White,
    onSurface = Neutral900,
    surfaceVariant = Neutral100,
    onSurfaceVariant = Neutral800,
    outline = Neutral200,
)

@Composable
fun PeterTheme(
    content: @Composable () -> Unit,
) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window ?: return@SideEffect
            // Dark status bar icons on light background
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = true
            // Dark navigation bar icons too
            WindowCompat.getInsetsController(window, view).isAppearanceLightNavigationBars = true
        }
    }

    MaterialTheme(
        colorScheme = PeterColorScheme,
        typography = PeterTypography,
        shapes = PeterShapes,
        content = content,
    )
}
