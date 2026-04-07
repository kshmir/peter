package com.peter.app.feature.home

import android.graphics.drawable.Drawable
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.peter.app.feature.home.components.AppTile
import com.peter.app.feature.home.components.ClockWidget
import com.peter.app.feature.home.components.ContactsTile
import com.peter.app.ui.R

private sealed class HomeTileItem(val key: String) {
    class App(val displayName: String, val icon: Drawable?, val packageName: String) :
        HomeTileItem(packageName)
    object Contacts : HomeTileItem("__contacts__")
}

@Composable
fun HomeScreen(
    onNavigateToAdmin: () -> Unit = {},
    onNavigateToContacts: () -> Unit = {},
    viewModel: HomeViewModel = hiltViewModel(),
) {
    val apps by viewModel.whitelistedApps.collectAsState()
    val columns by viewModel.columns.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .windowInsetsPadding(WindowInsets.systemBars),
    ) {
        ClockWidget(
            onAdminTrigger = onNavigateToAdmin,
        )

        // Build tile list: whitelisted apps only
        val tiles: List<HomeTileItem> = apps.map {
            HomeTileItem.App(it.displayName, it.icon, it.packageName)
        }

        val rows = tiles.chunked(columns)

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            rows.forEach { rowItems ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    rowItems.forEach { item ->
                        when (item) {
                            is HomeTileItem.App -> AppTile(
                                name = item.displayName,
                                icon = item.icon,
                                onClick = { viewModel.launchApp(item.packageName) },
                                modifier = Modifier
                                    .weight(1f)
                                    .fillMaxHeight(),
                            )
                            is HomeTileItem.Contacts -> ContactsTile(
                                onClick = onNavigateToContacts,
                                modifier = Modifier
                                    .weight(1f)
                                    .fillMaxHeight(),
                            )
                        }
                    }
                    repeat(columns - rowItems.size) {
                        Spacer(modifier = Modifier.weight(1f))
                    }
                }
            }
        }
    }
}
