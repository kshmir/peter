package com.peter.app.feature.admin

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.ui.res.stringResource
import com.peter.app.ui.R
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminScreen(
    onBack: () -> Unit,
    onNavigateToWhitelist: () -> Unit,
    onNavigateToContacts: () -> Unit,
    onNavigateToDisplay: () -> Unit,
    onNavigateToSecurity: () -> Unit,
    onNavigateToGuardLog: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        TopAppBar(
            title = {
                Text(
                    stringResource(R.string.admin_title),
                    style = MaterialTheme.typography.titleLarge,
                )
            },
            navigationIcon = {
                IconButton(onClick = onBack) {
                    Icon(
                        Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = stringResource(R.string.back),
                        modifier = Modifier.size(32.dp),
                    )
                }
            },
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            AdminMenuItem(
                icon = Icons.Filled.Star,
                title = stringResource(R.string.admin_apps),
                subtitle = stringResource(R.string.admin_apps_subtitle),
                onClick = onNavigateToWhitelist,
            )
            Spacer(modifier = Modifier.height(12.dp))
            AdminMenuItem(
                icon = Icons.Filled.Person,
                title = stringResource(R.string.admin_contacts),
                subtitle = stringResource(R.string.admin_contacts_subtitle),
                onClick = onNavigateToContacts,
            )
            Spacer(modifier = Modifier.height(12.dp))
            AdminMenuItem(
                icon = Icons.Filled.Build,
                title = stringResource(R.string.admin_display),
                subtitle = stringResource(R.string.admin_display_subtitle),
                onClick = onNavigateToDisplay,
            )
            Spacer(modifier = Modifier.height(12.dp))
            AdminMenuItem(
                icon = Icons.Filled.Lock,
                title = stringResource(R.string.admin_security),
                subtitle = stringResource(R.string.admin_security_subtitle),
                onClick = onNavigateToSecurity,
            )
            Spacer(modifier = Modifier.height(12.dp))
            AdminMenuItem(
                icon = Icons.Filled.Notifications,
                title = stringResource(R.string.guard_log_title),
                subtitle = stringResource(R.string.guard_log_subtitle),
                onClick = onNavigateToGuardLog,
            )
        }
    }
}

@Composable
private fun AdminMenuItem(
    icon: ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                modifier = Modifier.size(32.dp),
                tint = MaterialTheme.colorScheme.primary,
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.bodyLarge,
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                contentDescription = null,
                modifier = Modifier.size(28.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
