package com.peter.app.feature.setup

import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import androidx.hilt.navigation.compose.hiltViewModel
import com.peter.app.core.service.AppBlockerAccessibilityService
import com.peter.app.ui.R

@Composable
fun PermissionSetupScreen(
    onAllGranted: () -> Unit,
    viewModel: PermissionSetupViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current

    // Allow Settings access during permission setup
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        AppBlockerAccessibilityService.settingsTemporarilyAllowed = true
        viewModel.refreshPermissions(context)
    }

    val roleLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        viewModel.refreshPermissions(context)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(24.dp),
    ) {
        Text(
            text = stringResource(R.string.setup_step, 2, 4),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { 0.5f },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = stringResource(R.string.setup_permissions_title),
            style = MaterialTheme.typography.headlineSmall,
        )
        Spacer(modifier = Modifier.height(16.dp))

        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState()),
        ) {
            // 1. Home screen (no blocking involved)
            PermissionItem(
                title = stringResource(R.string.perm_home),
                description = stringResource(R.string.perm_home_desc),
                granted = state.isDefaultHome,
                onGrant = {
                    val roleManager = context.getSystemService(Context.ROLE_SERVICE) as RoleManager
                    if (roleManager.isRoleAvailable(RoleManager.ROLE_HOME)) {
                        roleLauncher.launch(roleManager.createRequestRoleIntent(RoleManager.ROLE_HOME))
                    }
                },
            )

            Spacer(modifier = Modifier.height(12.dp))

            // 2. Write settings (no blocking involved)
            PermissionItem(
                title = stringResource(R.string.perm_write_settings),
                description = stringResource(R.string.perm_write_settings_desc),
                granted = state.hasWriteSettings,
                onGrant = {
                    context.startActivity(
                        Intent(
                            Settings.ACTION_MANAGE_WRITE_SETTINGS,
                            Uri.parse("package:${context.packageName}"),
                        )
                    )
                },
            )

            Spacer(modifier = Modifier.height(12.dp))

            // 3. Notification access (no blocking involved)
            PermissionItem(
                title = stringResource(R.string.perm_notification_access),
                description = stringResource(R.string.perm_notification_access_desc),
                granted = state.hasNotificationAccess,
                onGrant = {
                    context.startActivity(
                        Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS")
                    )
                },
            )

            Spacer(modifier = Modifier.height(12.dp))

            // 4. Accessibility — LAST because it enables app blocking
            PermissionItem(
                title = stringResource(R.string.perm_overlay),
                description = stringResource(R.string.perm_overlay_desc),
                granted = state.hasAccessibility,
                onGrant = {
                    context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                },
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = {
                AppBlockerAccessibilityService.settingsTemporarilyAllowed = false
                onAllGranted()
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = MaterialTheme.shapes.medium,
            enabled = state.hasAccessibility,
        ) {
            Text(
                text = stringResource(R.string.continue_btn),
                style = MaterialTheme.typography.labelLarge,
            )
        }
    }
}

@Composable
private fun PermissionItem(
    title: String,
    description: String,
    granted: Boolean,
    onGrant: () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = if (granted) Icons.Filled.Check else Icons.Filled.Close,
                contentDescription = null,
                modifier = Modifier.size(28.dp),
                tint = if (granted) MaterialTheme.colorScheme.tertiary
                else MaterialTheme.colorScheme.error,
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(text = title, style = MaterialTheme.typography.bodyLarge)
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (!granted) {
                Spacer(modifier = Modifier.width(8.dp))
                OutlinedButton(onClick = onGrant) {
                    Text(stringResource(R.string.grant_permission), style = MaterialTheme.typography.labelMedium)
                }
            }
        }
    }
}
