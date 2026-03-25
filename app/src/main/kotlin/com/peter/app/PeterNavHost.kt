package com.peter.app

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.peter.app.core.service.AppBlockerAccessibilityService
import com.peter.app.feature.admin.AdminScreen
import com.peter.app.feature.admin.AppWhitelistScreen
import com.peter.app.feature.admin.ContactManagementScreen
import com.peter.app.feature.admin.DisplaySettingsScreen
import com.peter.app.feature.admin.GuardLogScreen
import com.peter.app.feature.admin.PinEntryScreen
import com.peter.app.feature.admin.SecurityScreen
import com.peter.app.feature.contacts.ContactsScreen
import com.peter.app.feature.home.HomeScreen
import com.peter.app.feature.setup.AppSelectionScreen
import com.peter.app.feature.setup.PermissionSetupScreen
import com.peter.app.feature.setup.WelcomeScreen
import kotlinx.serialization.Serializable

// Routes
@Serializable object WelcomeRoute
@Serializable object SetupPinRoute
@Serializable object SetupPermissionsRoute
@Serializable object SetupAppsRoute
@Serializable object HomeRoute
@Serializable object PinEntryRoute
@Serializable object AdminRoute
@Serializable object AppWhitelistRoute
@Serializable object ContactManagementRoute
@Serializable object DisplaySettingsRoute
@Serializable object SecurityRoute
@Serializable object GuardLogRoute
@Serializable object ContactsRoute

@Composable
fun PeterNavHost(
    viewModel: MainViewModel = hiltViewModel(),
) {
    val isFirstRun by viewModel.isFirstRun.collectAsState()
    val navController = rememberNavController()

    val startDestination: Any = if (isFirstRun) WelcomeRoute else HomeRoute

    NavHost(navController = navController, startDestination = startDestination) {

        // Setup flow
        composable<WelcomeRoute> {
            WelcomeScreen(
                onStart = { navController.navigate(SetupPinRoute) },
            )
        }

        composable<SetupPinRoute> {
            PinEntryScreen(
                isCreatingPin = true,
                onPinCorrect = {
                    navController.navigate(SetupPermissionsRoute) {
                        popUpTo(SetupPinRoute) { inclusive = true }
                    }
                },
                onCancel = { navController.popBackStack() },
            )
        }

        composable<SetupPermissionsRoute> {
            PermissionSetupScreen(
                onAllGranted = {
                    navController.navigate(SetupAppsRoute) {
                        popUpTo(SetupPermissionsRoute) { inclusive = true }
                    }
                },
            )
        }

        composable<SetupAppsRoute> {
            AppSelectionScreen(
                onDone = {
                    navController.navigate(HomeRoute) {
                        popUpTo(0) { inclusive = true }
                    }
                },
            )
        }

        // Main app
        composable<HomeRoute> {
            HomeScreen(
                onNavigateToAdmin = {
                    navController.navigate(PinEntryRoute)
                },
                onNavigateToContacts = {
                    navController.navigate(ContactsRoute)
                },
            )
        }

        composable<PinEntryRoute> {
            PinEntryScreen(
                onPinCorrect = {
                    AppBlockerAccessibilityService.isAdminUnlocked = true
                    navController.navigate(AdminRoute) {
                        popUpTo(PinEntryRoute) { inclusive = true }
                    }
                },
                onCancel = { navController.popBackStack() },
            )
        }

        composable<AdminRoute> {
            AdminScreen(
                onBack = {
                    AppBlockerAccessibilityService.isAdminUnlocked = false
                    navController.popBackStack(HomeRoute, inclusive = false)
                },
                onNavigateToWhitelist = {
                    navController.navigate(AppWhitelistRoute)
                },
                onNavigateToContacts = {
                    navController.navigate(ContactManagementRoute)
                },
                onNavigateToDisplay = {
                    navController.navigate(DisplaySettingsRoute)
                },
                onNavigateToSecurity = {
                    navController.navigate(SecurityRoute)
                },
                onNavigateToGuardLog = {
                    navController.navigate(GuardLogRoute)
                },
            )
        }

        composable<AppWhitelistRoute> {
            AppWhitelistScreen(
                onBack = { navController.popBackStack() },
            )
        }

        composable<DisplaySettingsRoute> {
            DisplaySettingsScreen(
                onBack = { navController.popBackStack() },
            )
        }

        composable<SecurityRoute> {
            SecurityScreen(
                onBack = { navController.popBackStack() },
            )
        }

        composable<GuardLogRoute> {
            GuardLogScreen(
                onBack = { navController.popBackStack() },
            )
        }

        composable<ContactManagementRoute> {
            ContactManagementScreen(
                onBack = { navController.popBackStack() },
            )
        }

        composable<ContactsRoute> {
            ContactsScreen(
                onBack = { navController.popBackStack() },
            )
        }
    }
}
