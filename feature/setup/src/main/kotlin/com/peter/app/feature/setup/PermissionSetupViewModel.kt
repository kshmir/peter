package com.peter.app.feature.setup

import android.app.role.RoleManager
import android.content.Context
import androidx.lifecycle.ViewModel
import com.peter.app.core.permission.PermissionChecker
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import javax.inject.Inject

data class PermissionSetupState(
    val isDefaultHome: Boolean = false,
    val hasAccessibility: Boolean = false,
    val hasWriteSettings: Boolean = false,
    val hasNotificationAccess: Boolean = false,
    val hasContacts: Boolean = false,
    val hasCallLog: Boolean = false,
)

@HiltViewModel
class PermissionSetupViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val permissionChecker: PermissionChecker,
) : ViewModel() {

    private val _state = MutableStateFlow(PermissionSetupState())
    val state: StateFlow<PermissionSetupState> = _state.asStateFlow()

    init {
        refreshPermissions(context)
    }

    fun refreshPermissions(context: Context) {
        val permState = permissionChecker.check(context)
        val roleManager = context.getSystemService(Context.ROLE_SERVICE) as RoleManager
        val isHome = roleManager.isRoleHeld(RoleManager.ROLE_HOME)

        _state.update {
            it.copy(
                isDefaultHome = isHome,
                hasAccessibility = permState.hasAccessibility,
                hasWriteSettings = permState.hasWriteSettings,
                hasNotificationAccess = permState.hasNotificationAccess,
                hasContacts = permState.hasContacts,
                hasCallLog = permState.hasCallLog,
            )
        }
    }
}
