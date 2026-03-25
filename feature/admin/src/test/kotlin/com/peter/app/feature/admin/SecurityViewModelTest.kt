package com.peter.app.feature.admin

import com.peter.app.core.database.entity.AdminSettingsEntity
import com.peter.app.core.repository.SettingsRepository
import com.peter.app.core.util.PinHasher
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SecurityViewModelTest {

    private val testDispatcher = UnconfinedTestDispatcher()
    private val settingsRepository = mockk<SettingsRepository>(relaxed = true)
    private lateinit var viewModel: SecurityViewModel

    @Before
    fun setup() {
        Dispatchers.setMain(testDispatcher)
        every { settingsRepository.getAdminSettings() } returns flowOf(
            AdminSettingsEntity(pinHash = "test", isMonitoringEnabled = true)
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `init loads monitoring state from settings`() = runTest {
        viewModel = SecurityViewModel(settingsRepository)

        assertTrue(viewModel.state.value.isMonitoringEnabled)
    }

    @Test
    fun `toggleMonitoring calls repository`() = runTest {
        viewModel = SecurityViewModel(settingsRepository)

        viewModel.toggleMonitoring(false)

        coVerify { settingsRepository.updateMonitoring(false) }
    }

    @Test
    fun `startPinChange enters pin change mode`() = runTest {
        viewModel = SecurityViewModel(settingsRepository)

        viewModel.startPinChange()

        assertTrue(viewModel.state.value.isPinChangeMode)
        assertEquals(0, viewModel.state.value.pinDigitsEntered)
    }

    @Test
    fun `cancelPinChange exits pin change mode`() = runTest {
        viewModel = SecurityViewModel(settingsRepository)

        viewModel.startPinChange()
        viewModel.onPinDigit(1)
        viewModel.cancelPinChange()

        assertFalse(viewModel.state.value.isPinChangeMode)
        assertEquals(0, viewModel.state.value.pinDigitsEntered)
    }

    @Test
    fun `entering 4 digits moves to confirmation`() = runTest {
        viewModel = SecurityViewModel(settingsRepository)
        viewModel.startPinChange()

        viewModel.onPinDigit(1)
        viewModel.onPinDigit(2)
        viewModel.onPinDigit(3)
        viewModel.onPinDigit(4)

        assertTrue(viewModel.state.value.isConfirming)
        assertEquals(0, viewModel.state.value.pinDigitsEntered)
    }

    @Test
    fun `matching confirmation updates pin`() = runTest {
        viewModel = SecurityViewModel(settingsRepository)
        viewModel.startPinChange()

        viewModel.onPinDigit(1)
        viewModel.onPinDigit(2)
        viewModel.onPinDigit(3)
        viewModel.onPinDigit(4)

        viewModel.onPinDigit(1)
        viewModel.onPinDigit(2)
        viewModel.onPinDigit(3)
        viewModel.onPinDigit(4)

        assertTrue(viewModel.state.value.pinChangeSuccess)
        assertFalse(viewModel.state.value.isPinChangeMode)
        coVerify { settingsRepository.updatePin(PinHasher.hash("1234")) }
    }

    @Test
    fun `mismatched confirmation resets`() = runTest {
        viewModel = SecurityViewModel(settingsRepository)
        viewModel.startPinChange()

        viewModel.onPinDigit(1)
        viewModel.onPinDigit(2)
        viewModel.onPinDigit(3)
        viewModel.onPinDigit(4)

        viewModel.onPinDigit(5)
        viewModel.onPinDigit(6)
        viewModel.onPinDigit(7)
        viewModel.onPinDigit(8)

        assertFalse(viewModel.state.value.isConfirming)
        assertEquals(0, viewModel.state.value.pinDigitsEntered)
    }

    @Test
    fun `onPinDelete removes digit`() = runTest {
        viewModel = SecurityViewModel(settingsRepository)
        viewModel.startPinChange()

        viewModel.onPinDigit(1)
        viewModel.onPinDigit(2)
        assertEquals(2, viewModel.state.value.pinDigitsEntered)

        viewModel.onPinDelete()
        assertEquals(1, viewModel.state.value.pinDigitsEntered)
    }
}
