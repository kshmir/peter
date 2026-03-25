package com.peter.app.feature.admin

import com.peter.app.core.repository.SettingsRepository
import com.peter.app.core.util.PinHasher
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
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
class PinEntryViewModelTest {

    private val testDispatcher = UnconfinedTestDispatcher()
    private val settingsRepository = mockk<SettingsRepository>(relaxed = true)
    private lateinit var viewModel: PinEntryViewModel

    @Before
    fun setup() {
        Dispatchers.setMain(testDispatcher)
        viewModel = PinEntryViewModel(settingsRepository)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `initial state is empty`() {
        val state = viewModel.state.value
        assertEquals(0, state.enteredDigits)
        assertFalse(state.isError)
        assertFalse(state.isCorrect)
        assertFalse(state.isLocked)
    }

    @Test
    fun `entering digits updates count`() {
        viewModel.onDigitEntered(1)
        assertEquals(1, viewModel.state.value.enteredDigits)

        viewModel.onDigitEntered(2)
        assertEquals(2, viewModel.state.value.enteredDigits)

        viewModel.onDigitEntered(3)
        assertEquals(3, viewModel.state.value.enteredDigits)
    }

    @Test
    fun `delete removes last digit`() {
        viewModel.onDigitEntered(1)
        viewModel.onDigitEntered(2)
        viewModel.onDelete()
        assertEquals(1, viewModel.state.value.enteredDigits)
    }

    @Test
    fun `delete on empty does nothing`() {
        viewModel.onDelete()
        assertEquals(0, viewModel.state.value.enteredDigits)
    }

    @Test
    fun `correct pin sets isCorrect true`() = runTest {
        val hash = PinHasher.hash("1234")
        coEvery { settingsRepository.verifyPin(hash) } returns true

        viewModel.onDigitEntered(1)
        viewModel.onDigitEntered(2)
        viewModel.onDigitEntered(3)
        viewModel.onDigitEntered(4)

        assertTrue(viewModel.state.value.isCorrect)
    }

    @Test
    fun `wrong pin increments failed attempts`() = runTest {
        coEvery { settingsRepository.verifyPin(any()) } returns false

        viewModel.onDigitEntered(9)
        viewModel.onDigitEntered(9)
        viewModel.onDigitEntered(9)
        viewModel.onDigitEntered(9)

        assertEquals(1, viewModel.state.value.failedAttempts)
        assertEquals(0, viewModel.state.value.enteredDigits)
    }

    @Test
    fun `create pin flow - first entry moves to confirming`() = runTest {
        viewModel.onDigitEnteredForCreate(1)
        viewModel.onDigitEnteredForCreate(2)
        viewModel.onDigitEnteredForCreate(3)
        viewModel.onDigitEnteredForCreate(4)

        assertTrue(viewModel.state.value.isConfirming)
        assertEquals(0, viewModel.state.value.enteredDigits)
    }

    @Test
    fun `create pin flow - matching confirmation saves pin`() = runTest {
        // First entry
        viewModel.onDigitEnteredForCreate(1)
        viewModel.onDigitEnteredForCreate(2)
        viewModel.onDigitEnteredForCreate(3)
        viewModel.onDigitEnteredForCreate(4)

        // Confirmation
        viewModel.onDigitEnteredForCreate(1)
        viewModel.onDigitEnteredForCreate(2)
        viewModel.onDigitEnteredForCreate(3)
        viewModel.onDigitEnteredForCreate(4)

        assertTrue(viewModel.state.value.isCorrect)
        coVerify { settingsRepository.saveAdminSettings(any()) }
    }

    @Test
    fun `create pin flow - mismatched confirmation resets`() = runTest {
        // First entry
        viewModel.onDigitEnteredForCreate(1)
        viewModel.onDigitEnteredForCreate(2)
        viewModel.onDigitEnteredForCreate(3)
        viewModel.onDigitEnteredForCreate(4)

        // Different confirmation
        viewModel.onDigitEnteredForCreate(5)
        viewModel.onDigitEnteredForCreate(6)
        viewModel.onDigitEnteredForCreate(7)
        viewModel.onDigitEnteredForCreate(8)

        // Should reset to non-confirming state
        assertFalse(viewModel.state.value.isConfirming)
        assertEquals(0, viewModel.state.value.enteredDigits)
    }
}
