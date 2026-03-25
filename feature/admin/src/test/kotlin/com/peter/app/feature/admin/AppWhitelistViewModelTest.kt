package com.peter.app.feature.admin

import com.peter.app.core.model.InstalledApp
import com.peter.app.core.repository.AppRepository
import app.cash.turbine.test
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
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AppWhitelistViewModelTest {

    private val testDispatcher = UnconfinedTestDispatcher()
    private val appRepository = mockk<AppRepository>(relaxed = true)
    private lateinit var viewModel: AppWhitelistViewModel

    @Before
    fun setup() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `installedApps state starts empty`() = runTest {
        every { appRepository.getAllInstalledApps() } returns flowOf(emptyList())

        viewModel = AppWhitelistViewModel(appRepository)

        assertEquals(emptyList<InstalledApp>(), viewModel.installedApps.value)
    }

    @Test
    fun `installedApps emits from repository`() = runTest {
        val apps = listOf(
            InstalledApp("com.test.a", "App A", null, true),
            InstalledApp("com.test.b", "App B", null, false),
        )
        every { appRepository.getAllInstalledApps() } returns flowOf(apps)

        viewModel = AppWhitelistViewModel(appRepository)

        viewModel.installedApps.test {
            val emitted = awaitItem()
            assertEquals(2, emitted.size)
            assertEquals("App A", emitted[0].displayName)
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun `toggleWhitelist enabled adds to whitelist`() = runTest {
        every { appRepository.getAllInstalledApps() } returns flowOf(emptyList())
        viewModel = AppWhitelistViewModel(appRepository)

        viewModel.toggleWhitelist("com.test", "Test", true)

        coVerify { appRepository.addToWhitelist("com.test", "Test") }
    }

    @Test
    fun `toggleWhitelist disabled removes from whitelist`() = runTest {
        every { appRepository.getAllInstalledApps() } returns flowOf(emptyList())
        viewModel = AppWhitelistViewModel(appRepository)

        viewModel.toggleWhitelist("com.test", "Test", false)

        coVerify { appRepository.removeFromWhitelist("com.test") }
    }
}
