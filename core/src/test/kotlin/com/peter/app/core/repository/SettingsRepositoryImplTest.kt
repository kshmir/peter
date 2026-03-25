package com.peter.app.core.repository

import com.peter.app.core.database.dao.AdminSettingsDao
import com.peter.app.core.database.entity.AdminSettingsEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SettingsRepositoryImplTest {

    private val dao = mockk<AdminSettingsDao>(relaxed = true)
    private val repo = SettingsRepositoryImpl(dao)

    private val testSettings = AdminSettingsEntity(
        pinHash = "abc123",
        isMonitoringEnabled = true,
        maxAppsPerRow = 3,
    )

    @Test
    fun `getAdminSettings returns flow from dao`() = runTest {
        every { dao.get() } returns flowOf(testSettings)

        val settings = repo.getAdminSettings().first()

        assertEquals("abc123", settings?.pinHash)
        assertTrue(settings!!.isMonitoringEnabled)
    }

    @Test
    fun `getAdminSettings returns null when no settings`() = runTest {
        every { dao.get() } returns flowOf(null)

        val settings = repo.getAdminSettings().first()

        assertEquals(null, settings)
    }

    @Test
    fun `saveAdminSettings calls upsert`() = runTest {
        repo.saveAdminSettings(testSettings)

        coVerify { dao.upsert(testSettings) }
    }

    @Test
    fun `updatePin delegates to dao`() = runTest {
        repo.updatePin("newhash")

        coVerify { dao.updatePin(eq("newhash"), any()) }
    }

    @Test
    fun `updateMonitoring delegates to dao`() = runTest {
        repo.updateMonitoring(false)

        coVerify { dao.updateMonitoring(eq(false), any()) }
    }

    @Test
    fun `updateMaxAppsPerRow delegates to dao`() = runTest {
        repo.updateMaxAppsPerRow(4)

        coVerify { dao.updateMaxAppsPerRow(eq(4), any()) }
    }

    @Test
    fun `verifyPin returns true for matching hash`() = runTest {
        coEvery { dao.getSync() } returns testSettings

        val result = repo.verifyPin("abc123")

        assertTrue(result)
    }

    @Test
    fun `verifyPin returns false for wrong hash`() = runTest {
        coEvery { dao.getSync() } returns testSettings

        val result = repo.verifyPin("wrong")

        assertFalse(result)
    }

    @Test
    fun `verifyPin returns false when no settings exist`() = runTest {
        coEvery { dao.getSync() } returns null

        val result = repo.verifyPin("anything")

        assertFalse(result)
    }
}
