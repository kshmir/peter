package com.peter.app.core.util

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PackageGroupResolverTest {

    @Test
    fun `directly whitelisted package is allowed`() {
        val whitelist = setOf("com.android.chrome")
        assertTrue(PackageGroupResolver.isAllowed("com.android.chrome", whitelist))
    }

    @Test
    fun `google search is allowed when chrome is whitelisted`() {
        val whitelist = setOf("com.android.chrome")
        assertTrue(PackageGroupResolver.isAllowed("com.google.android.googlequicksearchbox", whitelist))
    }

    @Test
    fun `chrome is allowed when google search is whitelisted`() {
        val whitelist = setOf("com.google.android.googlequicksearchbox")
        assertTrue(PackageGroupResolver.isAllowed("com.android.chrome", whitelist))
    }

    @Test
    fun `whatsapp business is allowed when whatsapp is whitelisted`() {
        val whitelist = setOf("com.whatsapp")
        assertTrue(PackageGroupResolver.isAllowed("com.whatsapp.w4b", whitelist))
    }

    @Test
    fun `unknown package not in any group is not allowed`() {
        val whitelist = setOf("com.android.chrome")
        assertFalse(PackageGroupResolver.isAllowed("com.random.malware", whitelist))
    }

    @Test
    fun `package in group but no group member is whitelisted is not allowed`() {
        val whitelist = setOf("com.some.other.app")
        assertFalse(PackageGroupResolver.isAllowed("com.android.chrome", whitelist))
    }

    @Test
    fun `samsung dialer allowed when google dialer is whitelisted`() {
        val whitelist = setOf("com.google.android.dialer")
        assertTrue(PackageGroupResolver.isAllowed("com.samsung.android.dialer", whitelist))
    }

    @Test
    fun `expandWhitelist includes all group members`() {
        val whitelist = setOf("com.android.chrome", "com.whatsapp")
        val expanded = PackageGroupResolver.expandWhitelist(whitelist)

        assertTrue("com.google.android.googlequicksearchbox" in expanded)
        assertTrue("com.whatsapp.w4b" in expanded)
        assertTrue("com.android.chrome" in expanded)
        assertTrue("com.whatsapp" in expanded)
    }

    @Test
    fun `expandWhitelist preserves non-grouped packages`() {
        val whitelist = setOf("com.random.app")
        val expanded = PackageGroupResolver.expandWhitelist(whitelist)

        assertTrue("com.random.app" in expanded)
        // Should not include unrelated groups
        assertFalse("com.android.chrome" in expanded)
    }

    @Test
    fun `empty whitelist allows nothing`() {
        assertFalse(PackageGroupResolver.isAllowed("com.android.chrome", emptySet()))
    }

    @Test
    fun `photos allowed when camera is whitelisted`() {
        val whitelist = setOf("com.google.android.GoogleCamera")
        assertTrue(PackageGroupResolver.isAllowed("com.google.android.apps.photos", whitelist))
    }
}
