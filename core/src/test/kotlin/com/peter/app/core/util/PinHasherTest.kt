package com.peter.app.core.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PinHasherTest {

    @Test
    fun `hash returns consistent result for same input`() {
        val hash1 = PinHasher.hash("1234")
        val hash2 = PinHasher.hash("1234")
        assertEquals(hash1, hash2)
    }

    @Test
    fun `hash returns different result for different input`() {
        val hash1 = PinHasher.hash("1234")
        val hash2 = PinHasher.hash("5678")
        assertNotEquals(hash1, hash2)
    }

    @Test
    fun `hash returns 64 char hex string`() {
        val hash = PinHasher.hash("0000")
        assertEquals(64, hash.length)
        assertTrue(hash.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun `verify returns true for matching pin`() {
        val hash = PinHasher.hash("9999")
        assertTrue(PinHasher.verify("9999", hash))
    }

    @Test
    fun `verify returns false for wrong pin`() {
        val hash = PinHasher.hash("1234")
        assertFalse(PinHasher.verify("4321", hash))
    }

    @Test
    fun `hash handles empty string`() {
        val hash = PinHasher.hash("")
        assertEquals(64, hash.length)
        assertTrue(PinHasher.verify("", hash))
    }
}
