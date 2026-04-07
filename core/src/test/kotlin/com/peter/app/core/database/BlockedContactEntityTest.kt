package com.peter.app.core.database

import com.peter.app.core.database.entity.BlockedContactEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BlockedContactEntityTest {

    @Test
    fun `create entity with all fields`() {
        val entity = BlockedContactEntity(
            id = 1,
            phoneNumber = "+1234567890",
            displayName = "Spam Caller",
            reason = "Telemarketer",
            blockedAt = 1000L,
        )

        assertEquals(1L, entity.id)
        assertEquals("+1234567890", entity.phoneNumber)
        assertEquals("Spam Caller", entity.displayName)
        assertEquals("Telemarketer", entity.reason)
        assertEquals(1000L, entity.blockedAt)
    }

    @Test
    fun `create entity with defaults`() {
        val before = System.currentTimeMillis()
        val entity = BlockedContactEntity(phoneNumber = "+1234567890")
        val after = System.currentTimeMillis()

        assertEquals(0L, entity.id)
        assertEquals("+1234567890", entity.phoneNumber)
        assertEquals("", entity.displayName)
        assertEquals("", entity.reason)
        assertTrue(entity.blockedAt in before..after)
    }

    @Test
    fun `copy modifies specified fields only`() {
        val original = BlockedContactEntity(
            id = 1,
            phoneNumber = "+1234567890",
            displayName = "Original",
            reason = "Spam",
            blockedAt = 1000L,
        )
        val updated = original.copy(displayName = "Updated")

        assertEquals(original.id, updated.id)
        assertEquals(original.phoneNumber, updated.phoneNumber)
        assertEquals("Updated", updated.displayName)
        assertEquals(original.reason, updated.reason)
        assertEquals(original.blockedAt, updated.blockedAt)
    }

    @Test
    fun `equals and hashCode work correctly`() {
        val entity1 = BlockedContactEntity(
            id = 1,
            phoneNumber = "+1234567890",
            displayName = "Test",
            reason = "Spam",
            blockedAt = 1000L,
        )
        val entity2 = BlockedContactEntity(
            id = 1,
            phoneNumber = "+1234567890",
            displayName = "Test",
            reason = "Spam",
            blockedAt = 1000L,
        )
        val entity3 = BlockedContactEntity(
            id = 2,
            phoneNumber = "+0987654321",
            blockedAt = 2000L,
        )

        assertEquals(entity1, entity2)
        assertEquals(entity1.hashCode(), entity2.hashCode())
        assertNotEquals(entity1, entity3)
    }
}
