package com.peter.app.core.repository

import com.peter.app.core.database.dao.ContactDao
import com.peter.app.core.database.entity.ContactEntity
import com.peter.app.core.model.Contact
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ContactRepositoryImplTest {

    private val contactDao = mockk<ContactDao>(relaxed = true)
    private val repo = ContactRepositoryImpl(contactDao)

    @Test
    fun `getAll maps entities to models`() = runTest {
        every { contactDao.getAll() } returns flowOf(
            listOf(
                ContactEntity(id = 1, displayName = "Alice", phoneNumber = "+1234", sortOrder = 0),
                ContactEntity(id = 2, displayName = "Bob", phoneNumber = "+5678", sortOrder = 1),
            )
        )

        val contacts = repo.getAll().first()

        assertEquals(2, contacts.size)
        assertEquals("Alice", contacts[0].displayName)
        assertEquals("+5678", contacts[1].phoneNumber)
    }

    @Test
    fun `getAll returns empty list when no contacts`() = runTest {
        every { contactDao.getAll() } returns flowOf(emptyList())

        val contacts = repo.getAll().first()

        assertEquals(0, contacts.size)
    }

    @Test
    fun `getById returns mapped model`() = runTest {
        coEvery { contactDao.getById(1) } returns ContactEntity(
            id = 1, displayName = "Alice", phoneNumber = "+1234",
        )

        val contact = repo.getById(1)

        assertEquals("Alice", contact?.displayName)
        assertEquals(1L, contact?.id)
    }

    @Test
    fun `getById returns null when not found`() = runTest {
        coEvery { contactDao.getById(99) } returns null

        val contact = repo.getById(99)

        assertNull(contact)
    }

    @Test
    fun `add inserts entity and returns id`() = runTest {
        coEvery { contactDao.insert(any()) } returns 5L

        val id = repo.add(Contact(displayName = "Charlie", phoneNumber = "+9999"))

        assertEquals(5L, id)
        coVerify { contactDao.insert(match { it.displayName == "Charlie" }) }
    }

    @Test
    fun `delete calls deleteById on dao`() = runTest {
        repo.delete(3L)

        coVerify { contactDao.deleteById(3L) }
    }
}
