package com.peter.app.core.repository

import com.peter.app.core.database.dao.ContactDao
import com.peter.app.core.database.entity.ContactEntity
import com.peter.app.core.model.Contact
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ContactRepositoryImpl @Inject constructor(
    private val contactDao: ContactDao,
) : ContactRepository {

    override fun getAll(): Flow<List<Contact>> {
        return contactDao.getAll().map { entities ->
            entities.map { it.toModel() }
        }
    }

    override suspend fun getById(id: Long): Contact? {
        return contactDao.getById(id)?.toModel()
    }

    override suspend fun add(contact: Contact): Long {
        return contactDao.insert(contact.toEntity())
    }

    override suspend fun update(contact: Contact) {
        contactDao.update(contact.toEntity())
    }

    override suspend fun delete(id: Long) {
        contactDao.deleteById(id)
    }

    private fun ContactEntity.toModel() = Contact(
        id = id,
        displayName = displayName,
        phoneNumber = phoneNumber,
        photoUri = photoUri,
        sortOrder = sortOrder,
    )

    private fun Contact.toEntity() = ContactEntity(
        id = id,
        displayName = displayName,
        phoneNumber = phoneNumber,
        photoUri = photoUri,
        sortOrder = sortOrder,
    )
}
