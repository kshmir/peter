package com.peter.app.core.repository

import com.peter.app.core.model.Contact
import kotlinx.coroutines.flow.Flow

interface ContactRepository {
    fun getAll(): Flow<List<Contact>>
    suspend fun getById(id: Long): Contact?
    suspend fun add(contact: Contact): Long
    suspend fun update(contact: Contact)
    suspend fun delete(id: Long)
}
