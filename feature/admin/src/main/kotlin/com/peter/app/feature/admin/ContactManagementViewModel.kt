package com.peter.app.feature.admin

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.peter.app.core.model.Contact
import com.peter.app.core.repository.ContactRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ContactManagementViewModel @Inject constructor(
    private val contactRepository: ContactRepository,
) : ViewModel() {

    val contacts: StateFlow<List<Contact>> =
        contactRepository.getAll()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun addContact(name: String, phone: String) {
        viewModelScope.launch {
            contactRepository.add(
                Contact(
                    displayName = name,
                    phoneNumber = phone,
                    sortOrder = contacts.value.size,
                )
            )
        }
    }

    fun deleteContact(id: Long) {
        viewModelScope.launch {
            contactRepository.delete(id)
        }
    }
}
