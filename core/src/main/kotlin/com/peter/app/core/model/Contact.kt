package com.peter.app.core.model

data class Contact(
    val id: Long = 0,
    val displayName: String,
    val phoneNumber: String,
    val photoUri: String? = null,
    val sortOrder: Int = 0,
)
