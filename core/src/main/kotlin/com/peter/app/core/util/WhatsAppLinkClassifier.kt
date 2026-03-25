package com.peter.app.core.util

import android.net.Uri

enum class LinkClassification {
    SAFE,
    GROUP_INVITE,
    UNKNOWN_CONTACT,
}

object WhatsAppLinkClassifier {

    fun classify(uri: Uri, knownPhoneNumbers: Set<String>): LinkClassification {
        val host = uri.host?.lowercase() ?: ""
        val path = uri.path?.lowercase() ?: ""

        return when {
            // Group invite links
            host == "chat.whatsapp.com" -> LinkClassification.GROUP_INVITE

            // wa.me/<phone> links
            host == "wa.me" && path.length > 1 -> {
                val phone = path.trimStart('/').replace(Regex("[^0-9+]"), "")
                if (phone.isBlank()) return LinkClassification.SAFE
                if (isKnownPhone(phone, knownPhoneNumbers)) LinkClassification.SAFE
                else LinkClassification.UNKNOWN_CONTACT
            }

            // api.whatsapp.com/send?phone=<number>
            host == "api.whatsapp.com" -> {
                val phone = uri.getQueryParameter("phone") ?: ""
                if (phone.isBlank()) return LinkClassification.SAFE
                if (isKnownPhone(phone, knownPhoneNumbers)) LinkClassification.SAFE
                else LinkClassification.UNKNOWN_CONTACT
            }

            else -> LinkClassification.SAFE
        }
    }

    private fun isKnownPhone(phone: String, knownPhones: Set<String>): Boolean {
        val digits = phone.filter { it.isDigit() }
        return knownPhones.any { known ->
            val knownDigits = known.filter { it.isDigit() }
            // Match if either contains the other (handles country code differences)
            digits.endsWith(knownDigits) || knownDigits.endsWith(digits)
        }
    }
}
