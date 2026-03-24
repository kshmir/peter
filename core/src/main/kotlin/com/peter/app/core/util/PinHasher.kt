package com.peter.app.core.util

import java.security.MessageDigest

object PinHasher {
    fun hash(pin: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(pin.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun verify(pin: String, hash: String): Boolean {
        return hash(pin) == hash
    }
}
