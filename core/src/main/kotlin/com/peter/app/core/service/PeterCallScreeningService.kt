package com.peter.app.core.service

import android.content.Intent
import android.database.Cursor
import android.provider.ContactsContract
import android.telecom.Call
import android.telecom.CallScreeningService
import android.util.Log
import com.peter.app.core.database.PeterDatabase
import com.peter.app.core.database.entity.GuardLogEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class PeterCallScreeningService : CallScreeningService() {

    companion object {
        private const val TAG = "CallScreener"
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onScreenCall(callDetails: Call.Details) {
        val number = callDetails.handle?.schemeSpecificPart ?: "unknown"
        val direction = callDetails.callDirection

        Log.w(TAG, "Incoming call from: $number (direction=$direction)")

        // Only screen incoming calls
        if (direction != Call.Details.DIRECTION_INCOMING) {
            respondAllow(callDetails)
            return
        }

        // Check settings
        val db = PeterDatabase.getInstance(this)
        val settings = runBlocking(Dispatchers.IO) { db.adminSettingsDao().getSync() }
        if (settings?.isCallScreeningEnabled != true) {
            Log.w(TAG, "Call screening disabled — allowing")
            respondAllow(callDetails)
            return
        }

        // Check if number is in device contacts
        val contactName = lookupContact(number)
        Log.w(TAG, "Contact lookup: $number → ${contactName ?: "NOT FOUND"}")

        // Check if number is in Peter's approved contacts
        val inPeter = runBlocking(Dispatchers.IO) {
            val contacts = db.contactDao().getAllSync()
            val digits = number.filter { it.isDigit() }
            contacts.any { c ->
                val cDigits = c.phoneNumber.filter { it.isDigit() }
                cDigits.endsWith(digits) || digits.endsWith(cDigits)
            }
        }

        Log.w(TAG, "In Peter contacts: $inPeter, In device contacts: ${contactName != null}")

        when {
            inPeter -> {
                // Approved contact — allow
                Log.w(TAG, "APPROVED contact — allowing call")
                respondAllow(callDetails)
            }
            contactName != null -> {
                // In device contacts but not Peter — allow with log
                Log.w(TAG, "Device contact ($contactName) — allowing call")
                logCall(db, number, contactName, "CALL_ALLOWED", "In device contacts")
                respondAllow(callDetails)
            }
            else -> {
                // Unknown number — silence and log
                Log.w(TAG, "UNKNOWN number — silencing call")
                logCall(db, number, null, "CALL_SCREENED", "Unknown number silenced")

                // Launch intercept screen
                InterceptData.pendingProfilePic = null
                val intent = Intent("com.peter.app.ACTION_INTERCEPT_NOTIFICATION").apply {
                    setPackage(packageName)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    putExtra("sender", number)
                    putExtra("message", "Llamada entrante de número desconocido")
                    putExtra("phone", number)
                    putExtra("threat_level", 0)
                    putExtra("threat_label", "Llamada desconocida")
                    putExtra("threat_desc", "Este número no está en tus contactos.")
                    putExtra("status", "CALL_SCREENED")
                }
                startActivity(intent)

                // Silence the call (don't reject — let it ring silently)
                respondToCall(
                    callDetails,
                    CallResponse.Builder()
                        .setDisallowCall(false)
                        .setSilenceCall(true)
                        .setSkipNotification(false)
                        .build()
                )
            }
        }
    }

    private fun respondAllow(callDetails: Call.Details) {
        respondToCall(
            callDetails,
            CallResponse.Builder()
                .setDisallowCall(false)
                .setSilenceCall(false)
                .build()
        )
    }

    private fun lookupContact(phone: String): String? {
        try {
            val uri = android.net.Uri.withAppendedPath(
                ContactsContract.PhoneLookup.CONTENT_FILTER_URI,
                android.net.Uri.encode(phone),
            )
            val cursor: Cursor? = contentResolver.query(
                uri,
                arrayOf(ContactsContract.PhoneLookup.DISPLAY_NAME),
                null, null, null,
            )
            cursor?.use {
                if (it.moveToFirst()) return it.getString(0)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error looking up $phone", e)
        }
        return null
    }

    private fun logCall(db: PeterDatabase, number: String, name: String?, event: String, detail: String) {
        scope.launch {
            try {
                db.guardLogDao().insert(
                    GuardLogEntity(
                        eventType = event,
                        packageName = "phone",
                        detail = "Number: $number | Name: ${name ?: "Unknown"} | $detail",
                    )
                )
            } catch (_: Exception) {}
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
