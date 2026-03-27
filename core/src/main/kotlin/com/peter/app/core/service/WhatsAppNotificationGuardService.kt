package com.peter.app.core.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.os.Bundle
import android.provider.ContactsContract
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import androidx.core.app.NotificationCompat
import com.peter.app.core.database.PeterDatabase
import com.peter.app.core.database.entity.GuardLogEntity
import com.peter.app.core.util.ScamPatternDetector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class WhatsAppNotificationGuardService : NotificationListenerService() {

    companion object {
        private const val TAG = "NotifGuard"
        private const val WHATSAPP_PKG = "com.whatsapp"
        private const val WHATSAPP_BIZ_PKG = "com.whatsapp.w4b"
        private const val GUARD_CHANNEL_ID = "peter_notif_guard"

        // Regex to detect phone numbers (international format)
        private val PHONE_REGEX = Regex("""^\+?\d[\d\s\-()]{6,}$""")
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onCreate() {
        super.onCreate()
        createChannel()
        Log.w(TAG, "WhatsApp notification guard started")
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName != WHATSAPP_PKG && sbn.packageName != WHATSAPP_BIZ_PKG) return

        // Check if notification filter is enabled
        try {
            val settings = PeterDatabase.getInstance(this).adminSettingsDao().let {
                kotlinx.coroutines.runBlocking(kotlinx.coroutines.Dispatchers.IO) { it.getSync() }
            }
            if (settings?.isNotificationFilterEnabled != true) return
        } catch (_: Exception) {}

        val extras = sbn.notification.extras ?: return

        // Skip non-message notifications (calls, summaries, system)
        val category = sbn.notification.category
        if (category == android.app.Notification.CATEGORY_CALL ||
            category == android.app.Notification.CATEGORY_SERVICE ||
            category == android.app.Notification.CATEGORY_PROGRESS ||
            category == android.app.Notification.CATEGORY_TRANSPORT ||
            category == android.app.Notification.CATEGORY_SYSTEM) {
            return
        }

        // Skip ongoing/foreground notifications (voice calls, video calls)
        if (sbn.isOngoing) return

        // Skip summary notifications ("WhatsApp - X messages from Y chats")
        if (sbn.notification.group != null && sbn.key.contains("|null|")) return

        // Skip notifications without message content
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        if (title.isBlank() || title == "WhatsApp") return

        // Skip group chats
        val isGroup = extras.getBoolean(Notification.EXTRA_IS_GROUP_CONVERSATION, false)
        val conversationTitle = extras.getCharSequence(Notification.EXTRA_CONVERSATION_TITLE)?.toString() ?: ""
        if (isGroup || conversationTitle.isNotBlank()) {
            Log.w(TAG, "Skipping group chat: $title / $conversationTitle")
            return
        }

        // Only alert for phone numbers (unknown contacts), not named contacts
        val isPhoneNumber = PHONE_REGEX.matches(title.trim())
        if (!isPhoneNumber) {
            Log.w(TAG, "Skipping named contact (not a phone number): $title")
            return
        }

        val textPreview = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""

        // Detect incoming WhatsApp CALLS — handle separately
        val incomingCallKeywords = listOf(
            "incoming voice call", "incoming video call",
            "llamada de voz entrante", "videollamada entrante",
            "chamada de voz recebida", "videochamada recebida",
            "ringing",
        )
        val isIncomingCall = incomingCallKeywords.any {
            textPreview.contains(it, ignoreCase = true) || title.contains(it, ignoreCase = true)
        }
        if (isIncomingCall) {
            Log.w(TAG, "WhatsApp INCOMING CALL from: $title | text: $textPreview")
            handleWhatsAppCall(title, textPreview)
            return
        }

        // Skip other non-message call notifications (ongoing, missed)
        val skipKeywords = listOf(
            "ongoing voice call", "llamada de voz en curso", "chamada de voz em andamento",
            "ongoing video call", "videollamada en curso", "videochamada em andamento",
            "calling", "llamando", "ligando",
            "missed call", "llamada perdida", "chamada perdida",
        )
        if (skipKeywords.any { textPreview.contains(it, ignoreCase = true) || title.contains(it, ignoreCase = true) }) {
            return
        }

        // ── Dump ALL notification data for analysis ──
        // title and textPreview already extracted above
        val text = textPreview
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""
        val subText = extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString() ?: ""
        val infoText = extras.getCharSequence(Notification.EXTRA_INFO_TEXT)?.toString() ?: ""
        val summaryText = extras.getString(Notification.EXTRA_SUMMARY_TEXT) ?: ""
        // conversationTitle and isGroup already checked above

        // Extract MessagingStyle messages if available
        val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
        val messageCount = messages?.size ?: 0

        // Check for person/sender info
        val people = extras.getStringArray(Notification.EXTRA_PEOPLE_LIST)
            ?: extras.getStringArray("android.people")

        Log.w(TAG, "═══════════════════════════════════════")
        Log.w(TAG, "WhatsApp Notification Dump:")
        Log.w(TAG, "  title: '$title'")
        Log.w(TAG, "  text: '$text'")
        Log.w(TAG, "  bigText: '$bigText'")
        Log.w(TAG, "  subText: '$subText'")
        Log.w(TAG, "  infoText: '$infoText'")
        Log.w(TAG, "  summaryText: '$summaryText'")
        Log.w(TAG, "  conversationTitle: '$conversationTitle'")
        Log.w(TAG, "  isGroup: $isGroup")
        Log.w(TAG, "  messageCount: $messageCount")
        Log.w(TAG, "  people: ${people?.toList()}")
        Log.w(TAG, "  category: ${sbn.notification.category}")
        Log.w(TAG, "  group: ${sbn.notification.group}")
        Log.w(TAG, "  key: ${sbn.key}")

        // Profile picture
        val largeIcon = sbn.notification.getLargeIcon()
        val extraLargeIcon = extras.get(Notification.EXTRA_LARGE_ICON)
        val extraPicture = extras.get(Notification.EXTRA_PICTURE)
        Log.w(TAG, "  largeIcon: $largeIcon")
        Log.w(TAG, "  extraLargeIcon: $extraLargeIcon (${extraLargeIcon?.javaClass?.simpleName})")
        Log.w(TAG, "  extraPicture: $extraPicture (${extraPicture?.javaClass?.simpleName})")

        // Dump ALL extras keys AND values for discovery
        val allKeys = extras.keySet()
        Log.w(TAG, "  ALL extras keys: $allKeys")
        for (key in allKeys) {
            val value = extras.get(key)
            if (value !is android.graphics.Bitmap && value !is android.app.Notification &&
                value !is Array<*> && value !is android.os.Parcelable) {
                Log.w(TAG, "  EXTRA[$key] = $value (${value?.javaClass?.simpleName})")
            }
        }
        // Specifically check hiddenConversationTitle
        val hiddenTitle = extras.getCharSequence("android.hiddenConversationTitle")
        Log.w(TAG, "  hiddenConversationTitle: '$hiddenTitle'")

        // Try to extract MessagingStyle data
        if (messages != null) {
            for ((i, msg) in messages.withIndex()) {
                if (msg is Bundle) {
                    val msgSender = msg.getCharSequence("sender")?.toString() ?: "unknown"
                    val msgText = msg.getCharSequence("text")?.toString() ?: ""
                    val msgTime = msg.getLong("time", 0)
                    Log.w(TAG, "  message[$i]: sender='$msgSender' text='$msgText' time=$msgTime")
                    Log.w(TAG, "  message[$i] keys: ${msg.keySet()}")

                    // Deep dive into sender_person
                    val senderPerson = msg.get("sender_person")
                    Log.w(TAG, "  message[$i] sender_person: $senderPerson (${senderPerson?.javaClass?.simpleName})")
                    if (senderPerson is android.app.Person) {
                        Log.w(TAG, "  message[$i] person.name: ${senderPerson.name}")
                        Log.w(TAG, "  message[$i] person.key: ${senderPerson.key}")
                        Log.w(TAG, "  message[$i] person.uri: ${senderPerson.uri}")
                        Log.w(TAG, "  message[$i] person.icon: ${senderPerson.icon}")
                    }

                    // Deep dive into extras within message
                    val msgExtras = msg.getBundle("extras")
                    if (msgExtras != null) {
                        Log.w(TAG, "  message[$i] extras keys: ${msgExtras.keySet()}")
                        for (key in msgExtras.keySet()) {
                            Log.w(TAG, "  message[$i] extras.$key = ${msgExtras.get(key)}")
                        }
                    }
                }
            }
        }

        // Also check messagingUser (the device owner)
        val messagingUser = extras.get("android.messagingUser")
        Log.w(TAG, "  messagingUser: $messagingUser (${messagingUser?.javaClass?.simpleName})")
        if (messagingUser is android.app.Person) {
            Log.w(TAG, "  messagingUser.name: ${messagingUser.name}")
            Log.w(TAG, "  messagingUser.key: ${messagingUser.key}")
            Log.w(TAG, "  messagingUser.uri: ${messagingUser.uri}")
        }

        // Check the notification key for phone info
        val wearableExtras = extras.getBundle("android.wearable.EXTENSIONS")
        if (wearableExtras != null) {
            Log.w(TAG, "  wearable keys: ${wearableExtras.keySet()}")
        }
        Log.w(TAG, "═══════════════════════════════════════")

        // ── Contact cross-reference ──
        val senderIsPhoneNumber = PHONE_REGEX.matches(title.trim())
        val contactLookup = lookupContact(title)

        Log.w(TAG, "── CONTACT ANALYSIS ──")
        Log.w(TAG, "  sender: '$title'")
        Log.w(TAG, "  isPhoneNumber: $senderIsPhoneNumber")
        Log.w(TAG, "  inDeviceContacts: ${contactLookup.inDeviceContacts}")
        Log.w(TAG, "  phoneFromContacts: ${contactLookup.phoneNumber}")
        Log.w(TAG, "  inPeterContacts: ${contactLookup.inPeterContacts}")
        Log.w(TAG, "  hasOutgoingCallHistory: ${contactLookup.hasOutgoingCallHistory}")
        Log.w(TAG, "  contactStatus: ${contactLookup.status}")
        Log.w(TAG, "──────────────────────")

        // If user has previously called this number, trust it more — don't intercept
        if (contactLookup.hasOutgoingCallHistory) {
            Log.w(TAG, "Has outgoing call history — trusting $title")
            return
        }

        // ── Scam detection ──
        val messageContent = bigText.ifBlank { text }
        if (messageContent.isBlank()) return

        val analysis = ScamPatternDetector.analyze(messageContent)

        // Determine threat level and whether to intercept
        val shouldIntercept: Boolean
        val threatLevel: Int
        val threatLabel: String
        val threatDesc: String

        when {
            analysis.isSuspicious -> {
                shouldIntercept = true
                threatLevel = 2 // HIGH_ALERT
                threatLabel = "Alerta de estafa"
                threatDesc = "Mensaje contiene patrones de estafa: \"${analysis.matchedPattern}\""
            }
            contactLookup.status == "UNKNOWN" -> {
                shouldIntercept = true
                threatLevel = 0 // UNKNOWN
                threatLabel = "Contacto desconocido"
                threatDesc = "Este número no está en tus contactos."
            }
            contactLookup.status == "NAME_NOT_IN_CONTACTS" -> {
                shouldIntercept = true
                threatLevel = 0
                threatLabel = "Contacto desconocido"
                threatDesc = "Este nombre no coincide con ningún contacto."
            }
            contactLookup.status == "IN_PHONE_CONTACTS" && !contactLookup.inPeterContacts -> {
                shouldIntercept = false // In phone contacts, let through but log
                threatLevel = -1
                threatLabel = ""
                threatDesc = ""
            }
            contactLookup.status == "APPROVED" -> {
                shouldIntercept = false
                threatLevel = -1
                threatLabel = ""
                threatDesc = ""
            }
            else -> {
                shouldIntercept = false
                threatLevel = -1
                threatLabel = ""
                threatDesc = ""
            }
        }

        // Log to guard log
        scope.launch {
            try {
                val db = PeterDatabase.getInstance(this@WhatsAppNotificationGuardService)
                db.guardLogDao().insert(
                    GuardLogEntity(
                        eventType = when {
                            analysis.isSuspicious -> "NOTIFICATION_BLOCKED"
                            contactLookup.status == "UNKNOWN" -> "UNKNOWN_SENDER"
                            contactLookup.status == "NAME_NOT_IN_CONTACTS" -> "UNVERIFIED_SENDER"
                            !contactLookup.inPeterContacts -> "NON_PETER_CONTACT"
                            else -> "WHATSAPP_MSG"
                        },
                        packageName = sbn.packageName,
                        detail = "From: $title | Phone: ${contactLookup.phoneNumber ?: "unknown"} | Status: ${contactLookup.status} | Msg: ${messageContent.take(80)}",
                    )
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error logging", e)
            }
        }

        // Intercept: cancel notification and show security screen
        if (shouldIntercept) {
            Log.w(TAG, "INTERCEPTING: $title (threat=$threatLevel, status=${contactLookup.status})")
            cancelNotification(sbn.key)

            // Extract profile picture bitmap
            var profileBitmap: android.graphics.Bitmap? = null
            try {
                val icon = sbn.notification.getLargeIcon()
                if (icon != null) {
                    val drawable = icon.loadDrawable(this)
                    if (drawable != null) {
                        profileBitmap = android.graphics.Bitmap.createBitmap(
                            drawable.intrinsicWidth, drawable.intrinsicHeight,
                            android.graphics.Bitmap.Config.ARGB_8888
                        )
                        val canvas = android.graphics.Canvas(profileBitmap)
                        drawable.setBounds(0, 0, canvas.width, canvas.height)
                        drawable.draw(canvas)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error extracting profile pic", e)
            }

            // Launch intercept activity via action intent (core can't reference :app directly)
            InterceptData.pendingProfilePic = profileBitmap
            val intent = Intent("com.peter.app.ACTION_INTERCEPT_NOTIFICATION").apply {
                setPackage(packageName)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                putExtra("sender", title)
                putExtra("message", messageContent)
                putExtra("phone", contactLookup.phoneNumber)
                putExtra("threat_level", threatLevel)
                putExtra("threat_label", threatLabel)
                putExtra("threat_desc", threatDesc)
                putExtra("status", contactLookup.status)
            }
            startActivity(intent)
        }
    }

    private fun postWarning(sender: String, matchedPattern: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notification = NotificationCompat.Builder(this, GUARD_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Mensaje sospechoso bloqueado")
            .setContentText("Se ocultó un mensaje de \"$sender\"")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(
                        "Se ocultó un mensaje de \"$sender\" porque parecía sospechoso " +
                        "(detectado: $matchedPattern).\n\n" +
                        "Si fue un error, pida a un familiar que lo revise."
                    )
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        nm.notify(System.currentTimeMillis().toInt(), notification)
    }

    private fun createChannel() {
        val channel = NotificationChannel(
            GUARD_CHANNEL_ID,
            "Protección de notificaciones",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Alertas cuando se bloquean mensajes sospechosos de WhatsApp"
        }
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(channel)
    }

    // ── WhatsApp call handling ──

    private fun handleWhatsAppCall(caller: String, callText: String) {
        try {
            val settings = PeterDatabase.getInstance(this).adminSettingsDao().let {
                kotlinx.coroutines.runBlocking(kotlinx.coroutines.Dispatchers.IO) { it.getSync() }
            }
            if (settings?.isCallScreeningEnabled != true) {
                Log.w(TAG, "Call screening disabled — allowing WhatsApp call")
                return
            }
        } catch (_: Exception) {}

        val contactLookup = lookupContact(caller)
        Log.w(TAG, "WhatsApp call: $caller | inDevice=${contactLookup.inDeviceContacts} | inPeter=${contactLookup.inPeterContacts}")

        if (contactLookup.inPeterContacts || contactLookup.inDeviceContacts) {
            Log.w(TAG, "Known contact calling — allowing")
            return
        }

        Log.w(TAG, "UNKNOWN WhatsApp caller: $caller — showing warning")

        InterceptData.pendingProfilePic = null
        val isVideo = callText.contains("video", ignoreCase = true)
        val intent = Intent("com.peter.app.ACTION_INTERCEPT_NOTIFICATION").apply {
            setPackage(packageName)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_MULTIPLE_TASK)
            putExtra("sender", caller)
            putExtra("message", if (isVideo) "Videollamada entrante de número desconocido" else "Llamada de voz entrante de número desconocido")
            putExtra("phone", contactLookup.phoneNumber ?: caller)
            putExtra("threat_level", 1)
            putExtra("threat_label", if (isVideo) "Videollamada desconocida" else "Llamada desconocida")
            putExtra("threat_desc", "Este número no está en tus contactos. Podría ser una estafa telefónica.")
            putExtra("status", "WA_CALL_UNKNOWN")
        }
        startActivity(intent)

        scope.launch {
            try {
                PeterDatabase.getInstance(this@WhatsAppNotificationGuardService)
                    .guardLogDao().insert(
                        com.peter.app.core.database.entity.GuardLogEntity(
                            eventType = "WA_CALL_SCREENED",
                            packageName = "com.whatsapp",
                            detail = "From: $caller | ${if (isVideo) "Video" else "Voice"} | Unknown",
                        )
                    )
            } catch (_: Exception) {}
        }
    }

    // ── Contact cross-reference ──

    data class ContactResult(
        val inDeviceContacts: Boolean,
        val phoneNumber: String?,
        val contactName: String?,
        val inPeterContacts: Boolean,
        val hasOutgoingCallHistory: Boolean,
        val status: String,
    )

    private fun lookupContact(senderTitle: String): ContactResult {
        val isPhoneNumber = PHONE_REGEX.matches(senderTitle.trim())

        return if (isPhoneNumber) {
            // Sender IS a phone number — look up by phone in device contacts
            val contactName = lookupNameByPhone(senderTitle.trim())
            val inPeter = checkPeterContacts(senderTitle.trim(), null)
            val hasOutgoing = hasOutgoingCallTo(senderTitle.trim())
            if (hasOutgoing) Log.w(TAG, "Has outgoing call history to: ${senderTitle.trim()}")
            ContactResult(
                inDeviceContacts = contactName != null,
                phoneNumber = senderTitle.trim(),
                contactName = contactName,
                inPeterContacts = inPeter,
                hasOutgoingCallHistory = hasOutgoing,
                status = when {
                    inPeter -> "APPROVED"
                    contactName != null -> "IN_PHONE_CONTACTS"
                    hasOutgoing -> "HAS_CALL_HISTORY"
                    else -> "UNKNOWN"
                },
            )
        } else {
            // Sender is a name — try exact match first, then fuzzy
            var phone = lookupPhoneByName(senderTitle.trim())
            var matchedName = senderTitle.trim()

            // If exact name match fails, try partial/fuzzy match
            if (phone == null) {
                val fuzzy = fuzzyLookupByName(senderTitle.trim())
                if (fuzzy != null) {
                    phone = fuzzy.first
                    matchedName = fuzzy.second
                    Log.w(TAG, "  Fuzzy match: '$senderTitle' → '$matchedName' (${phone})")
                }
            }

            val inPeter = checkPeterContacts(phone, senderTitle.trim())
            val hasOutgoing = if (phone != null) hasOutgoingCallTo(phone) else false
            ContactResult(
                inDeviceContacts = phone != null,
                phoneNumber = phone,
                contactName = matchedName,
                inPeterContacts = inPeter,
                hasOutgoingCallHistory = hasOutgoing,
                status = when {
                    inPeter -> "APPROVED"
                    phone != null -> "IN_PHONE_CONTACTS"
                    hasOutgoing -> "HAS_CALL_HISTORY"
                    else -> "NAME_NOT_IN_CONTACTS"
                },
            )
        }
    }

    /** Check if user has made an outgoing call to this number */
    private fun hasOutgoingCallTo(phone: String): Boolean {
        try {
            val digits = phone.filter { it.isDigit() }
            if (digits.length < 7) return false

            val cursor = contentResolver.query(
                android.provider.CallLog.Calls.CONTENT_URI,
                arrayOf(android.provider.CallLog.Calls.NUMBER),
                "${android.provider.CallLog.Calls.TYPE} = ? AND ${android.provider.CallLog.Calls.NUMBER} LIKE ?",
                arrayOf(
                    android.provider.CallLog.Calls.OUTGOING_TYPE.toString(),
                    "%${digits.takeLast(7)}%"
                ),
                null,
            )
            cursor?.use {
                val found = it.count > 0
                if (found) Log.w(TAG, "Found ${it.count} outgoing calls to $phone")
                return found
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error checking call log for $phone", e)
        }
        return false
    }

    private fun lookupNameByPhone(phone: String): String? {
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
                if (it.moveToFirst()) {
                    return it.getString(0)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error looking up phone: $phone", e)
        }
        return null
    }

    /** Fuzzy match: search contacts where name contains parts of the WhatsApp name */
    private fun fuzzyLookupByName(waName: String): Pair<String, String>? {
        try {
            val nameParts = waName.lowercase().split(" ").filter { it.length >= 3 }
            if (nameParts.isEmpty()) return null

            val cursor: Cursor? = contentResolver.query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                arrayOf(
                    ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                    ContactsContract.CommonDataKinds.Phone.NUMBER,
                ),
                null, null, null,
            )
            cursor?.use {
                while (it.moveToNext()) {
                    val contactName = it.getString(0)?.lowercase() ?: continue
                    val contactPhone = it.getString(1) ?: continue
                    // Match if any significant word from WhatsApp name appears in contact name
                    // or any word from contact name appears in WhatsApp name
                    val contactParts = contactName.split(" ").filter { p -> p.length >= 3 }
                    val hasOverlap = nameParts.any { part -> contactName.contains(part) } ||
                            contactParts.any { part -> waName.lowercase().contains(part) }
                    if (hasOverlap) {
                        return Pair(contactPhone, it.getString(0) ?: contactName)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in fuzzy lookup: $waName", e)
        }
        return null
    }

    private fun lookupPhoneByName(name: String): String? {
        try {
            val cursor: Cursor? = contentResolver.query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                arrayOf(ContactsContract.CommonDataKinds.Phone.NUMBER),
                "${ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME} = ?",
                arrayOf(name),
                null,
            )
            cursor?.use {
                if (it.moveToFirst()) {
                    return it.getString(0)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error looking up name: $name", e)
        }
        return null
    }

    private fun checkPeterContacts(phone: String?, name: String?): Boolean {
        try {
            val db = PeterDatabase.getInstance(this)
            val contacts = kotlinx.coroutines.runBlocking(kotlinx.coroutines.Dispatchers.IO) {
                db.contactDao().getAllSync()
            }
            val phoneDigits = phone?.filter { it.isDigit() }
            return contacts.any { c ->
                val cDigits = c.phoneNumber.filter { it.isDigit() }
                (phoneDigits != null && (cDigits.endsWith(phoneDigits) || phoneDigits.endsWith(cDigits))) ||
                (name != null && c.displayName.equals(name, ignoreCase = true))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error checking Peter contacts", e)
            return false
        }
    }
}
