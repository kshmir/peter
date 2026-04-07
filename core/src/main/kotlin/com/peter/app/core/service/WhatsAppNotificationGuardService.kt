package com.peter.app.core.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.RemoteInput
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

        // Samsung + AOSP dialer/incall packages
        private val PHONE_PACKAGES = setOf(
            "com.samsung.android.dialer",
            "com.samsung.android.incallui",
            "com.sec.phone",
            "com.android.phone",
            "com.android.dialer",
            "com.android.server.telecom",
            "com.google.android.dialer",
        )

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
        val pkg = sbn.packageName
        val isWhatsApp = pkg == WHATSAPP_PKG || pkg == WHATSAPP_BIZ_PKG
        val isPhoneDialer = pkg in PHONE_PACKAGES

        // ── DEBUG: Log every notification from WhatsApp/dialer ──
        if (isWhatsApp || isPhoneDialer) {
            Log.w(TAG, "╔══ NOTIFICATION RECEIVED ══")
            Log.w(TAG, "║ pkg=$pkg")
            Log.w(TAG, "║ key=${sbn.key}")
            Log.w(TAG, "║ tag=${sbn.tag}")
            Log.w(TAG, "║ id=${sbn.id}")
            Log.w(TAG, "║ category=${sbn.notification.category}")
            Log.w(TAG, "║ ongoing=${sbn.isOngoing}")
            Log.w(TAG, "║ group=${sbn.notification.group}")
            val extras = sbn.notification.extras
            if (extras != null) {
                Log.w(TAG, "║ title=${extras.getCharSequence(Notification.EXTRA_TITLE)}")
                Log.w(TAG, "║ text=${extras.getCharSequence(Notification.EXTRA_TEXT)}")
                Log.w(TAG, "║ bigText=${extras.getCharSequence(Notification.EXTRA_BIG_TEXT)}")
                Log.w(TAG, "║ convTitle=${extras.getCharSequence(Notification.EXTRA_CONVERSATION_TITLE)}")
                Log.w(TAG, "║ isGroup=${extras.getBoolean(Notification.EXTRA_IS_GROUP_CONVERSATION, false)}")
            }
            Log.w(TAG, "║ actions=${sbn.notification.actions?.map { it.title }}")
            Log.w(TAG, "╚══════════════════════════")
        }

        // ── CALL INTERCEPTION (runs before anything else) ──
        // Catches: WhatsApp VoIP calls + Samsung dialer calls
        val category = sbn.notification.category
        val extras = sbn.notification.extras ?: return
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val textPreview = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""

        val isCallNotification = category == Notification.CATEGORY_CALL
        val callKeywords = listOf(
            "incoming voice call", "incoming video call",
            "llamada de voz entrante", "videollamada entrante",
            "chamada de voz recebida", "videochamada recebida",
            "ringing",
        )
        val hasCallKeyword = callKeywords.any {
            textPreview.contains(it, ignoreCase = true) || title.contains(it, ignoreCase = true)
        }

        // Skip missed/ended call notifications — only intercept active incoming calls
        val missedCallKeywords = listOf(
            "missed", "perdida", "perdidas", "perdido",
            "ended", "finalizada", "terminada",
        )
        val isMissedCall = missedCallKeywords.any { textPreview.contains(it, ignoreCase = true) }

        if ((isWhatsApp || isPhoneDialer) && (isCallNotification || hasCallKeyword) && !isMissedCall) {
            Log.w(TAG, "CALL detected: pkg=$pkg title='$title' text='$textPreview' category=$category ongoing=${sbn.isOngoing}")
            handleIncomingCall(sbn, title, textPreview)
            return
        }
        if (isMissedCall) {
            Log.w(TAG, "Missed/ended call notification — skipping: $title / $textPreview")
            return
        }

        // ── Skip non-WhatsApp from here on (messages only) ──
        if (!isWhatsApp) return

        // Check if notification filter is enabled
        try {
            val settings = PeterDatabase.getInstance(this).adminSettingsDao().let {
                kotlinx.coroutines.runBlocking(kotlinx.coroutines.Dispatchers.IO) { it.getSync() }
            }
            if (settings?.isNotificationFilterEnabled != true) return
        } catch (_: Exception) {}

        // Skip non-message notifications (service, progress, system)
        if (category == Notification.CATEGORY_SERVICE ||
            category == Notification.CATEGORY_PROGRESS ||
            category == Notification.CATEGORY_TRANSPORT ||
            category == Notification.CATEGORY_SYSTEM) {
            return
        }

        // Skip ongoing/foreground notifications
        if (sbn.isOngoing) return

        // Skip summary notifications ("WhatsApp - X messages from Y chats")
        if (sbn.notification.group != null && sbn.key.contains("|null|")) return

        // Skip notifications without message content
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

        // Skip non-message call notifications (ongoing, missed)
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
        // Extract REAL phone number from notification key (JID), don't rely solely on title
        val extractedPhone = extractPhoneFromNotificationKey(sbn)
        val lookupTarget = extractedPhone ?: title
        val senderIsPhoneNumber = PHONE_REGEX.matches(title.trim())
        val contactLookup = lookupContact(lookupTarget)
        val isWaSynced = if (extractedPhone != null) isWhatsAppSyncedContact(extractedPhone) else false

        Log.w(TAG, "── CONTACT ANALYSIS ──")
        Log.w(TAG, "  sender: '$title'")
        Log.w(TAG, "  extractedPhone: $extractedPhone")
        Log.w(TAG, "  isPhoneNumber: $senderIsPhoneNumber")
        Log.w(TAG, "  inDeviceContacts: ${contactLookup.inDeviceContacts}")
        Log.w(TAG, "  phoneFromContacts: ${contactLookup.phoneNumber}")
        Log.w(TAG, "  inPeterContacts: ${contactLookup.inPeterContacts}")
        Log.w(TAG, "  hasOutgoingCallHistory: ${contactLookup.hasOutgoingCallHistory}")
        Log.w(TAG, "  isWhatsAppSynced: $isWaSynced")
        Log.w(TAG, "  contactStatus: ${contactLookup.status}")
        Log.w(TAG, "──────────────────────")

        // If WhatsApp-synced contact or has call history — trust them
        if (contactLookup.hasOutgoingCallHistory || isWaSynced) {
            Log.w(TAG, "Trusted contact (call history or WA synced) — allowing $title")
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

            // Auto-reply if enabled and scam detected
            if (analysis.isSuspicious) {
                try {
                    val settings = PeterDatabase.getInstance(this).adminSettingsDao().let {
                        kotlinx.coroutines.runBlocking(kotlinx.coroutines.Dispatchers.IO) { it.getSync() }
                    }
                    if (settings?.isAutoReplyEnabled == true) {
                        sendAutoReply(sbn)
                    }
                } catch (_: Exception) {}
            }
        }
    }

    /** Auto-reply message in 20 languages, ordered by world population coverage */
    private fun getAutoReplyMessage(): String {
        val lang = java.util.Locale.getDefault().language
        val msg = when (lang) {
            "es" -> "Este número está protegido por Peter. Esta conversación es monitoreada por seguridad."
            "en" -> "This number is protected by Peter. This conversation is monitored for security."
            "zh" -> "此号码受 Peter 保护。此对话受安全监控。"
            "hi" -> "यह नंबर Peter द्वारा सुरक्षित है। यह बातचीत सुरक्षा के लिए मॉनिटर की जाती है।"
            "ar" -> "هذا الرقم محمي بواسطة Peter. هذه المحادثة مراقبة لأغراض أمنية."
            "pt" -> "Este número está protegido por Peter. Esta conversa é monitorada por segurança."
            "bn" -> "এই নম্বরটি Peter দ্বারা সুরক্ষিত। এই কথোপকথন নিরাপত্তার জন্য পর্যবেক্ষণ করা হয়।"
            "ru" -> "Этот номер защищён Peter. Этот разговор отслеживается в целях безопасности."
            "ja" -> "この番号は Peter によって保護されています。この会話はセキュリティのために監視されています。"
            "fr" -> "Ce numéro est protégé par Peter. Cette conversation est surveillée pour des raisons de sécurité."
            "de" -> "Diese Nummer wird von Peter geschützt. Dieses Gespräch wird aus Sicherheitsgründen überwacht."
            "id", "ms" -> "Nomor ini dilindungi oleh Peter. Percakapan ini dipantau untuk keamanan."
            "tr" -> "Bu numara Peter tarafından korunmaktadır. Bu görüşme güvenlik amacıyla izlenmektedir."
            "ko" -> "이 번호는 Peter에 의해 보호됩니다. 이 대화는 보안을 위해 모니터링됩니다."
            "it" -> "Questo numero è protetto da Peter. Questa conversazione è monitorata per sicurezza."
            "ur" -> "یہ نمبر Peter کے ذریعے محفوظ ہے۔ یہ گفتگو سیکیورٹی کے لیے مانیٹر کی جاتی ہے۔"
            "pl" -> "Ten numer jest chroniony przez Peter. Ta rozmowa jest monitorowana w celach bezpieczeństwa."
            "uk" -> "Цей номер захищений Peter. Ця розмова контролюється з міркувань безпеки."
            "vi" -> "Số này được bảo vệ bởi Peter. Cuộc trò chuyện này được giám sát vì lý do an ninh."
            "th" -> "หมายเลขนี้ได้รับการปกป้องโดย Peter การสนทนานี้ถูกตรวจสอบเพื่อความปลอดภัย"
            "sw" -> "Nambari hii inalindwa na Peter. Mazungumzo haya yanafuatiliwa kwa usalama."
            "nl" -> "Dit nummer wordt beschermd door Peter. Dit gesprek wordt beveiligd gemonitord."
            "ro" -> "Acest număr este protejat de Peter. Această conversație este monitorizată pentru securitate."
            else -> "This number is protected by Peter. This conversation is monitored for security."
        }
        return "⚠\uFE0F $msg"
    }

    /** Auto-reply to scam messages via WhatsApp's notification RemoteInput */
    private fun sendAutoReply(sbn: StatusBarNotification) {
        val actions = sbn.notification.actions ?: return
        for (action in actions) {
            val remoteInputs = action.remoteInputs ?: continue
            if (remoteInputs.isEmpty()) continue

            // Found the reply action — build the reply intent
            val replyMessage = getAutoReplyMessage()

            val replyBundle = Bundle().apply {
                putCharSequence(remoteInputs[0].resultKey, replyMessage)
            }
            val replyIntent = Intent().apply {
                RemoteInput.addResultsToIntent(remoteInputs, this, replyBundle)
            }

            try {
                action.actionIntent.send(this, 0, replyIntent)
                Log.w(TAG, "AUTO-REPLY sent via notification RemoteInput")

                scope.launch {
                    try {
                        PeterDatabase.getInstance(this@WhatsAppNotificationGuardService)
                            .guardLogDao().insert(
                                GuardLogEntity(
                                    eventType = "AUTO_REPLY_SENT",
                                    packageName = sbn.packageName,
                                    detail = "Auto-reply sent to suspicious sender",
                                )
                            )
                    } catch (_: Exception) {}
                }
            } catch (e: PendingIntent.CanceledException) {
                Log.e(TAG, "Auto-reply PendingIntent cancelled", e)
            }
            return
        }
        Log.w(TAG, "No RemoteInput action found — cannot auto-reply")
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

    // ── Incoming call handling (WhatsApp VoIP + Samsung dialer) ──

    private fun handleIncomingCall(sbn: StatusBarNotification, caller: String, callText: String) {
        // Check if call screening is enabled
        try {
            val settings = PeterDatabase.getInstance(this).adminSettingsDao().let {
                kotlinx.coroutines.runBlocking(kotlinx.coroutines.Dispatchers.IO) { it.getSync() }
            }
            if (settings?.isCallScreeningEnabled != true) {
                Log.w(TAG, "Call screening disabled — allowing call")
                return
            }
        } catch (_: Exception) {}

        val isWhatsApp = sbn.packageName == WHATSAPP_PKG || sbn.packageName == WHATSAPP_BIZ_PKG
        val source = if (isWhatsApp) "WhatsApp" else "Phone"

        // For WhatsApp: extract REAL phone number from notification key (don't trust the title)
        // Scammers can set any profile name, but the JID in the key is their real number
        val extractedPhone = if (isWhatsApp) extractPhoneFromNotificationKey(sbn) else null
        val lookupTarget = extractedPhone ?: caller
        Log.w(TAG, "$source call from: title='$caller' extractedPhone=$extractedPhone lookupTarget=$lookupTarget")

        // Look up caller in contacts using the real phone number when available
        val contactLookup = lookupContact(lookupTarget)
        Log.w(TAG, "  inDevice=${contactLookup.inDeviceContacts} | inPeter=${contactLookup.inPeterContacts} | hasCallHistory=${contactLookup.hasOutgoingCallHistory}")

        // Also check WhatsApp synced contacts (covers cases where name doesn't match)
        val isWaSynced = if (extractedPhone != null) isWhatsAppSyncedContact(extractedPhone) else false
        if (isWaSynced) Log.w(TAG, "  WhatsApp synced contact: YES")

        // Allow known contacts
        if (contactLookup.inPeterContacts || contactLookup.inDeviceContacts || contactLookup.hasOutgoingCallHistory || isWaSynced) {
            Log.w(TAG, "Known contact calling — allowing")
            return
        }

        // For non-WhatsApp (phone dialer): if showing a name, they're in device contacts
        val callerIsPhoneNumber = PHONE_REGEX.matches(caller.trim())
        if (!callerIsPhoneNumber && !isWhatsApp) {
            Log.w(TAG, "Phone dialer showing name: $caller — allowing (device contact)")
            return
        }

        Log.w(TAG, "UNKNOWN caller: $caller ($source) — silencing and showing warning")

        // Try to decline/silence the call via the notification's action buttons
        declineCall(sbn)

        // Show intercept screen
        val isVideo = callText.contains("video", ignoreCase = true)
        InterceptData.pendingProfilePic = null
        val intent = Intent("com.peter.app.ACTION_INTERCEPT_NOTIFICATION").apply {
            setPackage(packageName)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_MULTIPLE_TASK)
            putExtra("sender", caller)
            putExtra("message",
                if (isVideo) "Videollamada entrante de número desconocido"
                else "Llamada entrante de número desconocido"
            )
            putExtra("phone", contactLookup.phoneNumber ?: caller)
            putExtra("threat_level", 1)
            putExtra("threat_label",
                if (isVideo) "Videollamada desconocida"
                else "Llamada desconocida"
            )
            putExtra("threat_desc", "Este número no está en tus contactos. Podría ser una estafa telefónica.")
            putExtra("status", if (isWhatsApp) "WA_CALL_UNKNOWN" else "PHONE_CALL_UNKNOWN")
        }
        startActivity(intent)

        // Log the event
        scope.launch {
            try {
                PeterDatabase.getInstance(this@WhatsAppNotificationGuardService)
                    .guardLogDao().insert(
                        GuardLogEntity(
                            eventType = if (isWhatsApp) "WA_CALL_SCREENED" else "PHONE_CALL_SCREENED",
                            packageName = sbn.packageName,
                            detail = "From: $caller | ${if (isVideo) "Video" else "Voice"} | $source | Unknown",
                        )
                    )
            } catch (_: Exception) {}
        }
    }

    /** Try to decline/silence an incoming call by triggering the notification's Decline action */
    private fun declineCall(sbn: StatusBarNotification) {
        val actions = sbn.notification.actions ?: return
        Log.w(TAG, "Call notification has ${actions.size} actions: ${actions.map { it.title }}")

        // Look for Decline/Reject button by label (localized)
        val declineLabels = listOf(
            "decline", "reject", "dismiss", "hang up",
            "rechazar", "colgar",
            "recusar", "rejeitar",
        )
        for (action in actions) {
            val label = action.title?.toString()?.lowercase() ?: continue
            if (declineLabels.any { label.contains(it) }) {
                Log.w(TAG, "Triggering Decline action: '${action.title}'")
                try {
                    action.actionIntent.send()
                } catch (e: PendingIntent.CanceledException) {
                    Log.e(TAG, "Decline PendingIntent cancelled", e)
                }
                return
            }
        }

        // Fallback: first action is typically Decline on WhatsApp/Samsung
        Log.w(TAG, "No labeled decline found — trying first action: '${actions[0].title}'")
        try {
            actions[0].actionIntent.send()
        } catch (e: PendingIntent.CanceledException) {
            Log.e(TAG, "First action PendingIntent cancelled", e)
            // Last resort: just cancel the notification (silences the ring)
            cancelNotification(sbn.key)
        }
    }

    /** Extract phone number from WhatsApp notification key (JID format: ...phone@s.whatsapp.net...) */
    private fun extractPhoneFromNotificationKey(sbn: StatusBarNotification): String? {
        try {
            val key = sbn.key ?: return null
            Log.w(TAG, "  [JID] raw key: $key")
            Log.w(TAG, "  [JID] tag: ${sbn.tag}")

            // Try tag first — WhatsApp often puts JID in the tag
            val jidRegex = Regex("""(\d{7,15})@s\.whatsapp\.net""")
            val tagMatch = if (sbn.tag != null) jidRegex.find(sbn.tag!!) else null
            if (tagMatch != null) {
                Log.w(TAG, "  [JID] found in tag: +${tagMatch.groupValues[1]}")
                return "+${tagMatch.groupValues[1]}"
            }

            // Try key
            val match = jidRegex.find(key)
            if (match != null) {
                Log.w(TAG, "  [JID] found in key: +${match.groupValues[1]}")
                return "+${match.groupValues[1]}"
            }

            // Try notification group
            val group = sbn.notification.group
            if (group != null) {
                Log.w(TAG, "  [JID] group: $group")
                val groupMatch = jidRegex.find(group)
                if (groupMatch != null) {
                    Log.w(TAG, "  [JID] found in group: +${groupMatch.groupValues[1]}")
                    return "+${groupMatch.groupValues[1]}"
                }
            }

            // Try MessagingStyle sender_person key
            val messages = sbn.notification.extras?.getParcelableArray(Notification.EXTRA_MESSAGES)
            if (messages != null) {
                for ((i, msg) in messages.withIndex()) {
                    if (msg is android.os.Bundle) {
                        val person = msg.get("sender_person")
                        if (person is android.app.Person) {
                            Log.w(TAG, "  [JID] person[$i]: name=${person.name}, key=${person.key}, uri=${person.uri}")
                            val personKey = person.key
                            if (personKey != null) {
                                val personMatch = jidRegex.find(personKey)
                                if (personMatch != null) {
                                    Log.w(TAG, "  [JID] found in person key: +${personMatch.groupValues[1]}")
                                    return "+${personMatch.groupValues[1]}"
                                }
                            }
                        }
                    }
                }
            }
            Log.w(TAG, "  [JID] NO phone number found in notification metadata")
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting phone from notification key", e)
        }
        return null
    }

    /** Check if a phone number belongs to a WhatsApp-synced contact in Android's ContactsContract */
    private fun isWhatsAppSyncedContact(phone: String): Boolean {
        try {
            val digits = phone.filter { it.isDigit() }
            if (digits.length < 7) return false
            Log.w(TAG, "  [WA-SYNC] checking phone=$phone digits=$digits last10=${digits.takeLast(10)}")

            // First try: WhatsApp profile MIME type
            val cursor = contentResolver.query(
                ContactsContract.Data.CONTENT_URI,
                arrayOf(ContactsContract.Data.DISPLAY_NAME, ContactsContract.Data.DATA1),
                "${ContactsContract.Data.MIMETYPE} = ? AND ${ContactsContract.Data.DATA1} LIKE ?",
                arrayOf(
                    "vnd.android.cursor.item/vnd.com.whatsapp.profile",
                    "%${digits.takeLast(10)}%"
                ),
                null,
            )
            cursor?.use {
                Log.w(TAG, "  [WA-SYNC] WhatsApp profile query: ${it.count} results")
                while (it.moveToNext()) {
                    Log.w(TAG, "  [WA-SYNC]   match: name=${it.getString(0)}, data1=${it.getString(1)}")
                }
                if (it.count > 0) return true
            }

            // Second try: RawContacts with WhatsApp account type
            val rawCursor = contentResolver.query(
                ContactsContract.RawContacts.CONTENT_URI,
                arrayOf(ContactsContract.RawContacts.DISPLAY_NAME_PRIMARY, ContactsContract.RawContacts.ACCOUNT_TYPE),
                "${ContactsContract.RawContacts.ACCOUNT_TYPE} IN (?, ?)",
                arrayOf("com.whatsapp", "com.whatsapp.w4b"),
                null,
            )
            rawCursor?.use {
                Log.w(TAG, "  [WA-SYNC] RawContacts with WA account: ${it.count} total")
                // Just log first 5 for debugging
                var logged = 0
                while (it.moveToNext() && logged < 5) {
                    Log.w(TAG, "  [WA-SYNC]   raw: name=${it.getString(0)}, type=${it.getString(1)}")
                    logged++
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error checking WhatsApp synced contacts", e)
        }
        return false
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
