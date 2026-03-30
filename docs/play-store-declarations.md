# Play Store Permission Declarations

Copy-paste-ready text for Google Play Console permission declaration forms.

---

## A. Accessibility Service Declaration

### Core functionality description

Peter is a caregiver-managed Android launcher designed to protect elderly users with dementia and other forms of cognitive decline from digital scams. The AccessibilityService is core to the app's protective function and is used for the following purposes:

1. **App blocking (foreground enforcement):** Peter restricts the device to a caregiver-approved list of applications. When the user attempts to open an unauthorized app, the AccessibilityService detects the foreground activity change and immediately redirects the user back to the safe launcher home screen. On Android 10 and above, no alternative API exists to detect and block arbitrary foreground app launches in real time. The deprecated `UsageStatsManager` approach introduces unacceptable delays that would allow scam apps to run before being caught.

2. **WhatsApp conversation scanning:** The AccessibilityService reads on-screen WhatsApp message content in real time to detect scam patterns, including financial fraud solicitations, phishing links, and social engineering attempts targeting elderly users. When a suspicious message is detected, the user is shown an on-screen warning. This functionality cannot be achieved through any other API, as WhatsApp does not expose message content through its notification payload beyond brief previews.

3. **Caregiver-controlled configuration:** All AccessibilityService behavior is configured exclusively by a caregiver through a PIN-protected admin panel. The elderly user cannot modify settings. This ensures the protective measures remain in place for users who cannot make informed security decisions due to cognitive decline.

**No alternative APIs exist on Android 10+ that can perform real-time foreground app blocking or read in-app message content for scam detection.** The AccessibilityService is not used to perform actions on behalf of the user, inject input, or scrape data for transmission. All processing occurs entirely on-device.

### User-facing disclosure

> Peter uses Android's Accessibility Service to keep you safe. It watches which apps are opened and ensures only caregiver-approved apps can run. It also reads WhatsApp messages on screen to check for scam or fraud attempts. All of this happens on your device only — no message content or personal data is sent anywhere. Your caregiver controls these protections through a secure admin panel.

---

## B. Notification Listener Declaration

### Core functionality description

Peter uses NotificationListenerService to intercept incoming WhatsApp notifications and analyze message previews for scam indicators before they reach the elderly user. This serves the following purposes:

1. **Unknown contact detection:** When a WhatsApp notification arrives, Peter checks the sender against the device's contacts and outgoing call history. Messages from unknown contacts receive additional scrutiny.

2. **Scam pattern detection:** Notification content is analyzed on-device for patterns associated with financial fraud, phishing, impersonation, and other scam techniques commonly used to exploit elderly individuals.

3. **Protective alerts:** When a suspicious message from an unknown sender is detected, Peter alerts the caregiver and/or warns the elderly user before they engage with the message.

**All notification processing occurs entirely on-device.** No notification content, sender information, or analysis results are transmitted to any server, third party, or external service. The NotificationListenerService is configured exclusively by the caregiver through a PIN-protected admin panel.

### User-facing disclosure

> Peter reads incoming WhatsApp notifications to check for messages from unknown contacts that may be scams. It looks for signs of fraud, phishing, or impersonation. Everything is checked on your phone only — no messages or personal information are ever sent anywhere. Your caregiver manages these safety settings.

---

## C. READ_CALL_LOG Declaration

### Core functionality description

Peter uses the READ_CALL_LOG permission to determine whether the elderly user has a pre-existing trusted relationship with a WhatsApp message sender. Specifically:

1. **Trust signal from outgoing calls:** When a WhatsApp message arrives from a number not saved in device contacts, Peter checks the outgoing call history. If the user has previously placed a call to that number, the sender is treated as a trusted contact and the message bypasses additional scam screening.

2. **Reduced false positives:** This prevents legitimate but unsaved contacts (e.g., a doctor's office the user has called, a neighbor, a family friend) from being flagged as potential scammers.

**The call log is read on-device only.** No call history data is transmitted, stored externally, or shared with any third party. Peter reads only the outgoing call records and does not modify or delete any call log entries.

### User-facing disclosure

> Peter checks your outgoing call history to identify people you already know. If you've called someone before, messages from them are treated as safe. Your call history stays on your phone and is never shared with anyone.

---

## D. CALL_PHONE Declaration

### Core functionality description

Peter uses the CALL_PHONE permission to provide one-tap calling from the simplified home screen. The app is designed for elderly users with dementia or cognitive decline who may struggle with multi-step phone interactions:

1. **Simplified calling interface:** The caregiver configures a set of trusted contacts (family members, doctors, emergency numbers) displayed as large, clearly labeled buttons on the home screen. Tapping a contact button initiates the call directly without requiring the user to navigate the system dialer.

2. **Reduced cognitive burden:** Eliminating intermediate steps (opening the dialer, confirming the number, pressing the call button) is essential for users with cognitive impairment who may become confused or anxious during multi-step processes.

### User-facing disclosure

> Peter lets you call your important contacts with a single tap from the home screen. When you press a contact's button, the call starts right away so you don't need to navigate menus or dial numbers.

---

## E. READ_CONTACTS Declaration

### Core functionality description

Peter uses the READ_CONTACTS permission to cross-reference WhatsApp message senders with the device's saved contacts. This is part of the scam protection system:

1. **Known vs. unknown contact identification:** When a WhatsApp message or notification is received, Peter checks whether the sender's phone number exists in the device's contact list. Messages from saved contacts are treated as trusted. Messages from unknown numbers receive additional scam pattern analysis.

2. **Contact display on home screen:** Caregiver-selected contacts are displayed on the simplified home screen with their saved names and photos for easy recognition by the elderly user.

**Contact data is read on-device only.** No contact names, phone numbers, or other personal information is transmitted, stored externally, or shared with any third party. Peter does not modify, create, or delete any contacts.

### User-facing disclosure

> Peter checks your phone's contact list to identify people you know. Messages from your saved contacts are treated as safe. Your contacts stay on your phone and are never shared with anyone.
