# Content Rating Questionnaire Answers

Answers for the IARC content rating questionnaire in Google Play Console.

---

## General Content

### Does the app contain any of the following types of content?

| Content Type | Present | Notes |
|---|---|---|
| Violence | No | |
| Fear / intense scenes | No | |
| Sexual content | No | |
| Nudity | No | |
| Profanity or crude humor | No | |
| Drug, alcohol, or tobacco use or references | No | |
| Gambling or simulated gambling | No | |
| Promotion of or instruction in criminal activity | No | |

### Does the app reference real-world issues such as crime, conflict, or social topics?

**Yes.** The app references fraud and scams in a protective context only. Peter is designed to detect and warn elderly users about scam attempts (financial fraud, phishing, impersonation). The references to scams are part of the app's safety mechanisms, not presented as entertainment content.

---

## Interactive Elements

### Does the app allow users to interact or exchange information with other users?

**No.** Peter is a launcher and protection layer. It does not provide any messaging, social, or communication features between users.

### Does the app share a user's current location with other users?

**No.**

### Does the app allow users to make purchases?

**No.** There are no in-app purchases, subscriptions, microtransactions, or any form of real-money transactions.

### Does the app contain advertising?

**No.** There are no ads of any kind.

### Does the app allow users to create, upload, or share content with others?

**No.** There is no user-generated content creation or sharing functionality.

---

## Communication Monitoring

### Does the app monitor, intercept, or analyze communications (calls, messages, notifications)?

**Yes.** Peter monitors WhatsApp notifications and on-screen WhatsApp messages to detect scam patterns targeting elderly users with cognitive decline.

- **What is monitored:** WhatsApp notification previews and on-screen WhatsApp message content.
- **Purpose:** Detecting financial fraud, phishing, impersonation, and other scam patterns that target vulnerable elderly users.
- **Who controls it:** A caregiver (family member or authorized guardian) configures and manages all monitoring through a PIN-protected admin panel.
- **Consent:** The caregiver who sets up the device provides informed consent on behalf of the elderly user. The app is not designed for covert surveillance. It is an elder protection tool, similar to parental controls but for adults with cognitive impairment.
- **Data handling:** All analysis occurs on-device. No communication content is transmitted, stored externally, or shared with any party.

---

## Target Audience and Appeal

### What is the target age group for this app?

**Adults (18+).** The app targets two adult user groups:

1. **Primary operators:** Adult caregivers (typically family members aged 30-70) who install and configure the app on behalf of an elderly relative.
2. **End users:** Elderly adults (typically 65+) with dementia or cognitive decline who use the simplified launcher on their Android device.

### Is this app specifically designed for or directed at children under 13?

**No.** This app is not designed for, marketed to, or intended for use by children. It does not comply with COPPA or similar children's privacy frameworks because those frameworks are not applicable.

### Is this app a "Designed for Families" app?

**No.** This is not a family or children's app. The "family" context is adult caregivers managing devices for elderly relatives.

---

## Classification Summary

Based on the above answers, the expected IARC rating is **PEGI 3 / ESRB Everyone / USK 0 / GRAC All** or equivalent, as the app contains no objectionable content. The references to fraud and scams are informational and protective, not glorifying or instructional.

---

## Additional Notes for Reviewers

- Peter is a launcher replacement (home screen app). After setup, it becomes the default launcher on the elderly user's device.
- The app requires several sensitive permissions (AccessibilityService, NotificationListenerService, READ_CALL_LOG, CALL_PHONE, READ_CONTACTS) — all justified by the elder protection use case and documented in the separate permissions declaration file.
- There is no backend server, no cloud component, and no data transmission. The app is fully self-contained and operates entirely on-device.
- The app is open to review and we can provide a demo video or test APK showing the caregiver setup flow and the scam detection in action.
