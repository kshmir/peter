# Data Safety Form Answers

Structured answers for every section of the Google Play Console Data Safety form.

---

## Overview

### Does your app collect or share any of the required user data types?

**Yes** — the app collects certain data types, but all data is processed and stored on-device only. No data is transmitted off the device or shared with any third party.

### Is all of the user data collected by your app encrypted in transit?

Not applicable. No user data is transmitted off the device. There is no data in transit.

### Do you provide a way for users to request that their data is deleted?

**Yes.** Users (or their caregivers) can delete all app data through the following methods:

- **Uninstalling the app** removes all locally stored data, including the Room database, preferences, and any cached content.
- **Clearing app data** from Android Settings > Apps > Peter > Storage > Clear Data removes all stored data without uninstalling.
- **Admin panel reset** within the app allows the caregiver to reset all settings and stored data via the PIN-protected admin panel.

---

## Data Collection and Sharing

### Does your app share any user data with third parties?

**No.** Peter does not share any user data with any third party, including advertising networks, analytics providers, or data brokers.

### Does your app collect any of the following data types?

#### Location

- **Approximate location:** Not collected
- **Precise location:** Not collected

#### Personal info

- **Name:** Not collected
- **Email address:** Not collected
- **User IDs:** Not collected
- **Address:** Not collected
- **Phone number:** Not collected
- **Race and ethnicity:** Not collected
- **Political or religious beliefs:** Not collected
- **Sexual orientation:** Not collected
- **Other info:** Not collected

#### Financial info

- **User payment info:** Not collected
- **Purchase history:** Not collected
- **Credit score:** Not collected
- **Other financial info:** Not collected

#### Health and fitness

- **Health info:** Not collected
- **Fitness info:** Not collected

#### Messages

- **Emails:** Not collected
- **SMS or MMS:** Not collected
- **Other in-app messages:** Not collected

> Note: Peter reads WhatsApp notifications and on-screen messages for real-time scam detection, but this content is analyzed transiently in memory and is not stored, logged, or collected. No message content is persisted or transmitted.

#### Photos and videos

- **Photos:** Not collected
- **Videos:** Not collected

#### Audio files

- **Voice or sound recordings:** Not collected
- **Music files:** Not collected
- **Other audio files:** Not collected

#### Files and docs

- **Files and docs:** Not collected

#### Calendar

- **Calendar events:** Not collected

#### Contacts

- **Contacts:** Collected

  - **Purpose:** On-device lookup to identify known vs. unknown WhatsApp message senders as part of the scam protection system. Also used to display caregiver-selected contacts on the simplified home screen.
  - **Is this data processed ephemerally?** Yes. Contact data is read from the system contacts provider at the time of lookup and is not copied or stored separately by the app.
  - **Is this data required for your app, or can users choose whether it's collected?** Required for core scam protection functionality.
  - **Is this data shared?** No.
  - **Is this data transferred to third parties?** No.

#### App activity

- **App interactions:** Collected

  - **Purpose:** Peter monitors which apps are launched to enforce the caregiver-approved app list. When an unauthorized app is detected in the foreground, Peter redirects the user back to the safe launcher.
  - **Is this data processed ephemerally?** Yes. App launch events are detected in real time via AccessibilityService and are not logged or stored.
  - **Is this data required for your app, or can users choose whether it's collected?** Required for core app-blocking functionality.
  - **Is this data shared?** No.
  - **Is this data transferred to third parties?** No.

- **Installed apps:** Not collected
- **Other user-generated content:** Not collected
- **Other actions:** Not collected

#### Web browsing

- **Web browsing history:** Not collected

#### Device or other IDs

- **Device or other IDs:** Not collected

---

## Data Handling and Security

### Is all collected data encrypted in transit?

Not applicable. No data leaves the device. There is no network transmission of user data.

### Is all collected data encrypted at rest?

**Yes.**

- The app's local database uses Android's Room persistence library on the device's encrypted storage partition.
- The caregiver PIN is stored securely using Android Keystore.
- All data resides in the app's private internal storage directory, which is sandboxed by Android and inaccessible to other apps.

### Can users request deletion of their data?

**Yes.** See deletion methods listed in the Overview section above.

---

## Additional Disclosures

### Does your app use any third-party SDKs or libraries that collect data?

**No.** Peter does not include any third-party SDKs that collect, transmit, or process user data. There are:

- No advertising SDKs
- No analytics SDKs (no Firebase Analytics, no Google Analytics, no Crashlytics)
- No crash reporting SDKs
- No social media SDKs
- No attribution or tracking SDKs

### Is your app a news or social media app?

**No.**

### Does your app support account creation?

**No.** There are no user accounts. The caregiver admin panel is protected by a local PIN only.

### Is data linked to user identity?

**No.** Peter does not maintain user profiles or link any collected data to a user identity. There are no accounts, no sign-ins, and no user identifiers transmitted off-device.

### Does your app contain ads?

**No.** Peter contains no advertising of any kind.

### Does your app use advertising ID?

**No.**
