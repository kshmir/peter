# Peter -- 60-Second Video Demo Script

## Purpose

This video demonstrates why Peter requires **AccessibilityService** and **NotificationListenerService** permissions. It is intended for Google Play's permissions review team and shows each permission being used for its declared, user-facing purpose: protecting a senior with dementia from scams and unauthorized app access.

---

## Script

### 0:00 - 0:10 | Home Screen

**Action:** App opens to Peter's simplified home screen. Three large icons are visible: WhatsApp, Phone, Camera. The wallpaper is clean and calming. Text is large and high-contrast.

**Text overlay:** "Peter -- Safe launcher for seniors"

**Voiceover (optional):** "Peter replaces the home screen with a simple, caregiver-approved interface."

**What it shows:** The launcher restricts visible apps to only those the caregiver has whitelisted.

---

### 0:10 - 0:20 | AccessibilityService in Action

**Action:** User swipes up or taps the app drawer. Taps on "Settings" (an unauthorized app). Peter immediately intercepts, shows a blocking screen ("This app is not available"), and redirects the user back to the home screen.

**Text overlay:** "Unauthorized apps are blocked automatically"

**Voiceover (optional):** "If the user tries to open a non-approved app, Peter's AccessibilityService detects the launch and safely redirects them home."

**Permission demonstrated:** `AccessibilityService` -- used to detect and block launches of non-whitelisted apps in real time, preventing a cognitively impaired user from accessing dangerous settings or installing apps.

---

### 0:20 - 0:35 | NotificationListenerService + Scam Detection

**Action:** A WhatsApp notification arrives from an unknown number. The message contains a scam: "You won a prize! Click here to claim: bit.ly/xxxxx". Peter intercepts the notification before it reaches the user. A red quarantine screen appears with a warning: "Suspicious message blocked -- possible scam detected."

**Text overlay:** "Scam messages intercepted before delivery"

**Voiceover (optional):** "When a suspicious WhatsApp message arrives, Peter's NotificationListenerService intercepts it and quarantines the content, protecting the user from phishing and financial fraud."

**Permission demonstrated:** `NotificationListenerService` -- used to read incoming notifications in real time, analyze message content for scam patterns (suspicious links, prize claims, financial fraud keywords), and block dangerous messages before the user sees them.

---

### 0:35 - 0:45 | Call Screening

**Action:** An incoming phone call from an unknown number rings. Peter silences the call and shows a warning screen: "Unknown caller blocked." The call is logged in the security event log.

**Text overlay:** "Unknown callers screened automatically"

**Voiceover (optional):** "Peter screens calls from unknown numbers, protecting the user from phone scams and unwanted contact."

**What it shows:** Call screening works alongside notification filtering to provide layered protection.

---

### 0:45 - 0:55 | Caregiver Admin Panel

**Action:** Caregiver performs the hidden 5-tap gesture, enters the 4-digit PIN. The admin panel opens showing: security event log, toggle controls for scam filters, whitelisted app list, notification filter settings, and language selection.

**Text overlay:** "Caregivers manage everything via PIN-protected panel"

**Voiceover (optional):** "The caregiver has full control through a PIN-protected admin panel -- managing approved apps, reviewing security events, and configuring protection settings."

**What it shows:** All security features are caregiver-managed, not user-facing. The elderly user never needs to interact with settings.

---

### 0:55 - 1:00 | Closing

**Action:** Back to the home screen. Grandmother (or actor) smiles and taps WhatsApp to video-call family.

**Text overlay:** "Protecting the ones you love"

**Voiceover (optional):** "Peter -- built with love for the people who matter most."

---

## Recording Instructions

### Screen Recording

```bash
# Connect device via USB, enable USB debugging
adb devices

# Record screen at 1280x720 for Play Store compatibility
adb shell screenrecord --size 1280x720 --bit-rate 6000000 /sdcard/peter-demo.mp4

# Pull the recording when done (Ctrl+C to stop, or 3-minute auto-stop)
adb pull /sdcard/peter-demo.mp4 ./peter-demo.mp4
```

### Text Overlays

Add text overlays in post-production using one of:

- **ffmpeg** (free, CLI):
  ```bash
  ffmpeg -i peter-demo.mp4 \
    -vf "drawtext=text='Peter -- Safe launcher for seniors':fontsize=36:fontcolor=white:borderw=2:bordercolor=black:x=(w-text_w)/2:y=h-80:enable='between(t,0,10)'" \
    -codec:a copy peter-demo-final.mp4
  ```
- **CapCut** (free, mobile/desktop) -- easiest for multiple overlays with timing
- **DaVinci Resolve** (free, desktop) -- professional quality

### Tips

- Record in portrait mode (phone orientation) since this is a launcher demo
- Use a clean test device or emulator with only the whitelisted apps installed
- Ensure the device clock and status bar look realistic (not an obvious emulator)
- Keep transitions natural -- a real user would not rush through screens
- Total video should be exactly 60 seconds or under for Play Store review
- Export at 1080x1920 (portrait) or 1280x720 (landscape) in H.264 MP4 format
