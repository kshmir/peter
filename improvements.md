# Peter — Future Improvements

## Custom Lock Screen

**Priority:** Medium
**Effort:** 1-2 days
**Permissions:** None needed

Replace the default lock screen with a simplified, senior-friendly version using `showWhenLocked=true` + `turnScreenOn=true` (standard Android APIs, Play Store compatible).

**How it works:**
1. `ACTION_SCREEN_ON` receiver detects screen turning on
2. Launches `PeterLockScreenActivity` on top of system lock screen
3. Shows: large clock, date, grandma's photo, emergency SOS button
4. Simple tap/swipe to unlock → `KeyguardManager.requestDismissKeyguard()` → Peter home screen
5. System PIN/pattern stays underneath for real security

**No `SYSTEM_ALERT_WINDOW` needed.** Apps like Ava Lockscreen, AcDisplay, and KLCK all use this approach.

**References:**
- https://victorbrandalise.com/how-to-show-activity-on-lock-screen-instead-of-notification/
- https://github.com/aosp-mirror/platform_frameworks_base/blob/master/tests/ShowWhenLockedApp/src/com/android/showwhenlocked/ShowWhenLockedActivity.java

---

## Block Replies to Unknown Contacts

**Priority:** High
**Effort:** 0.5 days

Use accessibility service to detect when grandma tries to compose/reply in an unknown contact's WhatsApp chat. Show warning before the message is sent.

---

## SOS Emergency Button

**Priority:** High
**Effort:** 0.5 days

Big red button on home screen that:
- Calls preset emergency contact
- Sends SMS with GPS location to family
- Triggers loud alarm sound

---

## Inactivity Alert

**Priority:** Medium
**Effort:** 1 day

If grandma hasn't used the phone in X hours, send a push notification to the caregiver's phone. Requires Firebase Cloud Messaging.

---

## Remote Admin (Firebase)

**Priority:** Medium
**Effort:** 3-5 days

Family can manage settings from their own phone:
- Add/remove whitelisted apps
- Add/remove contacts
- View guard log
- Get push notifications when scams are detected

---

## Medication Reminders

**Priority:** Medium
**Effort:** 1 day

Scheduled alarms with big "Tomé mi medicamento" confirmation button. Caregiver sets the schedule in admin panel. Uses `AlarmManager` exact alarms.

---

## Simplified Voice Message

**Priority:** Low
**Effort:** 1 day

Big button on home screen to record and send a voice message to a preset family member via WhatsApp share intent.

---

## Photo Frame Mode

**Priority:** Low
**Effort:** 1 day

When idle for X minutes, show family photos as a slideshow (from a shared Google Photos album or local folder).

---

## Automated WhatsApp Actions via AccessibilityService

**Priority:** Medium
**Effort:** 1-2 days

The AccessibilityService can programmatically click, tap, scroll, and type in any app. This enables powerful automated actions inside WhatsApp:

- **Auto-block scammer in WhatsApp** — navigate to contact info → tap "Block" → confirm
- **Auto-delete scam conversation** — long-press chat → tap delete → confirm
- **Auto-report scammer** — navigate to report flow inside WhatsApp
- **Prevent replies to unknown contacts** — detect the compose box, intercept before sending
- **Auto-archive suspicious chats** — swipe/archive scam conversations

**How it works:**
```kotlin
// Click a specific UI element by ID
val node = rootInActiveWindow.findAccessibilityNodeInfosByViewId("com.whatsapp:id/block")
node[0].performAction(AccessibilityNodeInfo.ACTION_CLICK)

// Tap at exact screen coordinates
val path = Path().apply { moveTo(540f, 1200f) }
dispatchGesture(GestureDescription.Builder()
    .addStroke(GestureDescription.StrokeDescription(path, 0, 100))
    .build(), null, null)

// Type text into a field
node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT,
    Bundle().apply { putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, "text") })
```

**Note:** This is powerful but fragile — WhatsApp UI IDs can change between updates. Should be implemented with fallbacks and robust node discovery.

---

## Fall Detection

**Priority:** Low
**Effort:** 2 days

Accelerometer-based fall detection. If a fall is detected and grandma doesn't respond to the alert within 30 seconds, auto-call emergency contact and send GPS location.
