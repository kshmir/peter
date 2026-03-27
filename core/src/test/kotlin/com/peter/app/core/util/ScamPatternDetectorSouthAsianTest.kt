package com.peter.app.core.util

import com.peter.app.core.util.ScamPatternDetector.ScamCategory
import com.peter.app.core.util.ScamPatternDetector.ThreatLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * South Asian, Arabic, and African language scam pattern detection tests.
 *
 * Covers: Hindi (HI), Bengali (BN), Urdu (UR), Arabic (AR), Swahili (SW)
 *
 * Each language section tests:
 * - Bank fraud with local payment systems
 * - Prize scams
 * - Phishing (OTP, click link)
 * - Money requests (urgent transfer)
 * - Impersonation (family emergency)
 * - Government scams (local tax/ID authorities)
 * - Tech support scams
 * - False positives (normal everyday messages)
 */
class ScamPatternDetectorSouthAsianTest {

    private fun analyze(text: String) = ScamPatternDetector.analyze(text)
    private fun analyzeConversation(messages: List<String>) =
        ScamPatternDetector.analyzeConversation(messages)

    // ═══════════════════════════════════════════════════════════════════════
    // HINDI (HI) — Devanagari script
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `HI - UPI account blocked Devanagari`() {
        val result = analyze("UPI पर fraud detect हुआ है। आपका खाता block हो सकता है। तुरंत verify करें।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `HI - SBI account suspended Devanagari`() {
        val result = analyze("SBI: आपका खाता संदिग्ध गतिविधि के कारण बंद कर दिया गया है। कृपया verify करें।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `HI - PhonePe fraud alert Devanagari`() {
        val result = analyze("PhonePe पर फ्रॉड का प्रयास पकड़ा गया है। आपका account block हो सकता है।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `HI - KYC update scam Devanagari`() {
        val result = analyze("आपका KYC अपडेट नहीं हुआ है। 24 घंटे में आपका खाता बंद हो जाएगा।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `HI - ATM card blocked Devanagari`() {
        val result = analyze("आपका ATM कार्ड ब्लॉक हो गया है। नीचे दिए लिंक से अपडेट करें।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `HI - KBC lottery prize scam Devanagari`() {
        val result = analyze("बधाई हो! KBC लॉटरी में आपने 25 लाख रुपये जीत लिए हैं।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `HI - Lucky draw winner Devanagari`() {
        val result = analyze("लकी ड्रॉ में आपका नंबर चुना गया है। इनाम लेने के लिए संपर्क करें।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `HI - OTP sharing request Devanagari`() {
        val result = analyze("आपके फ़ोन पर एक OTP आया है, कृपया वो ओटीपी मुझे भेज दीजिए।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `HI - Aadhaar verification phishing Devanagari`() {
        val result = analyze("आपका आधार कार्ड expire हो गया है। तुरंत verify करें वरना बैंक अकाउंट बंद हो जाएगा।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `HI - Click this link Devanagari`() {
        val result = analyze("इस लिंक पर क्लिक करें और अपना अकाउंट अपडेट करें: http://xyz.in")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `HI - Send money via UPI Devanagari`() {
        val result = analyze("जल्दी से Google Pay पर 5000 रुपये भेज दो, बहुत ज़रूरी है।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `HI - Family emergency impersonation Devanagari`() {
        val result = analyze("बेटा एक्सीडेंट हो गया है, हॉस्पिटल में भर्ती है। जल्दी पैसे भेजो।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `HI - Police impersonation Devanagari`() {
        val result = analyze("मैं बोल रहा हूँ CBI अधिकारी। आपके खिलाफ मामला दर्ज है।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `HI - Income tax notice scam Devanagari`() {
        val result = analyze("आयकर विभाग: बकाया 50,000 रुपये है। तुरंत भुगतान करें।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `HI - Fake PM scheme Devanagari`() {
        val result = analyze("PM योजना में रजिस्टर करें और 2 लाख रुपये पाएं। सीमित सीटें।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `HI - Microsoft tech support scam Devanagari`() {
        val result = analyze("Microsoft सपोर्ट से बोल रहा हूँ। आपके कंप्यूटर में वायरस है।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `HI - AnyDesk remote access scam Devanagari`() {
        val result = analyze("AnyDesk इन्स्टॉल करिए, हम आपका फ़ोन ठीक कर देंगे।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HINDI (HI) — Romanized/Hinglish
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `HI - UPI account blocked Romanized`() {
        val result = analyze("Aapka UPI account block ho gaya hai. Jaldi se verify karo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `HI - Paytm fraud alert Romanized`() {
        val result = analyze("Paytm mein fraud detect hua hai, aapka account band ho sakta hai.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `HI - KBC lottery Romanized`() {
        val result = analyze("Aapne KBC lottery mein 25 lakh jeet liye hain! Claim karne ke liye call karein.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `HI - OTP sharing Romanized`() {
        val result = analyze("Aapke phone par jo OTP aaya hai woh mujhe bhej do please.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `HI - Aadhaar link Romanized`() {
        val result = analyze("Aapka aadhaar card expire ho gaya hai, jaldi update karein.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `HI - Urgent money Romanized`() {
        val result = analyze("Jaldi paise bhej do PhonePe par, bahut urgent hai bhai.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `HI - Changed number impersonation Romanized`() {
        val result = analyze("Maine mera number badal liya hai, ye naya number save kar lo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `HI - Family accident Romanized`() {
        val result = analyze("Beta accident ho gaya hai hospital mein hai, paise bhejo turant.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `HI - RBI directive scam Romanized`() {
        val result = analyze("RBI ke naye directive ke anusar aapka khata verify karna zaroori hai.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HINDI (HI) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `HI FP - Simple greeting Devanagari`() {
        val result = analyze("नमस्ते, कैसे हो? सब ठीक?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `HI FP - Family dinner plans Devanagari`() {
        val result = analyze("आज रात खाने पर आना। माँ ने राजमा चावल बनाया है।")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `HI FP - Normal UPI payment discussion`() {
        val result = analyze("Maine PhonePe pe check kiya, balance aa gaya hai.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `HI FP - Weather conversation Romanized`() {
        val result = analyze("Aaj bahut garmi hai yaar, bahar mat jaana.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `HI FP - Temple visit plan`() {
        val result = analyze("कल मंदिर चलते हैं। सुबह 8 बजे निकलेंगे।")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `HI FP - Cricket discussion Romanized`() {
        val result = analyze("India ne aaj match jeet liya! Kohli ne century maari.")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BENGALI (BN) — Bengali script
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `BN - bKash account blocked`() {
        val result = analyze("আপনার bKash একাউন্ট ব্লক করা হয়েছে। এখনই ভেরিফাই করুন।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BN - Nagad fraud alert`() {
        val result = analyze("Nagad একাউন্টে জালিয়াতি ধরা পড়েছে। আপনার একাউন্ট বন্ধ হয়ে যাবে।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BN - Dutch-Bangla Bank account suspended`() {
        val result = analyze("Dutch-Bangla Bank: আপনার account suspend হয়েছে। অনুগ্রহ করে verify করুন।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BN - KYC update scam`() {
        val result = analyze("আপনার KYC আপডেট করুন, না হলে অ্যাকাউন্ট বন্ধ হয়ে যাবে। সময়সীমা ২৪ ঘন্টা।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BN - ATM card blocked`() {
        val result = analyze("আপনার ATM কার্ড ব্লক হয়ে গেছে। নিচের লিংকে ক্লিক করুন।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BN - Lottery winner prize scam`() {
        val result = analyze("অভিনন্দন! আপনি লটারিতে ৫ লক্ষ টাকা জিতেছেন। পুরস্কার নিতে যোগাযোগ করুন।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BN - Lucky draw selected`() {
        val result = analyze("লাকি ড্র তে আপনার নম্বর নির্বাচিত হয়েছে। এখনই claim করুন।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BN - OTP sharing request`() {
        val result = analyze("আপনার ফোনে একটা OTP এসেছে, সেটা আমাকে পাঠিয়ে দিন।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BN - NID verification phishing`() {
        val result = analyze("আপনার জাতীয় পরিচয়পত্র verify করুন, না হলে সব সেবা বন্ধ হয়ে যাবে।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BN - Click this link phishing`() {
        val result = analyze("এই লিংক এ ক্লিক করুন এবং আপনার তথ্য আপডেট করুন।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BN - Send money via bKash urgent`() {
        val result = analyze("জরুরি! bKash এ ১০,০০০ টাকা পাঠান, এখনই দরকার।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `BN - Urgent money via Nagad`() {
        val result = analyze("তাড়াতাড়ি টাকা পাঠান Nagad এ, বাবা হাসপাতালে।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any {
            it.category == ScamCategory.MONEY_REQUEST || it.category == ScamCategory.IMPERSONATION
        })
    }

    @Test
    fun `BN - Family accident impersonation`() {
        val result = analyze("ভাই দুর্ঘটনায় পড়েছে, হাসপাতালে ভর্তি। জরুরি টাকা লাগবে।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BN - Police impersonation`() {
        val result = analyze("আমি বলছি police থেকে। আপনার বিরুদ্ধে একটা case হয়েছে।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BN - Tax notice scam`() {
        val result = analyze("NBR থেকে নোটিশ: আপনার ট্যাক্স বকেয়া আছে। ২৪ ঘন্টায় জরিমানা হবে।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BN - Government scheme scam`() {
        val result = analyze("সরকারি প্রকল্পে আবেদন করুন, ৫০,০০০ টাকা পাবেন। সীমিত সুযোগ।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BN - Microsoft support scam`() {
        val result = analyze("Microsoft সাপোর্ট থেকে বলছি, আপনার কম্পিউটারে ভাইরাস ধরা পড়েছে।")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BENGALI (BN) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `BN FP - Simple greeting`() {
        val result = analyze("কেমন আছো? অনেকদিন কথা হয়নি।")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `BN FP - Lunch invitation`() {
        val result = analyze("আজ দুপুরে খেতে আসবে? মাছের ঝোল রান্না করেছি।")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `BN FP - Normal bKash payment done`() {
        val result = analyze("তোমার টাকাটা bKash এ পাঠিয়ে দিয়েছি, চেক করো।")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `BN FP - Weather conversation`() {
        val result = analyze("আজ বৃষ্টি হবে মনে হচ্ছে, ছাতা নিয়ে যেও।")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `BN FP - Cricket match talk`() {
        val result = analyze("বাংলাদেশ আজ ম্যাচ জিতেছে! সাকিব দারুণ খেলেছে।")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `BN FP - School plans`() {
        val result = analyze("বাচ্চাকে স্কুল থেকে আনতে হবে বিকেল ৪টায়।")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // URDU (UR) — Arabic script
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `UR - JazzCash account blocked`() {
        val result = analyze("آپ کا JazzCash اکاؤنٹ بلاک کر دیا گیا ہے۔ فوری طور پر ویریفائی کریں۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UR - Easypaisa fraud alert`() {
        val result = analyze("آپ کے Easypaisa اکاؤنٹ میں دھوکا دہی پائی گئی ہے۔ اکاؤنٹ بند ہو سکتا ہے۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UR - HBL account suspended`() {
        val result = analyze("HBL: آپ کا اکاؤنٹ معطل کر دیا گیا ہے۔ verify کرنے کے لیے یہاں کلک کریں۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UR - KYC update scam`() {
        val result = analyze("آپ کا KYC اپڈیٹ نہیں ہوا۔ ۲۴ گھنٹوں میں آپ کا کھاتا بند ہو جائے گا۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UR - ATM card blocked`() {
        val result = analyze("آپ کا ATM کارڈ بلاک ہو گیا ہے۔ نیچے دیے گئے لنک سے اپڈیٹ کریں۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UR - SBP directive scam`() {
        val result = analyze("اسٹیٹ بینک آف پاکستان کی نئی ہدایت کے مطابق آپ کا اکاؤنٹ ویریفائی کرنا ضروری ہے۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UR - Lottery winner`() {
        val result = analyze("مبارکباد! آپ نے لاٹری میں ۵ لاکھ روپے جیت لیے ہیں۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `UR - Lucky draw winner`() {
        val result = analyze("لکی ڈرا میں آپ کا نمبر منتخب ہوا ہے۔ انعام حاصل کریں۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `UR - OTP sharing request`() {
        val result = analyze("آپ کے فون پر جو OTP آیا ہے وہ مجھے بھیج دیں۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `UR - NADRA CNIC verification phishing`() {
        val result = analyze("نادرا: آپ کا شناختی کارڈ expire ہو گیا ہے۔ فوری طور پر ویریفائی کریں۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `UR - Click this link phishing`() {
        val result = analyze("یہ لنک پر کلک کریں اور اپنی معلومات اپڈیٹ کریں۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `UR - Send money via JazzCash urgent`() {
        val result = analyze("جلدی سے JazzCash پر ۱۰ ہزار روپے بھیج دو، بہت فوری ہے۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `UR - Urgent money request`() {
        val result = analyze("فوری طور پر پیسے بھیج دو، ابھی ضرورت ہے۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `UR - Family emergency impersonation`() {
        val result = analyze("بیٹا ایکسیڈنٹ میں زخمی ہو گیا ہے، ہسپتال میں ہے۔ فوری پیسے چاہیے۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `UR - FIA authority impersonation`() {
        val result = analyze("میں بول رہا ہوں FIA سے۔ آپ کے خلاف مقدمہ درج ہے۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `UR - FBR tax notice scam`() {
        val result = analyze("FBR نوٹس: آپ کے ٹیکس واجبات ادا نہیں ہوئے۔ فوری جرمانہ لگے گا۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `UR - BISP Ehsaas fake claim`() {
        val result = analyze("احساس پروگرام میں آپ کی رقم تیار ہے۔ ابھی رجسٹر کریں اور حاصل کریں۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `UR - Microsoft tech support scam`() {
        val result = analyze("Microsoft سپورٹ سے بات ہو رہی ہے۔ آپ کے کمپیوٹر میں وائرس ہے۔")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // URDU (UR) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `UR FP - Simple greeting`() {
        val result = analyze("السلام علیکم، کیسے ہو؟ سب خیریت؟")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `UR FP - Family dinner plan`() {
        val result = analyze("آج رات کھانے پر آنا۔ بریانی بنائی ہے۔")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `UR FP - Normal JazzCash payment done`() {
        val result = analyze("JazzCash پر چیک کیا، بیلنس آ گیا ہے۔")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `UR FP - Weather talk`() {
        val result = analyze("آج بہت گرمی ہے یار، باہر مت جاؤ۔")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `UR FP - Cricket discussion`() {
        val result = analyze("پاکستان نے آج میچ جیت لیا! بابر اعظم نے سنچری بنائی۔")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `UR FP - Mosque visit plan`() {
        val result = analyze("جمعے کو مسجد چلتے ہیں۔ نماز کے بعد بازار جائیں گے۔")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARABIC (AR) — Arabic script
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `AR - STC Pay account blocked`() {
        val result = analyze("STC Pay: حسابك محظور بسبب نشاط مشبوه. تحقق الآن.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - Al Rajhi bank account suspended`() {
        val result = analyze("الراجحي: حسابك موقوف مؤقتاً. أدخل بياناتك لإعادة التفعيل.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - SNB account verify`() {
        val result = analyze("البنك الأهلي: حسابك يحتاج تحقق فوري. أدخل بياناتك البنكية.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - Mada card blocked`() {
        val result = analyze("بطاقة مدى الخاصة بك محظور. تواصل معنا لإعادة التفعيل.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - Vodafone Cash Egypt fraud alert`() {
        val result = analyze("فودافون كاش: حسابك موقوف بسبب احتيال مشتبه. تحقق فوراً.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - Update bank information scam`() {
        val result = analyze("يجب عليك تحديث بيانات حسابك البنكي فوراً لتجنب الإيقاف.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - You won a prize`() {
        val result = analyze("مبروك! لقد فزت بجائزة قيمتها ٥٠,٠٠٠ ريال في السحب العشوائي.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `AR - Lottery selected winner`() {
        val result = analyze("تم اختيارك للفوز بجائزة نقدية كبيرة. اتصل بنا للاستلام.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `AR - Claim your reward`() {
        val result = analyze("لديك جائزة بانتظار الاستلام. أرسل بياناتك للحصول عليها.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `AR - OTP verification code sharing`() {
        val result = analyze("رمز التحقق وصلك على الجوال، أرسل لي الرقم من فضلك.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `AR - Absher account phishing Saudi`() {
        val result = analyze("أبشر: حسابك يحتاج تحديث عاجل. سجل دخول من هذا الرابط.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `AR - National ID verification phishing`() {
        val result = analyze("بطاقة الأحوال الخاصة بك انتهت. يجب تحديث بياناتك فوراً.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `AR - Click this link phishing`() {
        val result = analyze("هذا الرابط اضغط عليه لتأكيد حسابك قبل الإيقاف.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `AR - Send money via STC Pay urgent`() {
        val result = analyze("STC Pay أرسل مبلغ فلوس الحين. عاجل ضروري.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `AR - Vodafone Cash Egypt money request`() {
        val result = analyze("فودافون كاش، أرسل فلوس عن طريقه. محتاج المبلغ ضروري.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `AR - Urgent money request`() {
        val result = analyze("عاجل! محتاج فلوس الحين ضروري. أرسل لي على الحساب.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `AR - Family emergency impersonation`() {
        val result = analyze("ابني صار له حادث وهو في المستشفى. أحتاج فلوس فوراً.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `AR - Changed number impersonation`() {
        val result = analyze("غيرت رقمي، هذا الرقم الجديد. احفظه عندك.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `AR - Police authority impersonation`() {
        val result = analyze("أنا أتكلم من الشرطة. عندك مخالفة يجب تسويتها فوراً.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `AR - ZATCA tax notice scam`() {
        val result = analyze("الزكاة والضريبة: لديك مستحقات متأخرة وغرامة سيتم تطبيقها خلال ٤٨ ساعة.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `AR - Fake Saudi welfare Hafiz`() {
        val result = analyze("حافز: تسجيل مطلوب الآن واستلام المبلغ فوراً.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `AR - Google tech support scam`() {
        val result = analyze("Google دعم فني: تم اكتشاف نشاط مشبوه في حسابك.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `AR - Device virus detected`() {
        val result = analyze("فيروس في جهازك اكتشف. اتصل بالدعم الفني فوراً.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARABIC (AR) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `AR FP - Simple greeting`() {
        val result = analyze("السلام عليكم، كيف حالك؟ إن شاء الله بخير.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `AR FP - Family dinner invitation`() {
        val result = analyze("تعال العشا عندنا الليلة. أمي سوت كبسة.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `AR FP - Normal STC Pay transfer done`() {
        val result = analyze("حولت لك الفلوس على STC Pay، شيك حسابك.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `AR FP - Weather conversation`() {
        val result = analyze("الجو حار اليوم، ما أنصحك تطلع. خلك بالبيت.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `AR FP - Football match discussion`() {
        val result = analyze("الهلال فاز اليوم! ما شاء الله مباراة حلوة.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `AR FP - Mosque plans`() {
        val result = analyze("نروح المسجد صلاة الجمعة وبعدين نتغدى برا.")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SWAHILI (SW) — Latin script
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `SW - M-Pesa account blocked`() {
        val result = analyze("Akaunti yako ya M-Pesa imezuiwa kwa sababu ya shughuli za kutia shaka. Thibitisha sasa.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `SW - Tigo Pesa fraud alert Tanzania`() {
        val result = analyze("Tigo Pesa: Akaunti yako imefungwa kwa sababu ya udanganyifu. Wasiliana nasi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `SW - CRDB bank account suspended`() {
        val result = analyze("CRDB: Akaunti yako imezuiwa. Tafadhali thibitisha taarifa zako.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `SW - Equity Bank account verify`() {
        val result = analyze("Equity Bank account yako imefungwa kwa sababu ya tatizo la usalama. Verify sasa.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `SW - ATM card blocked`() {
        val result = analyze("Kadi yako ya ATM imezuiwa. Bonyeza kiungo hiki kurejesha.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `SW - Update bank information scam`() {
        val result = analyze("Sasisha taarifa za akaunti yako ya benki ili kuzuia kusimamishwa.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `SW - Prize winner scam`() {
        val result = analyze("Hongera! Umeshinda tuzo ya milioni 5 katika bahati nasibu yetu.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `SW - Lucky draw selected`() {
        val result = analyze("Umechaguliwa kupata zawadi maalum katika kura ya bahati. Wasiliana nasi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `SW - Claim your prize`() {
        val result = analyze("Una tuzo inakusubiri. Chukua sasa kabla muda haujaisha.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `SW - OTP verification code sharing`() {
        val result = analyze("Nambari ya uthibitisho, nipe tafadhali. Imekuja kwenye simu yako.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `SW - NIDA ID verification phishing Tanzania`() {
        val result = analyze("NIDA: Kitambulisho chako kimeisha muda. Thibitisha sasa au huduma zitasimamishwa.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `SW - Click this link phishing`() {
        val result = analyze("Bonyeza kiungo hiki kuthibitisha akaunti yako kabla ya kusimamishwa.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `SW - Send money via M-Pesa urgent`() {
        val result = analyze("Haraka! Tuma pesa kwa M-Pesa sasa hivi, nahitaji fedha dharura.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `SW - Tigo Pesa money request Tanzania`() {
        val result = analyze("Tigo Pesa, tuma fedha sasa. Kiasi cha shilingi 50,000. Ni dharura.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `SW - Urgent money request generic`() {
        val result = analyze("Dharura! Nahitaji pesa sasa hivi. Tuma haraka tafadhali.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `SW - Family emergency impersonation`() {
        val result = analyze("Mtoto amepata ajali, yuko hospitali. Tuma pesa haraka tafadhali.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `SW - Changed number impersonation`() {
        val result = analyze("Nimebadilisha nambari mpya ya simu. Ihifadhi nambari hii.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `SW - Police authority impersonation`() {
        val result = analyze("Mimi ni afisa wa polisi. Unahitajika kulipa faini au utafungwa.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `SW - KRA tax notice Kenya`() {
        val result = analyze("KRA: Una deni la kodi ambalo halijalipiwa. Faini itaongezwa ndani ya saa 48.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `SW - TRA tax notice Tanzania`() {
        val result = analyze("TRA notisi: Kodi yako haijalipwa. Faini itatumika ndani ya siku 3.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `SW - Government aid scam`() {
        val result = analyze("Mpango wa serikali wa msaada: Jiandikishe sasa upate pesa ya ruzuku.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `SW - Microsoft tech support scam`() {
        val result = analyze("Microsoft msaada wa kiufundi: Tumegundua shughuli za kutia shaka kwenye akaunti yako.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `SW - Device virus detected`() {
        val result = analyze("Virusi kwenye simu yako imegunduliwa. Piga simu kwa msaada wa kiufundi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SWAHILI (SW) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `SW FP - Simple greeting`() {
        val result = analyze("Habari yako? Mambo vipi? Tuonane baadaye.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `SW FP - Family dinner invitation`() {
        val result = analyze("Njoo kula chakula cha jioni nyumbani. Mama amepika pilau.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `SW FP - Normal M-Pesa payment done`() {
        val result = analyze("Nimekutumia pesa kwa M-Pesa, angalia akaunti yako.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `SW FP - Weather conversation`() {
        val result = analyze("Leo jua kali sana. Kaa ndani usitoke nje.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `SW FP - Football discussion`() {
        val result = analyze("Simba wameshinda leo! Mechi nzuri sana.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `SW FP - School pickup`() {
        val result = analyze("Nenda kumchukua mtoto shuleni saa kumi na moja.")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CROSS-LANGUAGE CONVERSATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `HI - Conversation escalation UPI scam Romanized`() {
        val result = analyzeConversation(listOf(
            "Hello ji, kaise hain aap?",
            "Main aapka bank se bol raha hoon",
            "Aapka UPI account block ho gaya hai, jaldi se OTP bhej do verify karne ke liye"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `BN - Conversation escalation bKash scam`() {
        val result = analyzeConversation(listOf(
            "আসসালামু আলাইকুম, কেমন আছেন?",
            "আমি bKash থেকে বলছি",
            "আপনার একাউন্ট ব্লক হয়ে গেছে, OTP দিন ভেরিফাই করার জন্য"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `AR - Conversation escalation STC Pay scam`() {
        val result = analyzeConversation(listOf(
            "السلام عليكم، كيف الحال؟",
            "أنا من خدمة عملاء STC Pay",
            "حسابك محظور بسبب نشاط مشبوه، أرسل رمز التحقق لإعادة التفعيل"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `SW - Conversation escalation M-Pesa scam`() {
        val result = analyzeConversation(listOf(
            "Habari yako ndugu?",
            "Mimi ni mfanyakazi wa Safaricom",
            "Akaunti yako ya M-Pesa imezuiwa, tuma nambari ya uthibitisho haraka"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.4f)
    }
}
