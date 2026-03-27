package com.peter.app.core.util

/**
 * Scam detection patterns for South Asian, Arabic, and African languages:
 * Hindi (HI), Bengali (BN), Urdu (UR), Arabic (AR), Swahili (SW)
 *
 * Covers:
 * - Hindi: Devanagari script + Romanized/Hinglish transliterations
 * - Bengali: Bengali script + Romanized transliterations
 * - Urdu: Arabic script (RTL) + Romanized transliterations
 * - Arabic: Arabic script (RTL) + Romanized transliterations
 * - Swahili: Latin script
 *
 * Regional payment systems covered:
 * - India: UPI, PhonePe, Google Pay, Paytm, SBI, HDFC, ICICI, PNB, Axis Bank, RBI
 * - Bangladesh: bKash, Nagad, Rocket, Dutch-Bangla Bank, BRAC Bank
 * - Pakistan: JazzCash, Easypaisa, HBL, UBL, Meezan Bank, State Bank of Pakistan
 * - Arab region: STC Pay, Mada, Al Rajhi, NCB/SNB, Vodafone Cash, Fawry, Instapay
 * - East Africa: M-Pesa, Tigo Pesa, Airtel Money, CRDB, NMB, Equity Bank
 */
internal object ScamPatternsSouthAsianArabicAfrican {

    fun allRules(): List<ScamPatternDetector.PatternRule> = buildList {
        addAll(hindiRules())
        addAll(bengaliRules())
        addAll(urduRules())
        addAll(arabicRules())
        addAll(swahiliRules())
    }

    // ══════════════════════════════════════════════════════════════════════
    // HINDI (HI) — Devanagari + Romanized/Hinglish
    // ══════════════════════════════════════════════════════════════════════

    private fun hindiRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("(आपका|aapka|apka).{0,20}(खाता|khata|account).{0,30}(ब्लॉक|block|बंद|band|suspend)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "HI", "IN", 0.4f,
            "HI: Account blocked/suspended",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(SBI|HDFC|ICICI|PNB|Axis Bank|RBI).{0,30}(खाता|account|khata).{0,20}(बंद|suspend|block|verify)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "HI", "IN", 0.4f,
            "HI: Indian bank account action required",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(UPI|PhonePe|Google Pay|GPay|Paytm).{0,25}(फ्रॉड|fraud|धोखा|dhokha|block|बंद|band|fail)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "HI", "IN", 0.4f,
            "HI: UPI/payment app fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(बैंक|bank).{0,20}(कर्मचारी|adhikari|officer|manager).{0,20}(बोल रहा|bol raha|call kar|calling)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "HI", "IN", 0.35f,
            "HI: Impersonating bank employee",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ATM|एटीएम).{0,20}(कार्ड|card).{0,20}(ब्लॉक|block|expire|बंद|band|clone)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "HI", "IN", 0.35f,
            "HI: ATM card blocked/expired",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(KYC|केवाईसी).{0,25}(अपडेट|update|expire|समाप्त|verify|पूरा|complete)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "HI", "IN", 0.4f,
            "HI: KYC update scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(RBI|आरबीआई).{0,25}(निर्देश|directive|order|guideline|notice)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "HI", "IN", 0.35f,
            "HI: Fake RBI directive",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(आपने|aapne).{0,20}(जीत|jeet|win).{0,20}(लिया|liya|hai|है|गए|gaye)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "HI", "IN", 0.4f,
            "HI: You have won a prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(KBC|कौन बनेगा करोड़पति).{0,30}(जीत|winner|lottery|prize|इनाम)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "HI", "IN", 0.45f,
            "HI: KBC lottery scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(लॉटरी|lottery|lucky draw|लकी ड्रॉ).{0,25}(जीत|win|नंबर|number|चुना गया|selected)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "HI", "IN", 0.4f,
            "HI: Lottery/lucky draw winner",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(इनाम|inaam|prize|पुरस्कार).{0,20}(लेने|claim|प्राप्त|पाने|collect)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "HI", "IN", 0.35f,
            "HI: Claim your prize",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("(OTP|ओटीपी).{0,25}(भेज|bhej|send|share|बता|bata|दे|de|दीजिए|dijiye)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "HI", "IN", 0.45f,
            "HI: OTP sharing request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(OTP|ओटीपी).{0,25}(आया|aaya|मिला|mila|गया|gaya).{0,15}(बता|share|भेज|send)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "HI", "IN", 0.45f,
            "HI: Share the OTP you received",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(आधार|aadhaar|aadhar).{0,20}(verify|वेरिफ|update|अपडेट|link|लिंक|expire|समाप्त)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "HI", "IN", 0.4f,
            "HI: Aadhaar verification phishing",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(PAN|पैन).{0,15}(card|कार्ड).{0,20}(verify|update|link|expire|suspend|block)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "HI", "IN", 0.35f,
            "HI: PAN card verification phishing",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(इस लिंक|is link|yeh link|ye link|इस URL).{0,15}(पर|par|pe|click|क्लिक|खोल|khol|open)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "HI", "IN", 0.35f,
            "HI: Click this link",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("(UPI|PhonePe|Google Pay|GPay|Paytm).{0,20}(भेज|bhej|send|transfer|कर|kar).{0,15}(दो|do|दे|de|दीजिए|dijiye)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "HI", "IN", 0.35f,
            "HI: Send money via UPI/payment app",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(पैसे|paise|paisa|रुपय|rupay|rupees).{0,20}(भेज|bhej|send|transfer|जमा|jama|deposit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "HI", "IN", 0.3f,
            "HI: Send/transfer money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(जल्दी|jaldi|turant|तुरंत|urgent|फ़ौरन|fauran).{0,20}(पैसे|paise|money|रुपय).{0,15}(चाहिए|chahiye|भेज|bhej|send)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "HI", "IN", 0.4f,
            "HI: Urgent money request",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("(मैंने|maine|mera).{0,15}(नंबर|number|phone).{0,15}(बदल|badal|change|नया|naya|new)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "HI", "IN", 0.3f,
            "HI: Changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(बेटा|beta|बेटी|beti|मम्मी|mummy|पापा|papa|भाई|bhai).{0,20}(एक्सीडेंट|accident|हॉस्पिटल|hospital|मुसीबत|musibat)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "HI", "IN", 0.4f,
            "HI: Family emergency impersonation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(मैं|main|mai).{0,10}(बोल रहा|bol raha|bol rahi).{0,15}(पुलिस|police|CBI|CID|अधिकारी|adhikari)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "HI", "IN", 0.4f,
            "HI: Police/authority impersonation",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(आयकर|income tax|IT department).{0,25}(नोटिस|notice|बकाया|due|refund|रिफंड|penalty|जुर्माना)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "HI", "IN", 0.4f,
            "HI: Income tax notice scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(सरकारी|sarkari|government).{0,20}(योजना|yojana|scheme).{0,20}(पैसे|paise|money|लाभ|laabh|benefit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "HI", "IN", 0.35f,
            "HI: Fake government scheme",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(PM|प्रधानमंत्री).{0,15}(योजना|yojana|scheme).{0,20}(रजिस्टर|register|apply|आवेदन|claim)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "HI", "IN", 0.35f,
            "HI: Fake PM scheme registration",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("(Microsoft|Apple|Google|Amazon).{0,20}(सपोर्ट|support|कस्टमर केयर|customer care|हेल्पलाइन|helpline)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "HI", "IN", 0.35f,
            "HI: Tech company support scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(वायरस|virus|hack|हैक|malware|मालवेयर).{0,25}(फ़ोन|phone|कंप्यूटर|computer|device|डिवाइस).{0,15}(मिला|पाया|detect)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "HI", "IN", 0.35f,
            "HI: Device infected with virus",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(AnyDesk|TeamViewer|remote access).{0,20}(install|इन्स्टॉल|download|डाउनलोड|connect)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "HI", "IN", 0.4f,
            "HI: Remote access app installation",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(Bitcoin|बिटकॉइन|crypto|क्रिप्टो).{0,25}(निवेश|invest|कमाई|kamai|earn|दोगुना|double|profit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "HI", "IN", 0.4f,
            "HI: Crypto investment scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(trading|ट्रेडिंग).{0,20}(सीख|seekh|learn|कमा|kama|earn|profit|पैसा|paisa|लाखों|lakhon)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "HI", "IN", 0.3f,
            "HI: Trading/earn money scheme",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(विदेश|videsh|abroad|America|UK|Dubai).{0,25}(रह|rah|living).{0,25}(प्यार|pyaar|love|शादी|shaadi|marry)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "HI", "IN", 0.3f,
            "HI: Foreign romance scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(gift|गिफ्ट|parcel|पार्सल).{0,25}(customs|कस्टम).{0,25}(फ़ीस|fees|पैसे|money|भेज|send)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "HI", "IN", 0.4f,
            "HI: Customs fee for gift/parcel",
        ))
    }

    // ══════════════════════════════════════════════════════════════════════
    // BENGALI (BN) — Bengali script + Romanized
    // ══════════════════════════════════════════════════════════════════════

    private fun bengaliRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("(আপনার|apnar).{0,20}(অ্যাকাউন্ট|account|হিসাব|hishab).{0,25}(ব্লক|block|বন্ধ|bondho|suspend)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "BN", "BD", 0.4f,
            "BN: Account blocked/suspended",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(bKash|বিকাশ|Nagad|নগদ|Rocket|রকেট).{0,25}(ব্লক|block|বন্ধ|bondho|suspend|fraud|জালিয়াতি)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "BN", "BD", 0.4f,
            "BN: bKash/Nagad/Rocket fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(Dutch-Bangla|ডাচ-বাংলা|BRAC Bank|ব্র্যাক ব্যাংক).{0,25}(অ্যাকাউন্ট|account|হিসাব).{0,20}(বন্ধ|block|verify|suspend)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "BN", "BD", 0.4f,
            "BN: DBBL/BRAC Bank account alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ব্যাংক|bank).{0,20}(কর্মকর্তা|kormokorta|officer|কর্মচারী|kormocharee).{0,20}(বলছি|bolchi|calling)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "BN", "BD", 0.35f,
            "BN: Impersonating bank officer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(KYC|কেওয়াইসি).{0,25}(আপডেট|update|ভেরিফাই|verify|সম্পন্ন|complete|সময়সীমা|deadline)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "BN", "BD", 0.4f,
            "BN: KYC update scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ATM|এটিএম).{0,15}(কার্ড|card).{0,20}(ব্লক|block|expire|বন্ধ|bondho|clone)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "BN", "BD", 0.35f,
            "BN: ATM card blocked/expired",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(আপনি|apni).{0,15}(জিতেছেন|jitechhen|জিতলেন|jitlen|won|বিজয়ী|bijoyi|winner)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "BN", "BD", 0.4f,
            "BN: You have won a prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(লটারি|lottery|লাকি ড্র|lucky draw).{0,25}(জিত|jit|win|নম্বর|number|নির্বাচিত|selected)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "BN", "BD", 0.4f,
            "BN: Lottery/lucky draw winner",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(পুরস্কার|puroshkar|prize|ইনাম|inaam).{0,20}(নিতে|nite|claim|পেতে|pete|collect|সংগ্রহ)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "BN", "BD", 0.35f,
            "BN: Claim your prize",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("(OTP|ওটিপি).{0,25}(পাঠা|pathao|পাঠান|pathano|পাঠিয়ে|pathiye|দিন|din|share|বলুন|bolun)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "BN", "BD", 0.45f,
            "BN: OTP sharing request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(OTP|ওটিপি).{0,25}(এসেছে|esheche|পেয়েছেন|peyechhen).{0,15}(দিন|din|share|বলুন|bolun|পাঠান|pathano)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "BN", "BD", 0.45f,
            "BN: Share the OTP you received",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(এই লিংক|ei link|এই URL).{0,15}(ক্লিক|click|খুলুন|khulun|open|যান|jan)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "BN", "BD", 0.35f,
            "BN: Click this link",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(NID|জাতীয় পরিচয়পত্র|এনআইডি).{0,20}(verify|ভেরিফাই|update|আপডেট|expire|link)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "BN", "BD", 0.4f,
            "BN: National ID verification phishing",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("(bKash|বিকাশ|Nagad|নগদ|Rocket|রকেট).{0,20}(পাঠান|pathano|পাঠা|pathao|send|transfer|করুন|korun)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "BN", "BD", 0.35f,
            "BN: Send money via bKash/Nagad/Rocket",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(টাকা|taka|money).{0,20}(পাঠান|pathano|পাঠা|pathao|send|transfer|জমা|joma|deposit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "BN", "BD", 0.3f,
            "BN: Send/transfer money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(জরুরি|joruri|urgent|এখনই|ekhoni|তাড়াতাড়ি|taratari).{0,20}(টাকা|taka|money).{0,15}(লাগবে|lagbe|দরকার|dorkar|পাঠান|pathano)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "BN", "BD", 0.4f,
            "BN: Urgent money request",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("(আমার|amar).{0,15}(নম্বর|number|ফোন|phone).{0,15}(বদলেছে|bodleche|change|নতুন|notun|new)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "BN", "BD", 0.3f,
            "BN: Changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(বাবা|baba|মা|ma|ভাই|bhai|বোন|bon|ছেলে|chhele|মেয়ে|meye).{0,20}(দুর্ঘটনা|durghotona|accident|হাসপাতাল|hashpatal|hospital|বিপদ|bipod)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "BN", "BD", 0.4f,
            "BN: Family emergency impersonation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(আমি|ami).{0,10}(বলছি|bolchi).{0,15}(পুলিশ|police|RAB|র\u200dআব|ডিবি|DB|কর্মকর্তা|officer)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "BN", "BD", 0.4f,
            "BN: Police/authority impersonation",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(সরকারি|sorkari|government).{0,20}(প্রকল্প|prokolpo|scheme|ভাতা|bhata|allowance).{0,20}(টাকা|taka|পাবেন|paben|আবেদন|abedon)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "BN", "BD", 0.35f,
            "BN: Fake government scheme",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ট্যাক্স|tax|আয়কর|aykor|NBR).{0,25}(নোটিশ|notice|বকেয়া|bokeya|due|জরিমানা|jorimana|penalty)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "BN", "BD", 0.4f,
            "BN: Tax notice scam",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("(Microsoft|Apple|Google|Amazon).{0,20}(সাপোর্ট|support|কাস্টমার কেয়ার|customer care|হেল্পলাইন|helpline)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "BN", "BD", 0.35f,
            "BN: Tech company support scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ভাইরাস|virus|হ্যাক|hack|malware).{0,25}(ফোন|phone|কম্পিউটার|computer|device).{0,15}(পাওয়া|pawa|detect)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "BN", "BD", 0.35f,
            "BN: Device infected with virus",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(Bitcoin|বিটকয়েন|crypto|ক্রিপ্টো).{0,25}(বিনিয়োগ|biniyog|invest|আয়|ay|earn|দ্বিগুণ|digun|double|profit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "BN", "BD", 0.4f,
            "BN: Crypto investment scam",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(বিদেশ|bidesh|abroad|America|UK|Dubai).{0,25}(থাকি|thaki|living).{0,25}(ভালোবাসা|bhalobasha|love|বিয়ে|biye|marry)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "BN", "BD", 0.3f,
            "BN: Foreign romance scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(gift|গিফট|parcel|পার্সেল).{0,25}(customs|কাস্টমস).{0,25}(ফি|fee|টাকা|taka|পাঠান|pathano)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "BN", "BD", 0.4f,
            "BN: Customs fee for gift/parcel",
        ))
    }

    // ══════════════════════════════════════════════════════════════════════
    // URDU (UR) — Arabic script (RTL) + Romanized
    // ══════════════════════════════════════════════════════════════════════

    private fun urduRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("(آپ کا|aapka|apka).{0,20}(اکاؤنٹ|account|کھاتا|khata).{0,25}(بلاک|block|بند|band|suspend|معطل)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UR", "PK", 0.4f,
            "UR: Account blocked/suspended",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(JazzCash|جیز کیش|Easypaisa|ایزی پیسہ).{0,25}(بلاک|block|بند|band|suspend|fraud|دھوکا|dhoka)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UR", "PK", 0.4f,
            "UR: JazzCash/Easypaisa fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(HBL|UBL|Meezan|میزان|State Bank|اسٹیٹ بینک).{0,25}(اکاؤنٹ|account|کھاتا).{0,20}(بند|block|verify|suspend|معطل)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UR", "PK", 0.4f,
            "UR: Pakistani bank account alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(بینک|bank).{0,20}(افسر|officer|ملازم|mulazim|manager).{0,20}(بول رہا|bol raha|call|فون)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UR", "PK", 0.35f,
            "UR: Impersonating bank officer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(KYC|کے وائی سی).{0,25}(اپڈیٹ|update|expire|ویریفائی|verify|تصدیق|مکمل|complete)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UR", "PK", 0.4f,
            "UR: KYC update scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ATM|اے ٹی ایم).{0,15}(کارڈ|card).{0,20}(بلاک|block|expire|بند|band|clone)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UR", "PK", 0.35f,
            "UR: ATM card blocked/expired",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(SBP|اسٹیٹ بینک آف پاکستان).{0,25}(ہدایت|directive|حکم|order|نوٹس|notice)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UR", "PK", 0.35f,
            "UR: Fake State Bank directive",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(آپ نے|aapne).{0,15}(جیت|jeet|win).{0,20}(لیا|liya|ہے|hai|گئے|gaye)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "UR", "PK", 0.4f,
            "UR: You have won a prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(لاٹری|lottery|لکی ڈرا|lucky draw).{0,25}(جیت|jeet|win|نمبر|number|منتخب|selected)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "UR", "PK", 0.4f,
            "UR: Lottery/lucky draw winner",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(انعام|inaam|prize|انعامات).{0,20}(لینے|claim|حاصل|حاصل کریں|collect)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "UR", "PK", 0.35f,
            "UR: Claim your prize",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("(OTP|او ٹی پی).{0,25}(بھیج|bhej|send|share|بتا|bata|دے|de|دیں|den)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "UR", "PK", 0.45f,
            "UR: OTP sharing request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(OTP|او ٹی پی).{0,25}(آیا|aaya|ملا|mila|گیا|gaya).{0,15}(بتا|share|بھیج|send|دیں)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "UR", "PK", 0.45f,
            "UR: Share the OTP you received",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(CNIC|شناختی کارڈ|NADRA|نادرا).{0,20}(verify|ویریفائی|update|اپڈیٹ|expire|link|تصدیق)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "UR", "PK", 0.4f,
            "UR: CNIC/NADRA verification phishing",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(اس لنک|is link|ye link|یہ لنک).{0,15}(پر|par|pe|click|کلک|کھول|khol|open)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "UR", "PK", 0.35f,
            "UR: Click this link",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("(JazzCash|جیز کیش|Easypaisa|ایزی پیسہ).{0,20}(بھیج|bhej|send|transfer|کر|kar).{0,15}(دو|do|دے|de|دیں|den)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "UR", "PK", 0.35f,
            "UR: Send money via JazzCash/Easypaisa",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(پیسے|paise|paisa|روپے|rupay|rupees).{0,20}(بھیج|bhej|send|transfer|جمع|jama|deposit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "UR", "PK", 0.3f,
            "UR: Send/transfer money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(جلدی|jaldi|فوری|fori|urgent|ابھی|abhi).{0,20}(پیسے|paise|money|روپے).{0,15}(چاہیے|chahiye|بھیج|bhej|send)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "UR", "PK", 0.4f,
            "UR: Urgent money request",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("(میں نے|maine|mera|میرا).{0,15}(نمبر|number|فون|phone).{0,15}(بدل|badal|change|نیا|naya|new)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "UR", "PK", 0.3f,
            "UR: Changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(بیٹا|beta|بیٹی|beti|امی|ami|ابو|abu|بھائی|bhai).{0,20}(ایکسیڈنٹ|accident|ہسپتال|hospital|مصیبت|musibat)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "UR", "PK", 0.4f,
            "UR: Family emergency impersonation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(میں|main|mai).{0,10}(بول رہا|bol raha).{0,15}(پولیس|police|FIA|ایف آئی اے|رینجرز|rangers|افسر|officer)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "UR", "PK", 0.4f,
            "UR: Police/FIA/authority impersonation",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(FBR|ایف بی آر|ٹیکس|tax).{0,25}(نوٹس|notice|واجبات|due|جرمانہ|penalty|ریفنڈ|refund)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "UR", "PK", 0.4f,
            "UR: Tax/FBR notice scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(سرکاری|sarkari|government|حکومتی).{0,20}(اسکیم|scheme|پروگرام|program).{0,20}(پیسے|paise|فائدہ|benefit|رجسٹر|register)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "UR", "PK", 0.35f,
            "UR: Fake government scheme",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(BISP|بینظیر انکم سپورٹ|احساس|Ehsaas).{0,25}(رقم|رجسٹر|register|پیسے|claim|حاصل)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "UR", "PK", 0.4f,
            "UR: Fake BISP/Ehsaas program scam",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("(Microsoft|Apple|Google|Amazon).{0,20}(سپورٹ|support|کسٹمر کیئر|customer care|ہیلپ لائن|helpline)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "UR", "PK", 0.35f,
            "UR: Tech company support scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(وائرس|virus|ہیک|hack|malware).{0,25}(فون|phone|کمپیوٹر|computer|device).{0,15}(ملا|پایا|detect)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "UR", "PK", 0.35f,
            "UR: Device infected with virus",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(Bitcoin|بٹ کوائن|crypto|کرپٹو).{0,25}(سرمایہ کاری|invest|کمائی|kamai|earn|دوگنا|double|profit|منافع)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "UR", "PK", 0.4f,
            "UR: Crypto investment scam",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(بیرون ملک|abroad|America|UK|Dubai).{0,25}(رہ|rah|رہتا|rehta|living).{0,25}(محبت|mohabbat|love|شادی|shaadi|marry)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "UR", "PK", 0.3f,
            "UR: Foreign romance scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(gift|گفٹ|parcel|پارسل).{0,25}(customs|کسٹمز).{0,25}(فیس|fee|پیسے|money|بھیج|send)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "UR", "PK", 0.4f,
            "UR: Customs fee for gift/parcel",
        ))
    }

    // ══════════════════════════════════════════════════════════════════════
    // ARABIC (AR) — Arabic script (RTL) + Romanized
    // ══════════════════════════════════════════════════════════════════════

    private fun arabicRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("(حسابك|hesabak|account).{0,25}(محظور|mahzoor|موقوف|mawqoof|blocked|suspended|معلق)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "AR", "ALL", 0.4f,
            "AR: Account blocked/suspended",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(STC Pay|مدى|mada|الراجحي|Al Rajhi).{0,25}(حساب|account).{0,20}(محظور|blocked|موقوف|suspended|تحقق|verify)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "AR", "SA", 0.4f,
            "AR-SA: Saudi payment/bank fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(الأهلي|الأهلى|NCB|SNB|البنك الأهلي).{0,25}(حساب|account).{0,20}(محظور|blocked|موقوف|suspended|تحقق|verify)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "AR", "SA", 0.4f,
            "AR-SA: SNB/NCB bank account alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(فودافون كاش|Vodafone Cash|فوري|Fawry|انستاباي|Instapay).{0,25}(حساب|account).{0,20}(محظور|blocked|موقوف|suspended|احتيال|fraud)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "AR", "EG", 0.4f,
            "AR-EG: Egyptian payment service fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(بطاقة مدى|mada card|بطاقة الصراف).{0,20}(محظور|blocked|منتهية|expired|مسروقة|stolen|مستنسخة|cloned)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "AR", "SA", 0.35f,
            "AR-SA: Mada/ATM card blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(البنك|bank|المصرف).{0,20}(موظف|muwazzaf|officer|مدير|manager).{0,20}(يتكلم|yatakallam|يتصل|calling)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "AR", "ALL", 0.35f,
            "AR: Impersonating bank employee",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(تحديث|update|تحقق|verify).{0,20}(بيانات|data|معلومات|information).{0,15}(بنك|bank|مصرف|مالية|financial)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "AR", "ALL", 0.4f,
            "AR: Update/verify bank information",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(لقد|قد).{0,10}(فزت|ربحت|fazta|rabihta).{0,20}(جائزة|prize|مبلغ|amount|سحب|draw)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "AR", "ALL", 0.4f,
            "AR: You have won a prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(يانصيب|lottery|سحب عشوائي|random draw|قرعة|qura).{0,25}(فائز|winner|ربح|win|اختيار|selected)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "AR", "ALL", 0.4f,
            "AR: Lottery/draw winner",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(جائزة|prize|مكافأة|reward).{0,20}(استلام|claim|تحصيل|collect|الحصول|receive)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "AR", "ALL", 0.35f,
            "AR: Claim your prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(تم اختيارك|تم انتخابك|تم ترشيحك).{0,20}(للفوز|للحصول|لربح|للاستفادة)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "AR", "ALL", 0.4f,
            "AR: You have been selected to win",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("(OTP|رمز التحقق|كود التأكيد).{0,25}(أرسل|arsil|send|share|أعط|a3ti|أخبرني|akhbirni)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "AR", "ALL", 0.45f,
            "AR: OTP/verification code sharing request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(رمز التحقق|كود التأكيد|OTP).{0,25}(وصل|wasal|وصلك|wasalak|جا|ja).{0,15}(أرسل|send|أعط|أخبرني|share)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "AR", "ALL", 0.45f,
            "AR: Share the verification code you received",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(هذا الرابط|هالرابط|هاللنك|this link).{0,15}(اضغط|click|افتح|open|ادخل|enter)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "AR", "ALL", 0.35f,
            "AR: Click this link",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(هوية|بطاقة الأحوال|رقم الهوية|الرقم القومي).{0,20}(تحقق|verify|تحديث|update|انتهت|expired|ربط|link)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "AR", "ALL", 0.4f,
            "AR: National ID verification phishing",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(أبشر|Absher|توكلنا|Tawakkalna).{0,20}(تحقق|verify|تحديث|update|انتهت|expired|تسجيل|login)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "AR", "SA", 0.4f,
            "AR-SA: Absher/Tawakkalna account phishing",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("(STC Pay|مدى|mada).{0,20}(أرسل|arsil|send|حول|hawwil|transfer).{0,15}(مبلغ|amount|فلوس|money|ريال)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "AR", "SA", 0.35f,
            "AR-SA: Send money via STC Pay/mada",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(فلوس|فلوسك|مال|money|مبلغ).{0,20}(أرسل|arsil|send|حول|hawwil|transfer|إيداع|deposit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "AR", "ALL", 0.3f,
            "AR: Send/transfer money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(فودافون كاش|Vodafone Cash|فوري|Fawry|انستاباي|Instapay).{0,20}(أرسل|send|حول|transfer).{0,15}(مبلغ|فلوس|money)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "AR", "EG", 0.35f,
            "AR-EG: Send money via Egyptian payment service",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(عاجل|urgent|ضروري|فورا|حالا|الحين).{0,20}(فلوس|money|مبلغ).{0,15}(محتاج|أحتاج|أرسل|send)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "AR", "ALL", 0.4f,
            "AR: Urgent money request",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("(غيرت|بدلت).{0,15}(رقم|رقمي|نمبر|number).{0,10}(الجديد|الحين|new|هذا)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "AR", "ALL", 0.3f,
            "AR: Changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ابني|ابنتي|ولدي|بنتي|أمي|أبوي|أخوي|أختي).{0,20}(حادث|accident|مستشفى|hospital|مشكلة|mushkila|طوارئ|emergency)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "AR", "ALL", 0.4f,
            "AR: Family emergency impersonation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(أنا|ana).{0,10}(أتكلم|أكلمك|atakallam).{0,15}(شرطة|police|أمن|security|مباحث|detective|ضابط|officer)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "AR", "ALL", 0.4f,
            "AR: Police/authority impersonation",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(الزكاة والضريبة|ZATCA|الهيئة العامة للزكاة|مصلحة الضرائب).{0,25}(إشعار|notice|مستحقات|dues|غرامة|penalty|استرداد|refund)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "AR", "ALL", 0.4f,
            "AR: Tax authority notice scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(حكومي|government|حكومة).{0,20}(برنامج|program|مساعدة|aid|إعانة|دعم|support).{0,20}(تسجيل|register|استلام|claim|مال|money)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "AR", "ALL", 0.35f,
            "AR: Fake government aid program",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(حساب المواطن|حافز|ساند|سند|تكافل).{0,25}(تسجيل|register|تحديث|update|استلام|claim|مبلغ|amount)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "AR", "SA", 0.4f,
            "AR-SA: Fake Saudi social welfare program",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("(Microsoft|Apple|Google|Amazon).{0,20}(دعم|support|خدمة عملاء|customer service|مساعدة|help)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "AR", "ALL", 0.35f,
            "AR: Tech company support scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(فيروس|virus|اختراق|hack|malware).{0,25}(هاتف|phone|جهاز|device|كمبيوتر|computer).{0,15}(اكتشف|detected|وجد|found)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "AR", "ALL", 0.35f,
            "AR: Device infected with virus",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(بتكوين|Bitcoin|كريبتو|crypto|عملات رقمية).{0,25}(استثمار|invest|ربح|earn|مضاعفة|double|أرباح|profit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "AR", "ALL", 0.4f,
            "AR: Crypto investment scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(تداول|trading|فوركس|forex).{0,20}(تعلم|learn|اربح|earn|أرباح|profit|ثروة|wealth|مضمون|guaranteed)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "AR", "ALL", 0.35f,
            "AR: Trading/forex scam",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(خارج البلد|abroad|أمريكا|America|بريطانيا|UK|دبي|Dubai).{0,25}(أعيش|أسكن|living).{0,25}(حب|love|زواج|marriage|علاقة|relationship)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "AR", "ALL", 0.3f,
            "AR: Foreign romance scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(هدية|gift|طرد|parcel|شحنة|shipment).{0,25}(جمارك|customs).{0,25}(رسوم|fees|فلوس|money|أرسل|send|ادفع|pay)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "AR", "ALL", 0.4f,
            "AR: Customs fee for gift/parcel",
        ))
    }

    // ══════════════════════════════════════════════════════════════════════
    // SWAHILI (SW) — Latin script
    // ══════════════════════════════════════════════════════════════════════

    private fun swahiliRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("(akaunti|account).{0,20}(yako|your).{0,20}(imezuiwa|blocked|imefungwa|suspended|imesimamishwa)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "SW", "ALL", 0.4f,
            "SW: Account blocked/suspended",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(M-Pesa|Mpesa|M Pesa).{0,25}(imezuiwa|blocked|imefungwa|suspended|udanganyifu|fraud|tatizo|problem)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "SW", "KE", 0.4f,
            "SW-KE: M-Pesa fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(Tigo Pesa|Airtel Money).{0,25}(imezuiwa|blocked|imefungwa|suspended|udanganyifu|fraud|tatizo|problem)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "SW", "TZ", 0.4f,
            "SW-TZ: Tigo Pesa/Airtel Money fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(CRDB|NMB|Equity Bank).{0,25}(akaunti|account).{0,20}(imezuiwa|blocked|imefungwa|suspended|thibitisha|verify)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "SW", "ALL", 0.4f,
            "SW: East African bank account alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(benki|bank).{0,20}(mfanyakazi|officer|meneja|manager).{0,20}(anapigia|anakupigia|calling|anawasiliana)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "SW", "ALL", 0.35f,
            "SW: Impersonating bank employee",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(kadi|card).{0,15}(ya benki|ya ATM).{0,20}(imezuiwa|blocked|imeisha muda|expired|imefungwa)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "SW", "ALL", 0.35f,
            "SW: Bank/ATM card blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(sasisha|update|thibitisha|verify).{0,20}(taarifa|information|data).{0,15}(benki|bank|akaunti|account)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "SW", "ALL", 0.4f,
            "SW: Update/verify bank information",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(umeshinda|umechaguliwa|you have won).{0,25}(tuzo|zawadi|prize|kiasi|amount|fedha|money)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "SW", "ALL", 0.4f,
            "SW: You have won a prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(bahati nasibu|lottery|kura ya bahati|lucky draw).{0,25}(shinda|win|nambari|number|chaguliwa|selected)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "SW", "ALL", 0.4f,
            "SW: Lottery/lucky draw winner",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(tuzo|zawadi|prize).{0,20}(chukua|claim|pokea|receive|pata|collect)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "SW", "ALL", 0.35f,
            "SW: Claim your prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(umechaguliwa|umeshinda|umeteuliwa).{0,20}(kupata|kupokea|kushinda|kuchukua)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "SW", "ALL", 0.4f,
            "SW: You have been selected to receive",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("(OTP|nambari ya uthibitisho|msimbo wa uthibitisho).{0,25}(tuma|send|share|ipe|nipe|peana)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "SW", "ALL", 0.45f,
            "SW: OTP/verification code sharing request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(OTP|nambari|msimbo).{0,25}(imekuja|umepata|umepokea).{0,15}(tuma|send|share|nipe|ipe)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "SW", "ALL", 0.45f,
            "SW: Share the code you received",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(bonyeza|click|fungua|open).{0,15}(kiungo|link|URL).{0,10}(hiki|hii|this)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "SW", "ALL", 0.35f,
            "SW: Click this link",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(kitambulisho|NIDA|ID).{0,20}(thibitisha|verify|sasisha|update|imeisha muda|expired|unganisha|link)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "SW", "TZ", 0.4f,
            "SW-TZ: National ID verification phishing",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("(M-Pesa|Mpesa|M Pesa).{0,20}(tuma|send|peleka|transfer).{0,15}(fedha|pesa|money|kiasi|amount)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "SW", "KE", 0.35f,
            "SW-KE: Send money via M-Pesa",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(Tigo Pesa|Airtel Money).{0,20}(tuma|send|peleka|transfer).{0,15}(fedha|pesa|money|kiasi|amount)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "SW", "TZ", 0.35f,
            "SW-TZ: Send money via Tigo Pesa/Airtel Money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(pesa|fedha|money).{0,20}(tuma|send|peleka|transfer|weka|deposit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "SW", "ALL", 0.3f,
            "SW: Send/transfer money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(haraka|urgent|dharura|sasa hivi|mara moja).{0,20}(pesa|fedha|money).{0,15}(nahitaji|ninahitajika|tuma|send)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "SW", "ALL", 0.4f,
            "SW: Urgent money request",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("(nimebadilisha|nimebadili).{0,15}(nambari|number|simu|phone).{0,15}(mpya|new|nyingine|hii)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "SW", "ALL", 0.3f,
            "SW: Changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(mtoto|mwana|mama|baba|kaka|dada|ndugu).{0,20}(ajali|accident|hospitali|hospital|hatari|danger|dharura|emergency)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "SW", "ALL", 0.4f,
            "SW: Family emergency impersonation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(mimi ni|ninazungumza|napigia).{0,15}(polisi|police|afisa|officer|mkuu|chief|askari)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "SW", "ALL", 0.4f,
            "SW: Police/authority impersonation",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(TRA|mamlaka ya mapato|kodi|tax).{0,25}(notisi|notice|deni|debt|faini|penalty|kurudisha|refund)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "SW", "TZ", 0.4f,
            "SW-TZ: Tax authority notice scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(KRA|Kenya Revenue|kodi|tax).{0,25}(notisi|notice|deni|debt|faini|penalty|kurudisha|refund)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "SW", "KE", 0.4f,
            "SW-KE: KRA tax notice scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(serikali|government).{0,20}(mpango|program|msaada|aid|ruzuku|grant).{0,20}(jiandikishe|register|pata|receive|pesa|money)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "SW", "ALL", 0.35f,
            "SW: Fake government aid program",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("(Microsoft|Apple|Google|Amazon).{0,20}(msaada|support|huduma kwa wateja|customer service|helpline)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "SW", "ALL", 0.35f,
            "SW: Tech company support scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(virusi|virus|kudukua|hack|malware).{0,25}(simu|phone|kompyuta|computer|kifaa|device).{0,15}(imegunduliwa|detected|imepatikana|found)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "SW", "ALL", 0.35f,
            "SW: Device infected with virus",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(Bitcoin|crypto|sarafu za kidijitali).{0,25}(uwekezaji|invest|faida|profit|pata|earn|maradufu|double)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "SW", "ALL", 0.4f,
            "SW: Crypto investment scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(biashara|trading|forex).{0,20}(jifunze|learn|pata|earn|faida|profit|utajiri|wealth|hakika|guaranteed)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "SW", "ALL", 0.35f,
            "SW: Trading/forex scam",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(nje ya nchi|abroad|Marekani|America|Uingereza|UK|Dubai).{0,25}(naishi|living).{0,25}(upendo|love|ndoa|marriage|uhusiano|relationship)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "SW", "ALL", 0.3f,
            "SW: Foreign romance scam",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(zawadi|gift|kifurushi|parcel|shehena|shipment).{0,25}(forodha|customs).{0,25}(ada|fee|pesa|money|tuma|send|lipa|pay)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "SW", "ALL", 0.4f,
            "SW: Customs fee for gift/parcel",
        ))
    }
}
