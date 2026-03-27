package com.peter.app.core.util

/**
 * Scam detection patterns for Eastern European and Turkish languages:
 * Polish (PL), Ukrainian (UK), Russian (RU), Turkish (TR)
 *
 * These patterns detect common WhatsApp scam messages targeting elderly users
 * in each language, using natural scammer phrasing and region-specific
 * financial institutions, government agencies, and cultural contexts.
 */
internal object ScamPatternsEastern {

    fun allRules(): List<ScamPatternDetector.PatternRule> = buildList {
        addAll(polishRules())
        addAll(ukrainianRules())
        addAll(russianRules())
        addAll(turkishRules())
    }

    // ══════════════════════════════════════════════════════════════════════
    //  POLISH (PL)
    // ══════════════════════════════════════════════════════════════════════

    private fun polishRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(twoje|pana|pani) (konto|karta).{0,30}(zablokowane|zablokowana|zawieszone|zawieszona|zamkni[eę]te)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.4f,
            "PL: Account/card blocked/suspended",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mbank|mbanku|m-bank).{0,25}(zablokowa|zawieszeni|weryfikacj|potwierd[zź]|aktualizacj)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.4f,
            "PL: mBank fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(pko|pko bp|pko b\\.?p\\.?).{0,25}(zablokowa|zawieszeni|weryfikacj|potwierd[zź]|aktualizacj)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.4f,
            "PL: PKO BP fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ing|ing bank).{0,25}(zablokowa|zawieszeni|weryfikacj|potwierd[zź]|aktualizacj)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.4f,
            "PL: ING Bank fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(santander|pekao|alior|bnp paribas|millennium|credit agricole).{0,25}(zablokowa|zawieszeni|weryfikacj|potwierd[zź])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.4f,
            "PL: Polish bank fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bblik.{0,20}(oszust|nieautoryzowa|podejrzan|zablokowa|potwierd[zź]|weryfikacj)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.4f,
            "PL: BLIK fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bprzelewy[2o][4a].{0,20}(problem|b[łl][eą]d|weryfikacj|potwierd[zź])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.35f,
            "PL: Przelewy24 issue",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(podaj|wpisz|prze[sś]lij|wy[sś]lij).{0,20}(has[łl]o|pin|kod (sms|autoryzacyjny|blik)|numer karty|cvv|dane karty)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.45f,
            "PL: Request for PIN/password/CVV/BLIK code",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(podejrzana|nieautoryzowana|nieznana) (transakcja|operacja|p[łl]atno[sś][cć]|wyp[łl]ata)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.4f,
            "PL: Suspicious/unauthorized transaction",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(twoja|pana|pani) karta.{0,20}(skompromitowana|sklonowana|skradziona|zast[ry]ze[żz]ona)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.4f,
            "PL: Card compromised/cloned/stolen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bwykryto.{0,25}(nieautoryzowany|podejrzany|nieznany).{0,15}(dost[eę]p|logowanie|przelew|transakcj)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.4f,
            "PL: Unauthorized access/login detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(aby unikn[aą][cć]|w celu unikni[eę]cia).{0,25}(blokady|zawieszenia|utraty [sś]rodk[oó]w|zamkni[eę]cia)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "PL", "ALL", 0.35f,
            "PL: To avoid blocking/loss of funds",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(wygra[łl](e[sś]|a[sś])?|zdoby[łl](e[sś]|a[sś])?) .{0,20}(nagrod[eę]|lotteryj|los|tysi[eę]cy|z[łl]otych|z[łl]|pln|euro)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "PL", "ALL", 0.4f,
            "PL: You won a prize/lottery",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bgratulacje.{0,25}(wygran|nagrod|losowani|zwyci[eę]|wyp[łl]at)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "PL", "ALL", 0.4f,
            "PL: Congratulations on winning",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(odbierz|zrealizuj|wyp[łl]a[cć]).{0,20}(nagrod[eę]|wygran[aą]|premi[eę]|bonus|prezent)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "PL", "ALL", 0.4f,
            "PL: Claim your prize/reward",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bzosta[łl](e[sś]|a[sś])? (wybrany|wybrana|wylosowany|wylosowana|wytypowany|wytypowana)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "PL", "ALL", 0.35f,
            "PL: You were selected/drawn",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kupon|voucher|bon).{0,15}(\\d+\\s*z[łl]|\\d+\\s*pln|\\d+\\s*euro|gratis|za darmo|do odebrania)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "PL", "ALL", 0.35f,
            "PL: Free voucher/coupon",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kliknij|wejd[źz]|naci[sś]nij|otwórz).{0,15}(link|odnośnik|tutaj|poni[żz]ej|w ł[aą]cz)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "PL", "ALL", 0.3f,
            "PL: Click this link",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(zweryfikuj|potwierd[źz]|zaktualizuj).{0,20}(swoje? (konto|dane|to[żz]samo[sś][cć]|profil))", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "PL", "ALL", 0.35f,
            "PL: Verify/update your account/data",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bpodejrzane (logowanie|pr[oó]ba logowania|aktywno[sś][cć]).{0,20}(twoj|pana|pani|na konc)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "PL", "ALL", 0.4f,
            "PL: Suspicious login attempt",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(twoje? konto|profil) (zostanie|b[eę]dzie) (usuni[eę]t|zablokowa|zawieszony|zamkni[eę]t)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "PL", "ALL", 0.35f,
            "PL: Account will be deleted/blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bpaczka.{0,20}(niedostarczona|oczekuje|zatrzymana|op[łl]a[cć]|dop[łl]a[cć]|op[łl]at[eę])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "PL", "ALL", 0.35f,
            "PL: Package delivery phishing",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(inpost|dpd|dhl|poczta polska|ups|fedex).{0,25}(niedostarczon|op[łl]at|dop[łl]at|potwierd[źz]|problem)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "PL", "ALL", 0.35f,
            "PL: Courier company phishing (InPost, DPD, DHL)",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(prze[sś]lij|wy[sś]lij|przeka[żz]|zr[oó]b przelew).{0,20}(pieni[aą]dze|pieni[eę]dzy|kasa|kas[eę]|z[łl]|z[łl]otych|pln)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "PL", "ALL", 0.35f,
            "PL: Send money/transfer request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(pilnie|natychmiast|jak najszybciej|szybko).{0,20}(prze[sś]l|wy[sś]lij|przeka[żz]|potrzebuj[eę]|po[żz]ycz)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "PL", "ALL", 0.4f,
            "PL: Urgent money request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bpotrzebuj[eę].{0,20}(pieni[eę]dzy|po[żz]yczki|pomocy finansowej|kasy)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "PL", "ALL", 0.3f,
            "PL: I need money/loan",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(przelej|wp[łl]a[cć]|wyślij).{0,15}na (konto|numer|rachunek)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "PL", "ALL", 0.35f,
            "PL: Transfer to account number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(blik|kod blik|wy[sś]lij blik|podaj blik)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "PL", "ALL", 0.35f,
            "PL: BLIK code request",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mamo|tato|babciu|dziadku|wnuczku|c[oó]rko|synku).{0,30}(zmieni[łl](am|em)|nowy numer|pisz[eę] z nowego|to ja)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "PL", "ALL", 0.4f,
            "PL: Family member changed number (mamo/tato/babciu)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(zmieni[łl](am|em) numer|mam nowy numer|pisz[eę] z innego (telefonu|numeru))", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "PL", "ALL", 0.35f,
            "PL: I changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mia[łl](am|em) wypadek|jestem w szpitalu|potrzebuj[eę] pomocy|co[sś] mi si[eę] sta[łl]o)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "PL", "ALL", 0.3f,
            "PL: Emergency - accident/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(to ja|to twój|to twoja|poznaj mnie|nie poznajesz mnie).{0,20}(syn|c[oó]rka|wnuk|wnuczka|brat|siostra)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "PL", "ALL", 0.35f,
            "PL: It's me, your son/daughter/grandchild",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(zus|zak[łl]ad ubezpiecze[ńn]).{0,30}(zaleg[łl]o[sś][cć]|d[łl]ug|kara|mandat|sk[łl]adka|weryfikacj|blokad)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "PL", "ALL", 0.4f,
            "PL: ZUS social security fraud",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(urz[aą]d skarbowy|us|izba skarbowa|krajowa administracja skarbowa|kas).{0,30}(zaleg[łl]o[sś][cć]|d[łl]ug|kara|mandat|kontrola|weryfikacj)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "PL", "ALL", 0.4f,
            "PL: Tax office (US/KAS) debt/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(policja|prokuratura|s[aą]d|komornik).{0,25}(wezwanie|nakaz|mandat|kara|grzywna|sprawa|post[eę]powanie|zajęcie)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "PL", "ALL", 0.35f,
            "PL: Police/court/bailiff summons",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(grozi ci|gro[źz]ba) (areszt|zatrzymanie|kara|grzywna|egzekucja|zaj[eę]cie)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "PL", "ALL", 0.4f,
            "PL: Threat of arrest/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(profil zaufany|epuap|e-puap|gov\\.pl|obywatel\\.gov).{0,20}(wygas|aktualizuj|potwierd[źz]|zweryfikuj|zablokowa)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "PL", "ALL", 0.35f,
            "PL: Profil Zaufany/ePUAP verification",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bitcoin|btc|ethereum|eth|kryptowalut|usdt|binance).{0,20}(inwestycj|okazja|zysk|zarobek|zarobi[cć]|podw[oó]j|potr[oó]j)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "PL", "ALL", 0.4f,
            "PL: Crypto investment opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(zarabiaj|zarobek|zysk|doch[oó]d).{0,15}(pasywn|z domu|bez pracy|[łl]atw|gwarantowan)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "PL", "ALL", 0.35f,
            "PL: Passive income/easy money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(podw[oó]j|potr[oó]j|pomn[oó][żz]).{0,15}(swoje|twoje|swoj[eą]|twoj[eą]) (pieni[aą]dze|inwestycj[eę]|kapita[łl])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "PL", "ALL", 0.4f,
            "PL: Double/triple your money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(platforma|aplikacja).{0,15}(inwestycyjna|do inwestowania|tradingowa|do zarabiania)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "PL", "ALL", 0.25f,
            "PL: Investment platform/app",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(tw[oó]j|pana|pani) (komputer|telefon|urz[aą]dzenie).{0,20}(zainfekowany|wirus|zhakowany|zagro[żz]ony|z[łl]o[sś]liwe)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "PL", "ALL", 0.4f,
            "PL: Your device is infected/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(pomoc techniczna|wsparcie techniczne|dzia[łl] techniczny).{0,20}(microsoft|apple|google|windows|samsung)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "PL", "ALL", 0.35f,
            "PL: Tech support impersonation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(zainstaluj|pobierz|[sś]ci[aą]gnij).{0,15}(aplikacj[eę]|program|oprogramowanie).{0,15}(zdaln|pomoc|teamviewer|anydesk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "PL", "ALL", 0.4f,
            "PL: Install remote access software",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(jestem|pracuj[eę] jako).{0,10}([żz]o[łl]nierz|wojskowy|in[żz]ynier|lekarz|pilot|marynarz).{0,20}(za granic[aą]|w iraku|w afganistanie|na misji|na platformie)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "PL", "ALL", 0.4f,
            "PL: Military/engineer abroad (romance scam)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kocham ci[eę]|jeste[sś] (mi[łl]o[sś]ci[aą]|wyj[aą]tkowa|wyj[aą]tkowy) (mojego|mego) [żz]ycia|b[oó]g (nas|ci[eę]).{0,15}(zsy[łl]a[łl]|po[łl][aą]czy[łl]))", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "PL", "ALL", 0.3f,
            "PL: Love declaration / destiny",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(potrzebuj[eę] pieni[eę]dzy|pomoc finansow[aą]).{0,15}(na (lot|bilet|wiz[eę]|szpital|operacj[eę]|leczenie))", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "PL", "ALL", 0.4f,
            "PL: Need money for travel/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(nie m[oó]w|nie m[oó]wi?[aą]c).{0,15}(rodzinie|dzieciom|nikomu|bliskim)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "PL", "ALL", 0.35f,
            "PL: Don't tell your family",
        ))
    }

    // ══════════════════════════════════════════════════════════════════════
    //  UKRAINIAN (UK)
    // ══════════════════════════════════════════════════════════════════════

    private fun ukrainianRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ваш[аеі]?) (рахунок|картка|карта).{0,30}(заблоковано|заблокована|призупинено|закрито)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.4f,
            "UK: Account/card blocked/suspended",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bприватбанк.{0,25}(заблокова|призупинен|верифікац|підтверд|оновлен|безпек)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.4f,
            "UK: PrivatBank fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bмонобанк.{0,25}(заблокова|призупинен|верифікац|підтверд|оновлен|безпек)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.4f,
            "UK: Monobank fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(а-банк|a-bank|ощадбанк|укрсиббанк|райффайзен).{0,25}(заблокова|призупинен|верифікац|підтверд|оновлен)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.4f,
            "UK: Ukrainian bank fraud alert (A-Bank, Oschadbank)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(введіть|надішліть|вкажіть|повідомте).{0,20}(пін-код|пін|пароль|код з смс|cvv|номер картки|дані картки)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.45f,
            "UK: Request for PIN/password/CVV/SMS code",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(підозріла|несанкціонована|невідома) (транзакція|операція|оплата|списання)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.4f,
            "UK: Suspicious/unauthorized transaction",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bвиявлено.{0,25}(несанкціонован|підозріл|невідом).{0,15}(доступ|вхід|операці|списання)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.4f,
            "UK: Unauthorized access/transaction detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bваша картка.{0,20}(скомпрометована|клонована|викрадена|зламана)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.4f,
            "UK: Card compromised/cloned/stolen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ваші? (кошти|гроші|заощадження)|ваш рахунок).{0,20}(під загрозою|в небезпеці|під ризиком)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.35f,
            "UK: Your money/account is at risk",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(для|щоб) (уникнення|запобігання|збереження).{0,20}(блокування|втрати коштів|закриття|списання)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.35f,
            "UK: To avoid blocking/loss of funds",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(служба безпеки|відділ безпеки|банк).{0,15}(зателефону|зв'яжіться|перезвоніть|напишіть)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "UK", "ALL", 0.3f,
            "UK: Bank security contact request",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ви виграли|ви отримали|вам нараховано).{0,20}(приз|нагород|грошей|гривень|грн|виграш|подарунок)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "UK", "ALL", 0.4f,
            "UK: You won a prize/reward",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bвітаємо.{0,25}(виграш|нагород|переможц|лотере|розіграш)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "UK", "ALL", 0.4f,
            "UK: Congratulations on winning",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(отримайте|заберіть|оформіть).{0,20}(ваш приз|виграш|нагород|подарунок|бонус)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "UK", "ALL", 0.4f,
            "UK: Claim your prize/reward",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(вас обрано|ви обрані|вас вибрано|вас відібрано)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "UK", "ALL", 0.35f,
            "UK: You have been selected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(купон|ваучер|сертифікат).{0,15}(\\d+\\s*грн|\\d+\\s*гривень|безкоштовн|в подарунок|отримати)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "UK", "ALL", 0.35f,
            "UK: Free voucher/coupon",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(натисніть|перейдіть|відкрийте|клікніть).{0,15}(на посилання|за посиланням|тут|нижче|на лінк)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "UK", "ALL", 0.3f,
            "UK: Click this link",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(верифікуйте|підтвердіть|оновіть).{0,20}(свій (акаунт|обліковий запис)|свої (дані|інформацію))", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "UK", "ALL", 0.35f,
            "UK: Verify/update your account/data",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bпідозрілий (вхід|логін|доступ|спроба входу).{0,20}(ваш|акаунт|обліков)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "UK", "ALL", 0.4f,
            "UK: Suspicious login attempt",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ваш (акаунт|обліковий запис)|обліковку) (буде|може бути) (видалено|заблоковано|призупинено)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "UK", "ALL", 0.35f,
            "UK: Account will be deleted/blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(посилка|відправлення).{0,20}(не доставлено|очікує|затримано|оплат|доплат)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "UK", "ALL", 0.35f,
            "UK: Package delivery phishing",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(нова пошта|укрпошта|meest).{0,25}(не доставлен|оплат|доплат|підтверд|проблем)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "UK", "ALL", 0.35f,
            "UK: Nova Poshta/Ukrposhta courier phishing",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(надішли|відправ|переведи|перекажи|скинь).{0,20}(гроші|грошей|грн|гривень|коштів)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "UK", "ALL", 0.35f,
            "UK: Send money/transfer request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(терміново|негайно|якнайшвидше|швидко).{0,20}(надішли|переведи|перекажи|скинь|потрібні)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "UK", "ALL", 0.4f,
            "UK: Urgent money request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bпотрібні.{0,20}(гроші|грошей|кошти|коштів|допомога фінансова)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "UK", "ALL", 0.3f,
            "UK: I need money/financial help",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(переведи|надішли|скинь).{0,15}на (карту|рахунок|картку)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "UK", "ALL", 0.35f,
            "UK: Transfer to card/account",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(мамо|тату|бабусю|дідусю|синку|доню|онуку|онучко).{0,30}(змінив|новий номер|пишу з нового|це я)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "UK", "ALL", 0.4f,
            "UK: Family member changed number (мамо/тату/бабусю)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(змінив номер|маю новий номер|пишу з іншого (телефону|номера))", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "UK", "ALL", 0.35f,
            "UK: I changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(потрапив у (аварію|дтп)|в лікарні|потрібна допомога|щось трапилось)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "UK", "ALL", 0.3f,
            "UK: Emergency - accident/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(це я|це твій|це твоя|не впізнаєш).{0,20}(син|дочка|онук|онучка|брат|сестра|племінник)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "UK", "ALL", 0.35f,
            "UK: It's me, your son/daughter/grandchild",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(дпс|державна податкова|податкова служба|податкова).{0,30}(заборгованість|борг|штраф|пеня|перевірка|блокування)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "UK", "ALL", 0.4f,
            "UK: Tax service (DPS/податкова) debt/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(поліція|прокуратура|суд|виконавча служба|дбр).{0,25}(виклик|повістка|штраф|справа|провадження|арешт)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "UK", "ALL", 0.35f,
            "UK: Police/court/prosecution summons",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(вам загрожує|загроза) (арешт|затримання|штраф|конфіскація|кримінальна відповідальність)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "UK", "ALL", 0.4f,
            "UK: Threat of arrest/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(дія|дія\\s*підпис|банк[іi]д|електронний підпис).{0,20}(закінчується|оновіть|підтвердіть|заблоковано)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "UK", "ALL", 0.35f,
            "UK: Diia/BankID digital signature verification",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(пенсійний фонд|пфу|соціальний захист).{0,25}(перевірка|виплата|заборгованість|оновлення даних)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "UK", "ALL", 0.35f,
            "UK: Pension fund / social services fraud",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(біткоїн|біткойн|btc|ефіріум|eth|крипто|usdt|binance).{0,20}(інвестиц|можливість|прибуток|заробіт|подвоїт|потроїт)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "UK", "ALL", 0.4f,
            "UK: Crypto investment opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(заробляй|заробіток|прибуток|дохід).{0,15}(пасивн|з дому|без роботи|легк|гарантован)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "UK", "ALL", 0.35f,
            "UK: Passive income/easy money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(подвоїти|потроїти|примножити).{0,15}(свої|ваші) (гроші|інвестиції|капітал|кошти)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "UK", "ALL", 0.4f,
            "UK: Double/triple your money",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ваш|твій) (комп'ютер|телефон|пристрій).{0,20}(інфіковано|вірус|зламано|під загрозою|шкідлив)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "UK", "ALL", 0.4f,
            "UK: Your device is infected/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(встановіть|завантажте|скачайте).{0,15}(додаток|програму).{0,15}(віддален|допомог|teamviewer|anydesk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "UK", "ALL", 0.4f,
            "UK: Install remote access software",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(я (військовий|солдат|інженер|лікар|пілот|моряк)).{0,20}(за кордоном|в іраку|в афганістані|на місії|на платформі)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "UK", "ALL", 0.4f,
            "UK: Military/engineer abroad (romance scam)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(кохаю тебе|ти кохання мого життя|доля нас з'єднала|бог нас послав)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "UK", "ALL", 0.3f,
            "UK: Love declaration / destiny",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(потрібні гроші|фінансова допомога).{0,15}(на (квиток|літак|візу|лікарню|операцію|лікування))", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "UK", "ALL", 0.4f,
            "UK: Need money for travel/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(не (кажи|говори|розповідай)).{0,15}(родині|дітям|нікому|близьким)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "UK", "ALL", 0.35f,
            "UK: Don't tell your family",
        ))
    }

    // ══════════════════════════════════════════════════════════════════════
    //  RUSSIAN (RU)
    // ══════════════════════════════════════════════════════════════════════

    private fun russianRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ваш[аеи]?) (счёт|счет|карта|аккаунт).{0,30}(заблокирован|приостановлен|закрыт|ограничен)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.4f,
            "RU: Account/card blocked/suspended",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(сбербанк|сбер).{0,25}(заблокиров|приостановл|верификац|подтверд|обновлен|безопасност)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.4f,
            "RU: Sberbank fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(тинькофф|тинькоф|т-банк|t-bank).{0,25}(заблокиров|приостановл|верификац|подтверд|обновлен)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.4f,
            "RU: Tinkoff/T-Bank fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(втб|vtb).{0,25}(заблокиров|приостановл|верификац|подтверд|обновлен|безопасност)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.4f,
            "RU: VTB fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(альфа[- ]?банк|alfa[- ]?bank|газпромбанк|совкомбанк|открытие|росбанк|почта банк|промсвязьбанк).{0,25}(заблокиров|приостановл|верификац|подтверд)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.4f,
            "RU: Russian bank fraud alert (Alfa-Bank, Gazprombank, etc.)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(сбп|система быстрых платежей).{0,20}(ошибк|возврат|подтверд|верификац|перевод)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.35f,
            "RU: SBP (fast payment system) fraud",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(введите|укажите|пришлите|сообщите|отправьте).{0,20}(пин-код|пин|пароль|код из смс|cvv|номер карты|данные карты|cvc)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.45f,
            "RU: Request for PIN/password/CVV/SMS code",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(подозрительная|несанкционированная|неизвестная) (транзакция|операция|оплата|списание)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.4f,
            "RU: Suspicious/unauthorized transaction",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bобнаружен.{0,25}(несанкционированн|подозрительн|неизвестн).{0,15}(доступ|вход|операци|списани|перевод)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.4f,
            "RU: Unauthorized access/transaction detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bваша карта.{0,20}(скомпрометирована|клонирована|украдена|взломана)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.4f,
            "RU: Card compromised/cloned/stolen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ваши (средства|деньги|сбережения|накопления)|ваш счёт).{0,20}(под угрозой|в опасности|в зоне риска)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.35f,
            "RU: Your money/savings are at risk",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(служба безопасности|отдел безопасности|сотрудник банка).{0,15}(позвоните|свяжитесь|перезвоните|напишите)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.35f,
            "RU: Bank security service contact request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(для|чтобы) (предотвращения|избежания|сохранения).{0,20}(блокировки|потери средств|закрытия|списания)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RU", "ALL", 0.35f,
            "RU: To avoid blocking/loss of funds",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(вы выиграли|вам начислено|вы получили).{0,20}(приз|наград|денег|рублей|руб|выигрыш|подарок)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "RU", "ALL", 0.4f,
            "RU: You won a prize/reward",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bпоздравляем.{0,25}(выигрыш|наград|победител|лотере|розыгрыш)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "RU", "ALL", 0.4f,
            "RU: Congratulations on winning",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(получите|заберите|оформите).{0,20}(ваш приз|выигрыш|наград|подарок|бонус)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "RU", "ALL", 0.4f,
            "RU: Claim your prize/reward",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(вас выбрали|вы были выбраны|вы отобраны|вы стали победителем)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "RU", "ALL", 0.35f,
            "RU: You have been selected/chosen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(купон|ваучер|сертификат).{0,15}(\\d+\\s*руб|\\d+\\s*рублей|бесплатн|в подарок|получить)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "RU", "ALL", 0.35f,
            "RU: Free voucher/coupon",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(нажмите|перейдите|откройте|кликните).{0,15}(по ссылке|на ссылку|здесь|ниже|на линк)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RU", "ALL", 0.3f,
            "RU: Click this link",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(верифицируйте|подтвердите|обновите).{0,20}(свой (аккаунт|учётную запись|учетную запись)|свои (данные|информацию))", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RU", "ALL", 0.35f,
            "RU: Verify/update your account/data",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bподозрительн(ый|ая) (вход|попытка входа|авторизация|активность).{0,20}(ваш|аккаунт|учётн)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RU", "ALL", 0.4f,
            "RU: Suspicious login attempt",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ваш (аккаунт|учётная запись)|учётную запись) (будет|может быть) (удалён|заблокирован|приостановлен)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RU", "ALL", 0.35f,
            "RU: Account will be deleted/blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(посылка|отправление).{0,20}(не доставлен|ожидает|задержан|оплат|доплат)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RU", "ALL", 0.35f,
            "RU: Package delivery phishing",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(почта россии|сдэк|cdek|boxberry|ozon|wildberries).{0,25}(не доставлен|оплат|доплат|подтверд|проблем)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RU", "ALL", 0.35f,
            "RU: Russian courier/marketplace phishing",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(госуслуги|mos\\.?ru|мос\\.?ру).{0,25}(обновите|подтвердите|верифи|истекает|заблокирован)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RU", "ALL", 0.4f,
            "RU: Gosuslugi/mos.ru phishing",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(пришли|отправь|переведи|скинь|перекинь).{0,20}(деньги|денег|рублей|руб|средства)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RU", "ALL", 0.35f,
            "RU: Send money/transfer request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(срочно|немедленно|как можно скорее|быстро|скорее).{0,20}(пришли|отправь|переведи|скинь|нужны)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RU", "ALL", 0.4f,
            "RU: Urgent money request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bнужны.{0,20}(деньги|денег|средства|помощь финансовая|в долг)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RU", "ALL", 0.3f,
            "RU: I need money/loan",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(переведи|отправь|скинь).{0,15}на (карту|счёт|счет|номер)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RU", "ALL", 0.35f,
            "RU: Transfer to card/account",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(одолжи|дай в долг|займи).{0,15}(до зарплаты|до понедельника|на пару дней|ненадолго)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RU", "ALL", 0.3f,
            "RU: Lend me money until payday",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(мам|пап|бабушк|бабуль|дедушк|дедуль|сынок|дочк|внучок|внученьк).{0,30}(сменил|новый номер|пишу с нового|это я)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RU", "ALL", 0.4f,
            "RU: Family member changed number (мам/пап/бабушка)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(сменил номер|у меня новый номер|пишу с другого (телефона|номера))", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RU", "ALL", 0.35f,
            "RU: I changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(попал в (аварию|дтп)|в больнице|нужна помощь|что-то случилось|меня задержали)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RU", "ALL", 0.3f,
            "RU: Emergency - accident/hospital/detained",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(это я|это твой|это твоя|не узнаёшь|не узнаешь).{0,20}(сын|дочь|дочка|внук|внучка|брат|сестра|племянник)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RU", "ALL", 0.35f,
            "RU: It's me, your son/daughter/grandchild",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(начальник|директор|руководитель|шеф).{0,20}(просил|поручил|срочное дело|нужна помощь|переведи)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RU", "ALL", 0.35f,
            "RU: Boss/director impersonation",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(фнс|федеральная налоговая|налоговая служба|налоговая).{0,30}(задолженность|долг|штраф|пеня|проверка|блокировка)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RU", "ALL", 0.4f,
            "RU: FNS (tax service) debt/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(мвд|полиция|следственный комитет|прокуратура|фсб).{0,25}(вызов|повестка|дело|расследовани|уголовн|задержани|допрос)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RU", "ALL", 0.4f,
            "RU: MVD/police/FSB investigation summons",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(суд|судебный пристав|фссп).{0,25}(задолженность|штраф|взыскание|исполнительн|арест|запрет)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RU", "ALL", 0.4f,
            "RU: Court/bailiff debt enforcement",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(вам грозит|грозит вам|угроза) (арест|задержание|штраф|конфискация|уголовное|срок)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RU", "ALL", 0.4f,
            "RU: Threat of arrest/criminal penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(госуслуги|единый портал|есиа).{0,20}(истекает|обновите|подтвердите|заблокирован)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RU", "ALL", 0.35f,
            "RU: Gosuslugi (government portal) verification",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(пенсионный фонд|пфр|соцзащита|социальная защита).{0,25}(проверка|выплата|задолженность|обновление данных|перерасчёт)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RU", "ALL", 0.35f,
            "RU: Pension fund / social services fraud",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bцентральный банк.{0,25}(предупрежда|информиру|заблокиров|проверк|безопасност)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RU", "ALL", 0.35f,
            "RU: Central Bank impersonation",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(биткоин|биткойн|btc|эфириум|eth|крипто|usdt|binance).{0,20}(инвестиц|возможност|прибыл|заработ|удвоит|утроит)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "RU", "ALL", 0.4f,
            "RU: Crypto investment opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(зарабатывай|заработок|прибыль|доход).{0,15}(пассивн|из дома|без работы|лёгк|легк|гарантирован)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "RU", "ALL", 0.35f,
            "RU: Passive income/easy money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(удвоить|утроить|приумножить).{0,15}(свои|ваши) (деньги|инвестиции|капитал|средства)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "RU", "ALL", 0.4f,
            "RU: Double/triple your money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(платформа|приложение).{0,15}(инвестиционн|для инвестиций|для трейдинга|для заработка)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "RU", "ALL", 0.25f,
            "RU: Investment platform/app",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(seed фраза|сид фраза|мнемоническая фраза|приватный ключ|закрытый ключ).{0,10}(отправ|введ|сообщ|поделитесь)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "RU", "ALL", 0.45f,
            "RU: Seed phrase / private key request",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ваш|твой) (компьютер|телефон|устройство).{0,20}(заражён|заражен|вирус|взломан|под угрозой|вредоносн)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "RU", "ALL", 0.4f,
            "RU: Your device is infected/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(техподдержка|служба поддержки|техническая поддержка).{0,20}(microsoft|apple|google|windows|samsung)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "RU", "ALL", 0.35f,
            "RU: Tech support impersonation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(установите|скачайте|загрузите).{0,15}(приложение|программу).{0,15}(удалённ|помощ|teamviewer|anydesk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "RU", "ALL", 0.4f,
            "RU: Install remote access software",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(я (военный|солдат|инженер|врач|пилот|моряк)).{0,20}(за границей|в ираке|в афганистане|на миссии|на платформе)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RU", "ALL", 0.4f,
            "RU: Military/engineer abroad (romance scam)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(люблю тебя|ты любовь моей жизни|ты моя родная душа|судьба нас свела|бог нас свёл)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RU", "ALL", 0.3f,
            "RU: Love declaration / destiny",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(нужны деньги|финансовая помощь).{0,15}(на (билет|самолёт|визу|больницу|операцию|лечение))", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RU", "ALL", 0.4f,
            "RU: Need money for travel/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(вдова|вдовец|разведён|разведена|одинок).{0,15}(ищу|хочу найти) (любовь|пару|спутника|спутницу|вторую половинку)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RU", "ALL", 0.3f,
            "RU: Widow/divorced looking for love",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(не (говори|рассказывай|сообщай)).{0,15}(семье|детям|никому|близким)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RU", "ALL", 0.35f,
            "RU: Don't tell your family",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(наследство|состояние|завещание).{0,20}(миллион|доллар|евро|поделиться|нужна ваша помощь)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RU", "ALL", 0.4f,
            "RU: Inheritance to share",
        ))
    }

    // ══════════════════════════════════════════════════════════════════════
    //  TURKISH (TR)
    // ══════════════════════════════════════════════════════════════════════

    private fun turkishRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(hesabınız|kartınız).{0,30}(bloke|askıya alın|donduruldu|kapatıldı|kısıtlandı)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.4f,
            "TR: Account/card blocked/suspended",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ziraat|ziraat bankası).{0,25}(bloke|askıya|doğrulama|onaylama|güncelleme|güvenlik)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.4f,
            "TR: Ziraat Bankası fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(iş bankası|işbank|türkiye iş).{0,25}(bloke|askıya|doğrulama|onaylama|güncelleme|güvenlik)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.4f,
            "TR: İş Bankası fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(garanti|garanti bbva).{0,25}(bloke|askıya|doğrulama|onaylama|güncelleme|güvenlik)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.4f,
            "TR: Garanti BBVA fraud alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(akbank|yapı kredi|yapıkredi|halkbank|vakıfbank|denizbank|finansbank|teb|şekerbank).{0,25}(bloke|askıya|doğrulama|onaylama|güncelleme)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.4f,
            "TR: Turkish bank fraud alert (Akbank, Yapı Kredi, etc.)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(papara|ininal|tosla|param).{0,20}(bloke|askıya|doğrulama|onaylama|sorun|şüpheli)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.35f,
            "TR: Papara/Ininal/Tosla fraud",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(girin|yazın|gönderin|iletin|bildirin).{0,20}(şifre|pin|sms kod|onay kodu|kart numarası|cvv|güvenlik kodu|cvc)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.45f,
            "TR: Request for PIN/password/CVV/SMS code",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(şüpheli|yetkisiz|bilinmeyen|tanınmayan) (işlem|ödeme|transfer|harcama|çekim)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.4f,
            "TR: Suspicious/unauthorized transaction",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\btespit edil.{0,25}(yetkisiz|şüpheli|bilinmeyen).{0,15}(erişim|giriş|işlem|çekim|transfer)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.4f,
            "TR: Unauthorized access/transaction detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bkartınız.{0,20}(ele geçirildi|klonlandı|çalındı|kopyalandı)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.4f,
            "TR: Card compromised/cloned/stolen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(paranız|hesabınızdaki para|birikimleriniz|bakiyeniz).{0,20}(tehlikede|risk altında|tehdit altında)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.35f,
            "TR: Your money/savings are at risk",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bloke|kapatılma|dondurulma|kayıp).{0,15}(önlemek|engellemek) için", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TR", "ALL", 0.35f,
            "TR: To avoid blocking/loss of funds",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kazandınız|size (çıktı|düştü)).{0,20}(ödül|hediye|para|tl|lira|çekiliş)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "TR", "ALL", 0.4f,
            "TR: You won a prize/reward",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\btebrikler.{0,25}(kazandınız|ödül|hediye|çekiliş|şanslı)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "TR", "ALL", 0.4f,
            "TR: Congratulations on winning",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(alın|teslim alın|talep edin).{0,20}(ödülünüz|hediyeniz|kazancınız|bonusunuz)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "TR", "ALL", 0.4f,
            "TR: Claim your prize/reward",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(seçildiniz|siz seçildiniz|kazanan siz oldunuz|şanslı kişi siz)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "TR", "ALL", 0.35f,
            "TR: You have been selected/chosen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kupon|hediye çeki|indirim kodu).{0,15}(\\d+\\s*tl|\\d+\\s*lira|bedava|ücretsiz|hemen al)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "TR", "ALL", 0.35f,
            "TR: Free voucher/coupon",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(tıklayın|girin|basın|açın).{0,15}(linke|bağlantıya|buraya|aşağıda|şuraya)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "TR", "ALL", 0.3f,
            "TR: Click this link",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(doğrulayın|onaylayın|güncelleyin).{0,20}(hesabınızı|bilgilerinizi|kimliğinizi|profilinizi)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "TR", "ALL", 0.35f,
            "TR: Verify/update your account/data",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bşüpheli (giriş|oturum açma|erişim).{0,20}(hesabınız|tespit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "TR", "ALL", 0.4f,
            "TR: Suspicious login attempt",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(hesabınız) (silinecek|kapatılacak|askıya alınacak|bloke edilecek)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "TR", "ALL", 0.35f,
            "TR: Account will be deleted/blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kargo|paket|gönderi).{0,20}(teslim edilemedi|bekliyor|beklemede|ödeme|ek ücret)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "TR", "ALL", 0.35f,
            "TR: Package delivery phishing",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ptt|yurtiçi kargo|aras kargo|mng|sürat kargo|trendyol|hepsiburada).{0,25}(teslim edilemedi|ödeme|onaylayın|sorun)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "TR", "ALL", 0.35f,
            "TR: Turkish courier/marketplace phishing",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(gönder|yolla|havale yap|transfer et|aktar).{0,20}(para|parayı|tl|lira)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "TR", "ALL", 0.35f,
            "TR: Send money/transfer request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(acil|hemen|derhal|bir an önce|acilen).{0,20}(gönder|yolla|havale|transfer|lazım|ihtiyacım)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "TR", "ALL", 0.4f,
            "TR: Urgent money request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(paraya ihtiyacım var|bana para lazım|borç ver|ödünç ver|maddi yardım)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "TR", "ALL", 0.3f,
            "TR: I need money/loan",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(havale yap|gönder|yolla).{0,15}(hesaba|iban|hesap numarası)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "TR", "ALL", 0.35f,
            "TR: Transfer to account/IBAN",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(anne|baba|anneciğim|babacığım|oğlum|kızım|torunum|abla|abi).{0,30}(değiştirdim|yeni numara|başka numaradan|benim)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "TR", "ALL", 0.4f,
            "TR: Family member changed number (anne/baba)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(numaramı değiştirdim|yeni numaram|başka telefondan yazıyorum|başka numaradan arıyorum)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "TR", "ALL", 0.35f,
            "TR: I changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kaza geçirdim|hastanedeyim|yardım lazım|başıma bir şey geldi|beni tutukladılar)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "TR", "ALL", 0.3f,
            "TR: Emergency - accident/hospital/detained",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(benim|ben senin|tanımadın mı|tanıyamadın mı).{0,20}(oğlun|kızın|torunun|kardeşin|yeğenin)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "TR", "ALL", 0.35f,
            "TR: It's me, your son/daughter/grandchild",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(e-devlet|e devlet|turkiye\\.gov|türkiye\\.gov).{0,25}(doğrulayın|onaylayın|güncelleyin|süresi doldu|bloke)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "TR", "ALL", 0.4f,
            "TR: e-Devlet (government portal) verification",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(sgk|sosyal güvenlik).{0,30}(borç|ceza|prim|ödeme|bloke|güncelleme)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "TR", "ALL", 0.4f,
            "TR: SGK (social security) debt/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(gelir idaresi|vergi dairesi|gib|maliye).{0,30}(borç|ceza|vergi|ödeme|haciz|bloke)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "TR", "ALL", 0.4f,
            "TR: Tax authority debt/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(polis|jandarma|savcılık|mahkeme|icra).{0,25}(çağrı|celp|ceza|dava|soruşturma|tutuklama|haciz)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "TR", "ALL", 0.35f,
            "TR: Police/court/prosecution summons",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(tutuklanacaksınız|gözaltına alınacaksınız|ceza kesilecek|hapis|size dava açıldı)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "TR", "ALL", 0.4f,
            "TR: Threat of arrest/prosecution",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(e-imza|e imza|mobil imza|kimlik doğrulama).{0,20}(süresi doldu|güncelleyin|yenileyin|bloke)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "TR", "ALL", 0.35f,
            "TR: Digital signature verification",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bitcoin|btc|ethereum|eth|kripto|usdt|binance).{0,20}(yatırım|fırsat|kâr|kazanç|kazan|ikiye katla|üçe katla)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "TR", "ALL", 0.4f,
            "TR: Crypto investment opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kazan|kazanç|gelir|kâr).{0,15}(pasif|evden|işsiz|kolay|garanti)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "TR", "ALL", 0.35f,
            "TR: Passive income/easy money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ikiye katla|üçe katla|çoğalt).{0,15}(paranızı|yatırımınızı|sermayenizi)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "TR", "ALL", 0.4f,
            "TR: Double/triple your money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(platform|uygulama).{0,15}(yatırım|trading|kripto|kazanç)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "TR", "ALL", 0.25f,
            "TR: Investment platform/app",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(seed ifade|özel anahtar|cüzdan anahtarı).{0,10}(gönder|gir|paylaş|yaz)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "TR", "ALL", 0.45f,
            "TR: Seed phrase / private key request",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bilgisayarınız|telefonunuz|cihazınız).{0,20}(virüs|enfekte|hacklen|ele geçiril|tehlikede|zararlı)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "TR", "ALL", 0.4f,
            "TR: Your device is infected/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(teknik destek|müşteri hizmetleri).{0,20}(microsoft|apple|google|windows|samsung)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "TR", "ALL", 0.35f,
            "TR: Tech support impersonation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kurun|indirin|yükleyin).{0,15}(uygulama|program|yazılım).{0,15}(uzaktan|yardım|teamviewer|anydesk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "TR", "ALL", 0.4f,
            "TR: Install remote access software",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ben (asker|subay|mühendis|doktor|pilot|denizci)im).{0,20}(yurt dışında|irak'ta|afganistan'da|görevde|platformda)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "TR", "ALL", 0.4f,
            "TR: Military/engineer abroad (romance scam)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(seni seviyorum|hayatımın aşkı|ruh eşim|kader bizi|allah bizi).{0,15}(birleştirdi|kavuşturdu|bir araya getirdi)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "TR", "ALL", 0.3f,
            "TR: Love declaration / destiny",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(paraya ihtiyacım|maddi yardım).{0,15}((uçak |uçuş )?bileti|vize|hastane|ameliyat|tedavi) için", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "TR", "ALL", 0.4f,
            "TR: Need money for travel/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(dul|boşanmış|yalnız).{0,15}(arıyorum|istiyorum) (aşk|eş|hayat arkadaşı|biri)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "TR", "ALL", 0.3f,
            "TR: Widow/divorced looking for love",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ailene|çocuklarına|kimseye) (söyleme|anlatma|bahsetme)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "TR", "ALL", 0.35f,
            "TR: Don't tell your family",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(miras|servet|vasiyet).{0,20}(milyon|dolar|euro|paylaşmak|yardımınız lazım)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "TR", "ALL", 0.4f,
            "TR: Inheritance to share",
        ))
    }
}
