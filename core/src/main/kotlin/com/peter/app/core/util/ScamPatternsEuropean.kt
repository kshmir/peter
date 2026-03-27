package com.peter.app.core.util

/**
 * Scam detection patterns for European languages:
 * French (FR), Italian (IT), Romanian (RO), German (DE), Dutch (NL)
 *
 * Coverage:
 * - French: France, Belgium, Switzerland, Quebec, West/Central Africa
 * - Italian: Italy, Swiss Italian
 * - Romanian: Romania, Moldova
 * - German: Germany, Austria, Switzerland
 * - Dutch: Netherlands, Belgium (Flanders)
 */
internal object ScamPatternsEuropean {

    fun allRules(): List<ScamPatternDetector.PatternRule> = buildList {
        // French
        addAll(frenchRules())
        // Italian
        addAll(italianRules())
        // Romanian
        addAll(romanianRules())
        // German
        addAll(germanRules())
        // Dutch
        addAll(dutchRules())
    }

    // ──────────────────────────────────────────────────────────────────
    // FRENCH (FR)
    // Covers: France, Belgium, Switzerland, Quebec, West/Central Africa
    // ──────────────────────────────────────────────────────────────────

    private fun frenchRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(votre|ton) (compte|carte).{0,30}(suspendu|bloqu[eé]|annul[eé]|ferm[eé]|d[eé]sactiv[eé])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "ALL", 0.4f,
            "FR: Account/card suspended/blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bbanque.{0,25}(bloqu|suspend|v[eé]rifi|mettre [àa] jour|confirm)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "ALL", 0.35f,
            "FR: Bank action required",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(v[eé]rifier|confirmer|mettre [àa] jour).{0,20}(donn[eé]es bancaires|informations bancaires|compte bancaire|coordonn[eé]es bancaires)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "ALL", 0.4f,
            "FR: Verify/update banking information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bcarte.{0,20}(expir[eé]e|compromis|clon[eé]e|vol[eé]e|pirat[eé]e)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "ALL", 0.35f,
            "FR: Card compromised/stolen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(transaction|op[eé]ration|mouvement).{0,15}(suspect|inhabituel|non autoris[eé]|frauduleu)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "ALL", 0.4f,
            "FR: Suspicious/unauthorized transaction",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(saisissez|fournissez|communiquez|entrez).{0,20}(code|mot de passe|pin|identifiant|num[eé]ro de carte|cvv|code secret)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "ALL", 0.45f,
            "FR: Request for credentials/PIN/CVV",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(votre|ton) (argent|fonds|[eé]pargne|solde).{0,20}(risque|danger|compromis|menac[eé])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "ALL", 0.35f,
            "FR: Your money is at risk",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(cr[eé]dit agricole|bnp paribas|soci[eé]t[eé] g[eé]n[eé]rale|la banque postale|caisse d'[eé]pargne|lcl|cic|boursorama|ing|fortuneo|hello bank|cr[eé]dit mutuel)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "FR", 0.2f,
            "FR-FR: French bank name",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(lydia|paylib|paypal|orange money).{0,20}(bloqu|suspend|v[eé]rifi|probl[eèe]me|compromis|pirat)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "ALL", 0.35f,
            "FR: Payment app fraud (Lydia/Paylib)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bnous avons d[eé]tect[eé].{0,30}(activit[eé]|transaction|acc[eèe]s|connexion).{0,20}(suspect|inhabituel|anormal)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "ALL", 0.4f,
            "FR: We detected suspicious activity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bpour [eé]viter.{0,20}(blocage|suspension|fermeture|annulation|d[eé]sactivation)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "ALL", 0.35f,
            "FR: To avoid blocking/cancellation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(belfius|kbc|ing|bnp paribas fortis|argenta|beobank|axa banque)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "BE", 0.2f,
            "FR-BE: Belgian bank name",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ubs|credit suisse|postfinance|raiffeisen|bcv|bcge)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "FR", "CH", 0.2f,
            "FR-CH: Swiss bank name",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(vous avez gagn[eé]|tu as gagn[eé]|f[eé]licitations|bravo).{0,30}(prix|lot|cadeau|prime|r[eé]compense)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "FR", "ALL", 0.4f,
            "FR: You won / congratulations + prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(loterie|tirage au sort|tombola|jeu concours).{0,20}(gagn[eé]|s[eé]lectionn[eé]|gagnant|vainqueur)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "FR", "ALL", 0.45f,
            "FR: Lottery/raffle won",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(r[eé]clamer|retirer|collecter|obtenir).{0,20}(prix|lot|gain|r[eé]compense|cadeau)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "FR", "ALL", 0.4f,
            "FR: Claim your prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(iphone|samsung|t[eé]l[eé]viseur|voiture|voyage|billet d'avion).{0,20}(gratuit|gagn[eé]|offert|cadeau)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "FR", "ALL", 0.35f,
            "FR: Product giveaway",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bon d'achat|coupon|ch[eèe]que cadeau|voucher).{0,20}(gratuit|offert|gagn[eé]|exclusi)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "FR", "ALL", 0.3f,
            "FR: Free voucher/coupon",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(whatsapp|facebook|instagram|google|amazon|carrefour|auchan|leclerc|lidl).{0,20}(tirage|concours|prix|offre|cadeau|anniversaire)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "FR", "ALL", 0.4f,
            "FR: Brand giveaway scam",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\bcliquez.{0,10}(ici|sur ce lien|imm[eé]diatement|vite|rapidement|maintenant)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "FR", "ALL", 0.35f,
            "FR: Click here urgently",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(v[eé]rifiez|confirmez).{0,15}(votre|ton) (compte|identit[eé]|adresse|profil|acc[eèe]s)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "FR", "ALL", 0.35f,
            "FR: Verify your account/identity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(connexion|acc[eèe]s).{0,15}(suspect|inhabituel|non autoris[eé]|depuis un autre|nouveau)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "FR", "ALL", 0.35f,
            "FR: Suspicious login detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(expire|expiration|d[eé]lai|limite).{0,15}(dans \\d+|aujourd'hui|ce soir|demain|bient[oô]t|heures)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "FR", "ALL", 0.3f,
            "FR: Expiring/limited time",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mettez [àa] jour|actualisez|renouvelez).{0,20}(vos informations|vos donn[eé]es|votre mot de passe|votre profil)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "FR", "ALL", 0.35f,
            "FR: Update your information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bvotre (compte|acc[eèe]s|profil) (sera|va [eê]tre) (supprim[eé]|ferm[eé]|d[eé]sactiv[eé])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "FR", "ALL", 0.4f,
            "FR: Account will be deleted/closed",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(colis|livraison|la poste|chronopost|colissimo|ups|dhl|dpd).{0,20}(en attente|bloqu[eé]|probl[eèe]me|frais|payer)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "FR", "ALL", 0.35f,
            "FR: Package delivery scam",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(envoie|transf[eèe]re|vire|fais).{0,15}(moi|nous|lui|leur).{0,15}(de l'argent|des sous|la somme|un virement|un mandat)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "FR", "ALL", 0.35f,
            "FR: Send me money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(j'ai besoin|il me faut|je dois avoir).{0,15}(d'argent|des sous|de fonds|de thunes) (urgent|vite|tout de suite|rapidement)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "FR", "ALL", 0.4f,
            "FR: I need money urgently",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(carte cadeau|bon cadeau|recharge|pcs|transcash|n[eé]osurf|coupon|steam|google play|itunes|apple).{0,15}(achet|envoi|code)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "FR", "ALL", 0.4f,
            "FR: Gift card / prepaid card request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(rib|iban|num[eé]ro de compte|bic|swift).{0,15}(voici|envoie|transf[eèe]re [àa]|sur ce)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "FR", "ALL", 0.35f,
            "FR: Transfer to this account (RIB/IBAN)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(western union|moneygram|mandat cash|wari|orange money|mtn money|wave).{0,15}(envoi|transf[eèe]r|fais)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "FR", "ALL", 0.4f,
            "FR: Money transfer service request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(pr[eê]te|avance|d[eé]panne).{0,10}(moi|nous).{0,15}(\\d+|argent|euros|sous|thunes)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "FR", "ALL", 0.3f,
            "FR: Lend me money",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(maman|mamie|m[eè]re|grand-m[eèe]re) c'est moi", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "FR", "ALL", 0.45f,
            "FR: Maman c'est moi (classic impersonation)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(salut|coucou|bonjour|hey).{0,10}(j'ai chang[eé]|j'ai un nouveau) (de|mon|le|un) (num[eé]ro|t[eé]l[eé]phone|portable)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "FR", "ALL", 0.4f,
            "FR: I changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(c'est|je suis) (ton|ta|votre) (fils|fille|petit-fils|petite-fille|neveu|ni[eèe]ce|cousin|cousine)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "FR", "ALL", 0.35f,
            "FR: I am your son/daughter/grandchild",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(on m'a vol[eé]|j'ai perdu|j'ai cass[eé]) (mon|le) (t[eé]l[eé]phone|portable|mobile)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "FR", "ALL", 0.3f,
            "FR: My phone was stolen/lost",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(voici|c'est) mon nouveau (num[eé]ro|t[eé]l[eé]phone|portable|contact)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "FR", "ALL", 0.35f,
            "FR: This is my new number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(enregistre|note|sauvegarde) (ce|mon) (nouveau )?(num[eé]ro|contact)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "FR", "ALL", 0.3f,
            "FR: Save my new number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ne dis rien [àa] personne|entre nous|c'est un secret|n'en parle [àa] personne|garde [çc]a pour toi)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "FR", "ALL", 0.35f,
            "FR: Don't tell anyone (secrecy pressure)",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(imp[oô]ts|direction g[eé]n[eé]rale des finances|tr[eé]sor public|dgfip|fisc)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "FR", "FR", 0.2f,
            "FR-FR: French tax authority mention",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(imp[oô]ts|dgfip|fisc).{0,40}(dette|amende|p[eé]nalit[eé]|remboursement|r[eé]gularisation|mise en demeure)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "FR", "FR", 0.4f,
            "FR-FR: Tax debt/penalty/refund",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(police|gendarmerie|tribunal|procureur|pr[eé]fecture|justice).{0,20}(convocation|amende|plainte|proc[eèe]s|poursuite|mandat|arrestation)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "FR", "ALL", 0.35f,
            "FR: Police/court legal action",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(carte vitale|ameli|s[eé]cu|caf|p[oô]le emploi|cpam|france connect).{0,20}(expir|renouvel|mettre [àa] jour|activ|bloqu|suspend)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "FR", "FR", 0.35f,
            "FR-FR: Social security/benefits renewal",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(amende|contravention|pv|proc[eèe]s[ -]verbal).{0,20}(impay[eé]|payer|r[eé]gler|en ligne)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "FR", "ALL", 0.35f,
            "FR: Unpaid fine/ticket",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(vous [eê]tes convoqu[eé]|vous risquez|vous serez poursuivi|proc[eé]dure judiciaire|mandat d'arr[eê]t)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "FR", "ALL", 0.4f,
            "FR: Summons/arrest threat",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bitcoin|btc|ethereum|eth|crypto|cryptomonnaie|usdt|binance).{0,20}(investir|opportunit[eé]|gain|rendement|rentabilit[eé]|doubler|tripler)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "FR", "ALL", 0.4f,
            "FR: Crypto investment opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(gagner|obtenir|g[eé]n[eé]rer).{0,15}(bitcoin|crypto|argent facile|revenus passifs|argent depuis chez vous)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "FR", "ALL", 0.35f,
            "FR: Earn crypto/easy money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(doubler|tripler|multiplier|d[eé]cupler).{0,15}(votre|ton) (argent|investissement|capital|mise)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "FR", "ALL", 0.4f,
            "FR: Double/triple your money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(rendement|retour|gain|b[eé]n[eé]fice).{0,15}(\\d+%|garanti|assur[eé]|certain)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "FR", "ALL", 0.4f,
            "FR: Guaranteed returns",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(trading|forex|options binaires|march[eé] boursier).{0,20}(gagner|gain|opportunit[eé]|signal|signaux)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "FR", "ALL", 0.35f,
            "FR: Trading/forex opportunity",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(votre|ton) (appareil|t[eé]l[eé]phone|ordinateur|pc|portable).{0,20}(infect[eé]|virus|pirat[eé]|compromis|menac[eé]|danger)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "FR", "ALL", 0.4f,
            "FR: Your device is infected/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(virus|malware|trojan|spyware|logiciel malveillant).{0,20}(d[eé]tect[eé]|trouv[eé]|votre|ton|dans)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "FR", "ALL", 0.35f,
            "FR: Virus/malware detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(appelez|contactez|joignez).{0,15}(support|assistance|service technique|aide technique|service client)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "FR", "ALL", 0.3f,
            "FR: Call tech support",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(acc[eèe]s [àa] distance|teamviewer|anydesk|quicksupport).{0,15}(installer|t[eé]l[eé]charger|autoriser|donner l'acc[eèe]s)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "FR", "ALL", 0.45f,
            "FR: Remote access request",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(je suis|je travaille comme).{0,10}(militaire|soldat|ing[eé]nieur|m[eé]decin|docteur|pilote|marin).{0,20}(en|[àa]|au|du) (l'[eé]tranger|irak|afghanistan|syrie|plateforme|navire|base)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "FR", "ALL", 0.4f,
            "FR: Military/engineer abroad (classic romance scam)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(je t'aime|tu es l'amour de ma vie|tu es mon [aâ]me s[oœ]ur|tu es sp[eé]cial).{0,20}(depuis que je t'ai vu|depuis le premier moment|jamais ressenti [çc]a)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "FR", "ALL", 0.3f,
            "FR: Love declaration from unknown",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(h[eé]ritage|fortune|testament).{0,20}(millions|euros|dollars|partager avec toi|besoin de ton aide)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "FR", "ALL", 0.4f,
            "FR: Inheritance to share",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(veuve|veuf|divorc[eé]e?|seul[e]?).{0,15}(cherche|recherche|besoin de) (compagnie|amour|partenaire|quelqu'un de sp[eé]cial)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "FR", "ALL", 0.3f,
            "FR: Widow/divorced looking for love",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mon (ch[eé]ri|amour|c[oœ]ur|b[eé]b[eé]|tr[eé]sor|ange)).{0,25}(envoie|aide|besoin|urgent|argent|transfert)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "FR", "ALL", 0.35f,
            "FR: Pet name + money/help request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(dieu|le destin|l'univers).{0,15}(nous a r[eé]unis|t'a mis sur mon chemin|veut qu'on soit ensemble)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "FR", "ALL", 0.3f,
            "FR: God/destiny brought us together",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // ITALIAN (IT)
    // Covers: Italy, Swiss Italian
    // ──────────────────────────────────────────────────────────────────

    private fun italianRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(il tuo|il suo|il vostro) (conto|carta).{0,30}(sospeso|bloccato|annullato|chiuso|disattivato)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "ALL", 0.4f,
            "IT: Account/card suspended/blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bbanca.{0,25}(blocc|sospe|verific|aggiorn|conferm)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "ALL", 0.35f,
            "IT: Bank action required",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verificare|confermare|aggiornare).{0,20}(dati bancari|informazioni bancarie|conto bancario|credenziali)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "ALL", 0.4f,
            "IT: Verify/update banking information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bcarta.{0,20}(scadut|compromess|clonat|rubat|hackerata)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "ALL", 0.35f,
            "IT: Card compromised/stolen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(transazione|operazione|movimento).{0,15}(sospett|insolito|non autorizzat|fraudolent)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "ALL", 0.4f,
            "IT: Suspicious/unauthorized transaction",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(inserisci|fornisci|comunica|inserire).{0,20}(codice|password|pin|numero di carta|cvv|otp|token)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "ALL", 0.45f,
            "IT: Request for credentials/PIN/CVV",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(il tuo|il suo) (denaro|fondi|risparmi|saldo).{0,20}(rischio|pericolo|compromess|minacci)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "ALL", 0.35f,
            "IT: Your money is at risk",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(intesa sanpaolo|unicredit|banca mediolanum|monte dei paschi|bnl|bper|banco bpm|poste italiane|postepay|bancoposta)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "IT", 0.2f,
            "IT-IT: Italian bank name",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(postepay|bancomat|satispay|nexi|pagopa).{0,20}(blocc|sospes|verific|problem|compromess|hacker)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "IT", 0.35f,
            "IT-IT: Payment app fraud (PostePay/Bancomat/Satispay)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\babbiamo (rilevato|riscontrato|individuato).{0,30}(attivit[àa]|transazione|accesso|operazione).{0,20}(sospett|anomal|insolit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "ALL", 0.4f,
            "IT: We detected suspicious activity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bper evitare.{0,20}(blocco|sospensione|chiusura|annullamento|disattivazione)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "ALL", 0.35f,
            "IT: To avoid blocking/cancellation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(il tuo|il suo) (conto|carta) (sar[àa]|verr[àa]|[eè] stato|[eè] stata) (bloccato|sospeso|chiuso|annullato)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "IT", "ALL", 0.4f,
            "IT: Account will be/was blocked",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(hai vinto|ha vinto|sei stato selezionato|congratulazioni|complimenti).{0,30}(premio|omaggio|regalo|ricompensa)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "IT", "ALL", 0.4f,
            "IT: You won / congratulations + prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(lotteria|estrazione|sorteggio|concorso a premi).{0,20}(vinto|selezionat|vincitor|vincitrice)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "IT", "ALL", 0.45f,
            "IT: Lottery/raffle won",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(riscuotere|ritirare|reclamare|richiedere).{0,20}(premio|vincita|ricompensa|omaggio|regalo)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "IT", "ALL", 0.4f,
            "IT: Claim your prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(iphone|samsung|televisore|auto|macchina|viaggio|volo|crociera).{0,20}(gratis|vinto|premio|sorteggio|regalo|omaggio)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "IT", "ALL", 0.35f,
            "IT: Product giveaway",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(buono|voucher|coupon|buono regalo|buono sconto).{0,20}(gratis|omaggio|vinto|esclusiv)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "IT", "ALL", 0.3f,
            "IT: Free voucher/coupon",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(whatsapp|facebook|instagram|google|amazon|esselunga|conad|lidl|coop).{0,20}(sorteggio|concorso|premio|offerta|regalo|anniversario)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "IT", "ALL", 0.4f,
            "IT: Brand giveaway scam",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\bclicca.{0,10}(qui|sul link|subito|immediatamente|ora|adesso)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "IT", "ALL", 0.35f,
            "IT: Click here urgently",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verifica|conferma).{0,15}(il tuo|il suo|la tua|la sua) (conto|identit[àa]|profilo|accesso|indirizzo)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "IT", "ALL", 0.35f,
            "IT: Verify your account/identity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(accesso|login).{0,15}(sospetto|insolito|non autorizzato|da un altro|nuovo)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "IT", "ALL", 0.35f,
            "IT: Suspicious login detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(scade|scadenza|termine|limite).{0,15}(tra \\d+|oggi|stasera|domani|a breve|ore)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "IT", "ALL", 0.3f,
            "IT: Expiring/limited time",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(aggiorna|aggiornare|rinnova|rinnovare).{0,20}(le tue informazioni|i tuoi dati|la tua password|il tuo profilo)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "IT", "ALL", 0.35f,
            "IT: Update your information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(il tuo|il suo) (conto|accesso|profilo) (sar[àa]|verr[àa]) (eliminato|chiuso|disattivato|cancellato)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "IT", "ALL", 0.4f,
            "IT: Account will be deleted/closed",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(pacco|spedizione|consegna|poste|bartolini|brt|gls|sda|dhl|ups).{0,20}(in attesa|bloccato|problema|spese|pagare)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "IT", "ALL", 0.35f,
            "IT: Package delivery scam",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(inviami|trasferisci|mandami|fai un).{0,15}(dei soldi|denaro|la somma|un bonifico|un versamento)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "IT", "ALL", 0.35f,
            "IT: Send me money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ho bisogno|mi serve|devo avere).{0,15}(di soldi|di denaro|dei fondi) (urgente|subito|adesso|immediatamente)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "IT", "ALL", 0.4f,
            "IT: I need money urgently",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(carta regalo|buono regalo|ricarica|paysafecard|steam|google play|itunes|apple).{0,15}(compra|invia|codice)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "IT", "ALL", 0.4f,
            "IT: Gift card request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(iban|codice conto|bonifico|bic|swift).{0,15}(ecco|invia|trasferisci a|su questo)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "IT", "ALL", 0.35f,
            "IT: Transfer to this account (IBAN)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(western union|moneygram|postepay).{0,15}(invia|trasfer|manda|fai)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "IT", "ALL", 0.4f,
            "IT: Money transfer service request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(prestami|anticipami|passami).{0,15}(\\d+|soldi|euro|denaro)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "IT", "ALL", 0.3f,
            "IT: Lend me money",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mamma|mammina|nonna|nonnina|madre) sono io", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "IT", "ALL", 0.45f,
            "IT: Mamma sono io (classic impersonation)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ciao|ehi|salve|buongiorno).{0,10}(ho cambiato|ho un nuovo) (il mio|il|un) (numero|telefono|cellulare)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "IT", "ALL", 0.4f,
            "IT: I changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(sono|io sono) (tuo|tua|vostro|vostra) (figlio|figlia|nipote|cugino|cugina)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "IT", "ALL", 0.35f,
            "IT: I am your son/daughter/grandchild",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mi hanno rubato|ho perso|ho rotto|si [eè] rotto) il (telefono|cellulare|telefonino)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "IT", "ALL", 0.3f,
            "IT: My phone was stolen/lost",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(questo [eè]|ecco) il mio nuovo (numero|telefono|cellulare|contatto)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "IT", "ALL", 0.35f,
            "IT: This is my new number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(non dire niente a nessuno|tra di noi|[eè] un segreto|non parlarne con nessuno|tienilo per te)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "IT", "ALL", 0.35f,
            "IT: Don't tell anyone (secrecy pressure)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(salva|segna|memorizza) (questo|il mio) (nuovo )?(numero|contatto)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "IT", "ALL", 0.3f,
            "IT: Save my new number",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(agenzia delle entrate|guardia di finanza|inps|equitalia|agenzia riscossione|fisco)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "IT", "IT", 0.2f,
            "IT-IT: Italian tax/fiscal authority",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(agenzia delle entrate|guardia di finanza|fisco).{0,40}(debito|multa|sanzione|cartella|irregolarit[àa]|accertamento)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "IT", "IT", 0.4f,
            "IT-IT: Tax debt/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(polizia|carabinieri|tribunale|procura|questura|prefettura).{0,20}(denuncia|convocazione|ordine|mandato|arresto|procedimento)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "IT", "ALL", 0.35f,
            "IT: Police/court legal action",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(spid|carta d'identit[àa]|tessera sanitaria|codice fiscale|inps).{0,20}(scadut|rinnov|aggiorn|attiv|bloccat|sospes)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "IT", "IT", 0.35f,
            "IT-IT: SPID/ID/INPS renewal",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(multa|contravvenzione|verbale|sanzione).{0,20}(non pagat|pagare|saldare|online)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "IT", "ALL", 0.35f,
            "IT: Unpaid fine/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(sei convocato|rischi|sarai perseguito|procedimento giudiziario|mandato d'arresto)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "IT", "ALL", 0.4f,
            "IT: Summons/arrest threat",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bitcoin|btc|ethereum|eth|cripto|criptovaluta|usdt|binance).{0,20}(investire|opportunit[àa]|guadagno|rendimento|raddoppiare|triplicare)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "IT", "ALL", 0.4f,
            "IT: Crypto investment opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(guadagnare|ottenere|generare).{0,15}(bitcoin|cripto|soldi facili|reddito passivo|soldi da casa)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "IT", "ALL", 0.35f,
            "IT: Earn crypto/easy money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(raddoppiare|triplicare|moltiplicare|decuplicare).{0,15}(il tuo|il suo|il vostro) (denaro|investimento|capitale)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "IT", "ALL", 0.4f,
            "IT: Double/triple your money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(rendimento|ritorno|guadagno|profitto).{0,15}(\\d+%|garantito|assicurato|sicuro)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "IT", "ALL", 0.4f,
            "IT: Guaranteed returns",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(trading|forex|opzioni binarie|borsa).{0,20}(guadagnare|guadagno|opportunit[àa]|segnale|segnali)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "IT", "ALL", 0.35f,
            "IT: Trading/forex opportunity",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(il tuo|il suo) (dispositivo|telefono|computer|pc|cellulare).{0,20}(infett|virus|hackerato|compromesso|minaccia|pericolo)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "IT", "ALL", 0.4f,
            "IT: Your device is infected/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(virus|malware|trojan|spyware|ransomware).{0,20}(rilevato|trovato|nel tuo|il tuo|nel suo)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "IT", "ALL", 0.35f,
            "IT: Virus/malware detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(chiama|contatta).{0,15}(supporto|assistenza|servizio tecnico|help desk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "IT", "ALL", 0.3f,
            "IT: Call tech support",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(accesso remoto|teamviewer|anydesk|quicksupport).{0,15}(installare|scaricare|consentire|dare accesso)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "IT", "ALL", 0.45f,
            "IT: Remote access request",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(sono|lavoro come).{0,10}(militare|soldato|ingegnere|medico|dottore|pilota|marinaio).{0,20}(in|a|al|del) (estero|iraq|afghanistan|siria|piattaforma|nave|base)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "IT", "ALL", 0.4f,
            "IT: Military/engineer abroad (classic romance scam)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ti amo|sei l'amore della mia vita|sei la mia anima gemella|sei speciale).{0,20}(da quando ti ho visto|dal primo momento|non ho mai provato)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "IT", "ALL", 0.3f,
            "IT: Love declaration from unknown",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(eredit[àa]|fortuna|testamento).{0,20}(milioni|euro|dollari|condividere con te|ho bisogno del tuo aiuto)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "IT", "ALL", 0.4f,
            "IT: Inheritance to share",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(vedov[ao]|divorziat[ao]|sol[ao]).{0,15}(cerco|in cerca di|ho bisogno di) (compagnia|amore|un partner|qualcuno di speciale)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "IT", "ALL", 0.3f,
            "IT: Widow/divorced looking for love",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(tesoro|amore mio|caro|cara|cuore mio).{0,25}(invia|aiuta|bisogno|urgente|soldi|trasferimento)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "IT", "ALL", 0.35f,
            "IT: Pet name + money/help request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(dio|il destino|l'universo).{0,15}(ci ha uniti|ti ha messo sulla mia strada|vuole che stiamo insieme)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "IT", "ALL", 0.3f,
            "IT: God/destiny brought us together",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // ROMANIAN (RO)
    // Covers: Romania, Moldova
    // ──────────────────────────────────────────────────────────────────

    private fun romanianRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(contul|cardul) (t[aă]u|dumneavoastr[aă]).{0,30}(suspendat|blocat|anulat|[îi]nchis|dezactivat)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "ALL", 0.4f,
            "RO: Account/card suspended/blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bbanc[aă].{0,25}(bloc|suspen|verific|actualiz|confirm)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "ALL", 0.35f,
            "RO: Bank action required",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verifica|confirma|actualiza).{0,20}(datele bancare|informa[tț]iile bancare|contul bancar|credentialele)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "ALL", 0.4f,
            "RO: Verify/update banking information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bcard(ul)?.{0,20}(expirat|compromis|clonat|furat|pirat)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "ALL", 0.35f,
            "RO: Card compromised/stolen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(tranzac[tț]ie|opera[tț]iune|mi[sș]care).{0,15}(suspect[aă]|neobi[sș]nuit[aă]|neautorizat[aă]|frauduloas[aă])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "ALL", 0.4f,
            "RO: Suspicious/unauthorized transaction",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(introdu|furniza|comunica).{0,20}(codul|parola|pin-ul|num[aă]rul cardului|cvv|otp|token)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "ALL", 0.45f,
            "RO: Request for credentials/PIN/CVV",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(banii|fondurile|economiile) (t[aă]i|tale|dumneavoastr[aă]).{0,20}(risc|pericol|compromis|amenin[tț])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "ALL", 0.35f,
            "RO: Your money is at risk",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(banca transilvania|bcr|brd|ing|raiffeisen|cec bank|alpha bank|otp bank|unicredit|libra bank|garanti)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "RO", 0.2f,
            "RO-RO: Romanian bank name",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(transfergo|revolut|george|bt pay|brd finance).{0,20}(bloc|suspen|verific|problem|compromis|pirat)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "RO", 0.35f,
            "RO-RO: Payment app fraud (TransferGo/Revolut/George)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bam detectat.{0,30}(activitate|tranzac[tț]ie|acces|opera[tț]iune).{0,20}(suspect[aă]|neobi[sș]nuit[aă]|anormal[aă])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "ALL", 0.4f,
            "RO: We detected suspicious activity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bpentru a evita.{0,20}(blocarea|suspendarea|[îi]nchiderea|anularea|dezactivarea)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "RO", "ALL", 0.35f,
            "RO: To avoid blocking/cancellation",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ai c[aâ][sș]tigat|a[tț]i c[aâ][sș]tigat|felicit[aă]ri).{0,30}(premiu|cadou|recompens[aă]|c[aâ][sș]tig)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "RO", "ALL", 0.4f,
            "RO: You won / congratulations + prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(loterie|tombola|extragere|concurs).{0,20}(c[aâ][sș]tigat|selectat|c[aâ][sș]tig[aă]tor|ales)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "RO", "ALL", 0.45f,
            "RO: Lottery/raffle won",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(revendica|ridica|colecta|ob[tț]ine).{0,20}(premiul|c[aâ][sș]tigul|recompensa|cadoul)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "RO", "ALL", 0.4f,
            "RO: Claim your prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(iphone|samsung|televizor|ma[sș]in[aă]|vacan[tț][aă]|zbor|croazier[aă]).{0,20}(gratis|c[aâ][sș]tigat|premiu|tombola|cadou)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "RO", "ALL", 0.35f,
            "RO: Product giveaway",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(whatsapp|facebook|instagram|google|amazon|emag|kaufland|lidl|carrefour).{0,20}(tombola|concurs|premiu|ofert[aă]|cadou|aniversare)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "RO", "ALL", 0.4f,
            "RO: Brand giveaway scam",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(apas[aă]|acceseaz[aă]|d[aă] click).{0,10}(aici|pe link|imediat|urgent|acum|rapid)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RO", "ALL", 0.35f,
            "RO: Click here urgently",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verific[aă]|confirm[aă]).{0,15}(contul|identitatea|adresa|profilul|accesul) (t[aă]u|t[aă]|dumneavoastr[aă])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RO", "ALL", 0.35f,
            "RO: Verify your account/identity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(conectare|acces).{0,15}(suspect[aă]|neobi[sș]nuit[aă]|neautorizat[aă]|de pe alt|nou[aă])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RO", "ALL", 0.35f,
            "RO: Suspicious login detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(expir[aă]|expirare|termen|limit[aă]).{0,15}([îi]n \\d+|ast[aă]zi|disear[aă]|m[aâ]ine|[îi]n cur[aâ]nd|ore)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RO", "ALL", 0.3f,
            "RO: Expiring/limited time",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(actualizeaz[aă]|renoi[eè]ste|re[îi]nnoie[sș]te).{0,20}(informa[tț]iile|datele|parola|profilul)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RO", "ALL", 0.35f,
            "RO: Update your information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(colet|livrare|po[sș]t[aă]|curier|fan courier|sameday|cargus|dhl|ups).{0,20}([îi]n a[sș]teptare|blocat|problem[aă]|tax[aă]|pl[aă]te[sș]te)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "RO", "ALL", 0.35f,
            "RO: Package delivery scam",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(trimite|transfer[aă]|d[aă]).{0,10}(-mi|-ne|-i).{0,15}(bani|suma|un transfer|un mandat)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RO", "ALL", 0.35f,
            "RO: Send me money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(am nevoie|[îi]mi trebuie|trebuie s[aă] am).{0,15}(de bani|de fonduri) (urgent|repede|imediat|acum)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RO", "ALL", 0.4f,
            "RO: I need money urgently",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(card cadou|voucher|[îi]nc[aă]rcare|paysafecard|steam|google play|itunes|apple).{0,15}(cump[aă]r|trimite|cod)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RO", "ALL", 0.4f,
            "RO: Gift card request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(iban|num[aă]r de cont|transfer bancar|bic|swift).{0,15}(iat[aă]|trimite|transfer[aă] pe|pe acest)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RO", "ALL", 0.35f,
            "RO: Transfer to this account (IBAN)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(western union|moneygram|ria|transfergo).{0,15}(trimite|transfer|fa|face)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RO", "ALL", 0.4f,
            "RO: Money transfer service request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b([îi]mprumut[aă]|avanseaz[aă]|d[aă]).{0,10}(-mi).{0,15}(\\d+|bani|lei|euro)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "RO", "ALL", 0.3f,
            "RO: Lend me money",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mam[aă]|m[aă]mic[aă]|bunic[aă]|buni|bunico) sunt eu", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RO", "ALL", 0.45f,
            "RO: Mama sunt eu (classic impersonation)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bun[aă]|salut|hei).{0,10}(mi-am schimbat|am un nou) (num[aă]rul|telefonul|mobilul)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RO", "ALL", 0.4f,
            "RO: I changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(sunt|eu sunt) (fiul|fiica|nepotul|nepoata|v[aă]rul|vara) (t[aă]u|ta|dumneavoastr[aă])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RO", "ALL", 0.35f,
            "RO: I am your son/daughter/grandchild",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mi s-a furat|am pierdut|mi s-a stricat|s-a stricat) (telefonul|mobilul|celularul)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RO", "ALL", 0.3f,
            "RO: My phone was stolen/lost",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(acesta este|iat[aă]) noul meu (num[aă]r|telefon|contact)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RO", "ALL", 0.35f,
            "RO: This is my new number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(nu spune nim[aă]nui|[îi]ntre noi|e un secret|nu vorbi cu nimeni|p[aă]streaz[aă] pentru tine)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "RO", "ALL", 0.35f,
            "RO: Don't tell anyone (secrecy pressure)",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(anaf|fisc|administra[tț]ia fiscal[aă]|finan[tț]e publice|trezorerie)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RO", "RO", 0.2f,
            "RO-RO: Romanian tax authority mention",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(anaf|fisc).{0,40}(datorie|amend[aă]|penalitate|soma[tț]ie|executare|neregul[aă]|restant[aă])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RO", "RO", 0.4f,
            "RO-RO: Tax debt/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(poli[tț]ie|poli[tț]ia|tribunal|parchet|justi[tț]ie|prefectur[aă]).{0,20}(pl[aâ]ngere|cita[tț]ie|ordin|mandat|arestare|dosar)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RO", "ALL", 0.35f,
            "RO: Police/court legal action",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(amend[aă]|contraven[tț]ie|proces[ -]verbal|sanc[tț]iune).{0,20}(nepl[aă]tit[aă]|pl[aă]te[sș]te|achit[aă]|online)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RO", "ALL", 0.35f,
            "RO: Unpaid fine/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(e[sș]ti citat|ri[sș]ti|vei fi urm[aă]rit|procedur[aă] judiciar[aă]|mandat de arestare)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RO", "ALL", 0.4f,
            "RO: Summons/arrest threat",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(cnp|carte de identitate|buletin|permis|pa[sș]aport|cas|cass).{0,20}(expirat|re[îi]nnoire|actualizare|blocat|suspendat)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "RO", "RO", 0.35f,
            "RO-RO: ID/document renewal",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bitcoin|btc|ethereum|eth|cripto|criptomonede|usdt|binance).{0,20}(investi|oportunitate|c[aâ][sș]tig|randament|dubla|tripla)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "RO", "ALL", 0.4f,
            "RO: Crypto investment opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(c[aâ][sș]tiga|ob[tț]ine|genera).{0,15}(bitcoin|cripto|bani u[sș]or|venit pasiv|bani de acas[aă])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "RO", "ALL", 0.35f,
            "RO: Earn crypto/easy money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(dubla|tripla|multiplica|[îi]nzeci).{0,15}(banii|investi[tț]ia|capitalul) (t[aă]u|t[aă]|tale)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "RO", "ALL", 0.4f,
            "RO: Double/triple your money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(randament|profit|c[aâ][sș]tig|venit).{0,15}(\\d+%|garantat|asigurat|sigur)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "RO", "ALL", 0.4f,
            "RO: Guaranteed returns",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(dispozitivul|telefonul|calculatorul|pc-ul) (t[aă]u|dumneavoastr[aă]).{0,20}(infectat|virus|hack|compromis|amenin[tț]|pericol)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "RO", "ALL", 0.4f,
            "RO: Your device is infected/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(virus|malware|troian|spyware|ransomware).{0,20}(detectat|g[aă]sit|[îi]n|pe)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "RO", "ALL", 0.35f,
            "RO: Virus/malware detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(sun[aă]|contacteaz[aă]).{0,15}(suport|asisten[tț][aă]|serviciu tehnic|help desk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "RO", "ALL", 0.3f,
            "RO: Call tech support",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(acces la distan[tț][aă]|teamviewer|anydesk|quicksupport).{0,15}(instala|desc[aă]rca|permite|acorda acces)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "RO", "ALL", 0.45f,
            "RO: Remote access request",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(sunt|lucrez ca).{0,10}(militar|soldat|inginer|medic|doctor|pilot|marinar).{0,20}([îi]n|la|din) (str[aă]in[aă]tate|irak|afganistan|siria|platform[aă]|nav[aă]|baz[aă])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RO", "ALL", 0.4f,
            "RO: Military/engineer abroad (classic romance scam)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(te iubesc|e[sș]ti dragostea vie[tț]ii mele|e[sș]ti sufletul meu pereche|e[sș]ti special[aă]).{0,20}(de c[aâ]nd te-am v[aă]zut|din prima clip[aă]|n-am sim[tț]it niciodat[aă])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RO", "ALL", 0.3f,
            "RO: Love declaration from unknown",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mo[sș]tenire|avere|testament).{0,20}(milioane|euro|dolari|[îi]mp[aă]r[tț]i cu tine|am nevoie de ajutorul t[aă]u)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RO", "ALL", 0.4f,
            "RO: Inheritance to share",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(v[aă]duv[aă]?|divor[tț]at[aă]?|singur[aă]?).{0,15}(caut|[îi]n c[aă]utare de|am nevoie de) (companie|dragoste|un partener|pe cineva special)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RO", "ALL", 0.3f,
            "RO: Widow/divorced looking for love",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(dragul[aă]?|iubirea mea|scumpul[aă]?|sufletul meu|[îi]ngerul meu).{0,25}(trimite|ajut[aă]|nevoie|urgent|bani|transfer)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "RO", "ALL", 0.35f,
            "RO: Pet name + money/help request",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // GERMAN (DE)
    // Covers: Germany, Austria, Switzerland
    // ──────────────────────────────────────────────────────────────────

    private fun germanRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Ihr|dein|Ihre) (Konto|Karte).{0,30}(gesperrt|blockiert|storniert|geschlossen|deaktiviert|eingeschr[aä]nkt)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "ALL", 0.4f,
            "DE: Account/card suspended/blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bBank.{0,25}(gesperr|blockier|verifizier|aktualisier|best[aä]tig)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "ALL", 0.35f,
            "DE: Bank action required",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verifizieren|best[aä]tigen|aktualisieren).{0,20}(Bankdaten|Kontodaten|Bankverbindung|Zugangsdaten)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "ALL", 0.4f,
            "DE: Verify/update banking information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bKarte.{0,20}(abgelaufen|kompromittiert|geklont|gestohlen|gehackt)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "ALL", 0.35f,
            "DE: Card compromised/stolen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Transaktion|Buchung|Bewegung|[Üü]berweisung).{0,15}(verd[aä]chtig|ungew[oö]hnlich|nicht autorisiert|betr[uü]gerisch)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "ALL", 0.4f,
            "DE: Suspicious/unauthorized transaction",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(geben Sie|teilen Sie|senden Sie).{0,20}(Passwort|PIN|Kartennummer|CVV|TAN|Zugangscode|Sicherheitscode)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "ALL", 0.45f,
            "DE: Request for credentials/PIN/CVV/TAN",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Ihr|dein) (Geld|Guthaben|Ersparnisse|Kontoguthaben).{0,20}(Gefahr|Risiko|kompromittiert|bedroht)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "ALL", 0.35f,
            "DE: Your money is at risk",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(sparkasse|volksbank|commerzbank|deutsche bank|postbank|dkb|ing[- ]diba|n26|comdirect|targobank|hypovereinsbank|consorsbank)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "DE", 0.2f,
            "DE-DE: German bank name",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(paypal|giropay|klarna|sofort[uü]berweisung|paydirekt|n26|revolut).{0,20}(gesperr|blockier|verifizier|problem|kompromitt|gehack)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "ALL", 0.35f,
            "DE: Payment app fraud (PayPal/Giropay/Klarna)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bwir haben.{0,20}(verd[aä]chtige|ungew[oö]hnliche|nicht autorisierte).{0,20}(Aktivit[aä]t|Transaktion|Zugriff|Buchung).{0,10}(festgestellt|erkannt|bemerkt)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "ALL", 0.4f,
            "DE: We detected suspicious activity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bum.{0,10}(Sperrung|Blockierung|Schlie[sß]ung|Stornierung|Deaktivierung).{0,10}zu vermeiden", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "ALL", 0.35f,
            "DE: To avoid blocking/cancellation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(erste bank|raiffeisen|bawag|bank austria|oberbank|steierm[aä]rkische)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "AT", 0.2f,
            "DE-AT: Austrian bank name",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ubs|credit suisse|postfinance|zürcher kantonalbank|raiffeisen schweiz|julius b[aä]r)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "DE", "CH", 0.2f,
            "DE-CH: Swiss bank name (German)",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Sie haben gewonnen|du hast gewonnen|Herzlichen Gl[uü]ckwunsch|Gratulation).{0,30}(Preis|Gewinn|Geschenk|Belohnung)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "DE", "ALL", 0.4f,
            "DE: You won / congratulations + prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Lotterie|Verlosung|Gewinnspiel|Ziehung|Tombola).{0,20}(gewonnen|ausgew[aä]hlt|Gewinner|Siegerin)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "DE", "ALL", 0.45f,
            "DE: Lottery/raffle won",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(einfordern|abholen|beanspruchen|einl[oö]sen).{0,20}(Preis|Gewinn|Belohnung|Geschenk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "DE", "ALL", 0.4f,
            "DE: Claim your prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(iPhone|Samsung|Fernseher|Auto|Reise|Flug|Kreuzfahrt).{0,20}(gratis|kostenlos|gewonnen|Preis|Verlosung|Geschenk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "DE", "ALL", 0.35f,
            "DE: Product giveaway",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Gutschein|Voucher|Coupon|Geschenkkarte|Einkaufsgutschein).{0,20}(gratis|kostenlos|gewonnen|exklusiv)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "DE", "ALL", 0.3f,
            "DE: Free voucher/coupon",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(WhatsApp|Facebook|Instagram|Google|Amazon|Aldi|Lidl|Edeka|Rewe|dm|M[uü]ller).{0,20}(Gewinnspiel|Verlosung|Preis|Aktion|Geschenk|Jubil[aä]um)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "DE", "ALL", 0.4f,
            "DE: Brand giveaway scam",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(klicken|klick) Sie.{0,10}(hier|auf den Link|sofort|umgehend|jetzt|schnell)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "DE", "ALL", 0.35f,
            "DE: Click here urgently",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verifizieren|best[aä]tigen) Sie.{0,15}(Ihr|Ihre) (Konto|Identit[aä]t|Adresse|Profil|Zugang)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "DE", "ALL", 0.35f,
            "DE: Verify your account/identity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Anmeldung|Zugriff|Login).{0,15}(verd[aä]chtig|ungew[oö]hnlich|nicht autorisiert|von einem anderen|neuer)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "DE", "ALL", 0.35f,
            "DE: Suspicious login detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(l[aä]uft ab|Ablauf|Frist|Limit).{0,15}(in \\d+|heute|morgen|bald|Stunden|Minuten)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "DE", "ALL", 0.3f,
            "DE: Expiring/limited time",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(aktualisieren|erneuern) Sie.{0,20}(Ihre Daten|Ihre Informationen|Ihr Passwort|Ihr Profil)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "DE", "ALL", 0.35f,
            "DE: Update your information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bIhr (Konto|Zugang|Profil) wird (gel[oö]scht|gesperrt|deaktiviert|geschlossen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "DE", "ALL", 0.4f,
            "DE: Account will be deleted/closed",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Paket|Lieferung|Sendung|Post|DHL|DPD|Hermes|GLS|UPS).{0,20}(wartet|blockiert|Problem|Geb[uü]hr|bezahlen|Zoll)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "DE", "ALL", 0.35f,
            "DE: Package delivery scam",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(schick|[uü]berweise|sende|transferiere) mir.{0,15}(Geld|den Betrag|eine [Üü]berweisung)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "DE", "ALL", 0.35f,
            "DE: Send me money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ich brauche|ich ben[oö]tige).{0,15}(Geld|Mittel) (dringend|sofort|schnell|jetzt)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "DE", "ALL", 0.4f,
            "DE: I need money urgently",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Geschenkkarte|Guthabenkarte|Aufladung|Paysafecard|Steam|Google Play|iTunes|Apple).{0,15}(kauf|schick|Code)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "DE", "ALL", 0.4f,
            "DE: Gift card request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(IBAN|Kontonummer|BIC|SWIFT|[Üü]berweisung).{0,15}(hier ist|schick|[uü]berweise auf|auf dieses)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "DE", "ALL", 0.35f,
            "DE: Transfer to this account (IBAN)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Western Union|MoneyGram|Wise|TransferWise).{0,15}(schick|[uü]berweise|sende|mach)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "DE", "ALL", 0.4f,
            "DE: Money transfer service request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(leih|borgst du|kannst du mir).{0,15}(\\d+|Geld|Euro|Franken)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "DE", "ALL", 0.3f,
            "DE: Lend me money",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Mama|Mutti|Oma|Omi|Mutter) ich bin('s| es)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "DE", "ALL", 0.45f,
            "DE: Mama ich bins (classic impersonation)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Hallo|Hey|Hi).{0,10}(ich hab|ich habe) (eine neue|meine) (Nummer|Handy|Telefon)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "DE", "ALL", 0.4f,
            "DE: I changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ich bin|hier ist) (dein|Ihr|deine|Ihre) (Sohn|Tochter|Enkel|Enkelin|Neffe|Nichte|Cousin|Cousine)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "DE", "ALL", 0.35f,
            "DE: I am your son/daughter/grandchild",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mir wurde gestohlen|ich habe verloren|mein.{0,5}ist kaputt).{0,10}(Handy|Telefon|Smartphone)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "DE", "ALL", 0.3f,
            "DE: My phone was stolen/lost",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Handy|Telefon|Smartphone).{0,10}(gestohlen|verloren|kaputt|kaputtgegangen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "DE", "ALL", 0.3f,
            "DE: Phone stolen/lost/broken (alt word order)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(das ist|hier ist) meine neue (Nummer|Handynummer|Telefonnummer)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "DE", "ALL", 0.35f,
            "DE: This is my new number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(speicher|notier|merk dir) (diese|meine) (neue )?(Nummer|Kontakt|Handynummer)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "DE", "ALL", 0.3f,
            "DE: Save my new number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(sag niemandem|unter uns|das ist ein Geheimnis|erz[aä]hl niemandem|behalt das f[uü]r dich)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "DE", "ALL", 0.35f,
            "DE: Don't tell anyone (secrecy pressure)",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Finanzamt|Bundeszentralamt|Steuer|Steuerbeh[oö]rde|Zoll)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "DE", "DE", 0.2f,
            "DE-DE: German tax authority mention",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Finanzamt|Steuerbeh[oö]rde|Steuer).{0,40}(Schuld|Nachzahlung|Bu[sß]geld|Mahnung|Pfändung|Unregelmä[sß]igkeit|Steuerbescheid)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "DE", "DE", 0.4f,
            "DE-DE: Tax debt/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Polizei|Gericht|Staatsanwaltschaft|Kripo|Kriminalpolizei).{0,20}(Anzeige|Vorladung|Haftbefehl|Ermittlung|Verfahren|Verhaftung)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "DE", "ALL", 0.35f,
            "DE: Police/court legal action",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Personalausweis|Reisepass|Gesundheitskarte|Elster|GEZ|Rundfunkbeitrag).{0,20}(abgelaufen|erneuern|aktualisieren|gesperrt|aktivieren)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "DE", "DE", 0.35f,
            "DE-DE: ID/document/Elster renewal",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Bu[sß]geld|Strafzettel|Ordnungswidrigkeit|Verwarnung).{0,20}(unbezahlt|bezahlen|begleichen|online)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "DE", "ALL", 0.35f,
            "DE: Unpaid fine/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Sie sind vorgeladen|Sie riskieren|Sie werden strafrechtlich verfolgt|Gerichtsverfahren|Haftbefehl)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "DE", "ALL", 0.4f,
            "DE: Summons/arrest threat",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Bundesministerium|Bundeskanzleramt|Regierung).{0,20}(informiert|teilt mit|warnt|benachrichtigt)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "DE", "DE", 0.3f,
            "DE-DE: Federal ministry impersonation",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Bitcoin|BTC|Ethereum|ETH|Krypto|Kryptow[aä]hrung|USDT|Binance).{0,20}(investieren|Gelegenheit|Gewinn|Rendite|Rentabilit[aä]t|verdoppeln|verdreifachen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "DE", "ALL", 0.4f,
            "DE: Crypto investment opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verdienen|erhalten|generieren) Sie.{0,15}(Bitcoin|Krypto|leichtes Geld|passives Einkommen|Geld von zu Hause)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "DE", "ALL", 0.35f,
            "DE: Earn crypto/easy money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verdoppeln|verdreifachen|vervielfachen|verzehnfachen) Sie.{0,15}(Ihr|dein) (Geld|Investment|Kapital|Anlage)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "DE", "ALL", 0.4f,
            "DE: Double/triple your money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Rendite|Ertrag|Gewinn|Profit).{0,15}(\\d+%|garantiert|gesichert|sicher)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "DE", "ALL", 0.4f,
            "DE: Guaranteed returns",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Trading|Forex|bin[aä]re Optionen|B[oö]rse|Aktienmarkt).{0,20}(verdienen|Gewinn|Gelegenheit|Signal|Signale)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "DE", "ALL", 0.35f,
            "DE: Trading/forex opportunity",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Ihr|dein) (Ger[aä]t|Handy|Computer|PC|Smartphone|Laptop).{0,20}(infiziert|Virus|gehackt|kompromittiert|bedroht|Gefahr)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "DE", "ALL", 0.4f,
            "DE: Your device is infected/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Virus|Malware|Trojaner|Spyware|Ransomware).{0,20}(erkannt|gefunden|auf Ihrem|auf deinem|in Ihrem)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "DE", "ALL", 0.35f,
            "DE: Virus/malware detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(rufen Sie an|kontaktieren Sie).{0,15}(Support|Kundendienst|technischer Service|Helpdesk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "DE", "ALL", 0.3f,
            "DE: Call tech support",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Fernzugriff|TeamViewer|AnyDesk|QuickSupport).{0,15}(installieren|herunterladen|erlauben|Zugriff gew[aä]hren)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "DE", "ALL", 0.45f,
            "DE: Remote access request",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ich bin|ich arbeite als).{0,10}(Milit[aä]r|Soldat|Ingenieur|Arzt|Doktor|Pilot|Seemann).{0,20}(im|in|beim) (Ausland|Irak|Afghanistan|Syrien|Plattform|Schiff|St[uü]tzpunkt)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "DE", "ALL", 0.4f,
            "DE: Military/engineer abroad (classic romance scam)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ich liebe dich|du bist die Liebe meines Lebens|du bist mein Seelenverwandter|du bist etwas Besonderes).{0,20}(seit ich dich gesehen habe|vom ersten Moment|habe ich noch nie gef[uü]hlt)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "DE", "ALL", 0.3f,
            "DE: Love declaration from unknown",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Erbschaft|Verm[oö]gen|Testament).{0,20}(Millionen|Euro|Dollar|mit dir teilen|brauche deine Hilfe)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "DE", "ALL", 0.4f,
            "DE: Inheritance to share",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Witwe|Witwer|geschieden|allein).{0,15}(suche|auf der Suche nach|brauche) (Gesellschaft|Liebe|Partner|jemand Besonderen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "DE", "ALL", 0.3f,
            "DE: Widow/divorced looking for love",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mein Schatz|mein Liebling|Liebster|Liebste|mein Herz|mein Engel).{0,25}(schick|hilf|brauche|dringend|Geld|[Üü]berweisung)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "DE", "ALL", 0.35f,
            "DE: Pet name + money/help request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Gott|das Schicksal|das Universum).{0,15}(hat uns zusammengef[uü]hrt|hat dich in mein Leben gebracht|will dass wir zusammen sind)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "DE", "ALL", 0.3f,
            "DE: God/destiny brought us together",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // DUTCH (NL)
    // Covers: Netherlands, Belgium (Flanders)
    // ──────────────────────────────────────────────────────────────────

    private fun dutchRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(uw|je|jouw) (rekening|kaart|bankpas).{0,30}(geblokkeerd|opgeschort|geannuleerd|gesloten|gedeactiveerd)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "ALL", 0.4f,
            "NL: Account/card suspended/blocked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bbank.{0,25}(geblokkeer|opgeschor|verificer|bijwerk|bevestig)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "ALL", 0.35f,
            "NL: Bank action required",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verifi[eë]ren|bevestigen|bijwerken|actualiseren).{0,20}(bankgegevens|rekeninggegevens|bankinformatie|inloggegevens)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "ALL", 0.4f,
            "NL: Verify/update banking information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bank)?pas.{0,20}(verlopen|gecompromitteerd|gekloond|gestolen|gehackt)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "ALL", 0.35f,
            "NL: Card compromised/stolen",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(transactie|overboeking|betaling).{0,15}(verdacht|ongebruikelijk|niet geautoriseerd|frauduleus)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "ALL", 0.4f,
            "NL: Suspicious/unauthorized transaction",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(voer in|geef|stuur|deel).{0,20}(wachtwoord|pincode|kaartnummer|cvv|tan|beveiligingscode|inlogcode)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "ALL", 0.45f,
            "NL: Request for credentials/PIN/CVV",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(uw|je|jouw) (geld|tegoed|spaargeld|saldo).{0,20}(gevaar|risico|gecompromitteerd|bedreigd)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "ALL", 0.35f,
            "NL: Your money is at risk",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ing|rabobank|abn amro|sns bank|volksbank|triodos|asn bank|regiobank|knab|bunq)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "NL", 0.2f,
            "NL-NL: Dutch bank name",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ideal|tikkie|betaalverzoek|bunq|knab|revolut|paypal).{0,20}(geblokkeer|opgeschor|verificer|probleem|gecompromitteer|gehack)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "ALL", 0.35f,
            "NL: Payment app fraud (iDEAL/Tikkie)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bwe hebben.{0,20}(verdachte|ongebruikelijke|niet geautoriseerde).{0,20}(activiteit|transactie|toegang|betaling).{0,10}(gedetecteerd|ontdekt|vastgesteld)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "ALL", 0.4f,
            "NL: We detected suspicious activity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bom.{0,10}(blokkering|opschorting|sluiting|annulering|deactivering).{0,10}te voorkomen", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "ALL", 0.35f,
            "NL: To avoid blocking/cancellation",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(belfius|kbc|bnp paribas fortis|argenta|beobank|axa bank|ing belgi[eë])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "NL", "BE", 0.2f,
            "NL-BE: Belgian bank name (Flemish)",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(u heeft gewonnen|je hebt gewonnen|gefeliciteerd|proficiat).{0,30}(prijs|lot|cadeau|beloning)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "NL", "ALL", 0.4f,
            "NL: You won / congratulations + prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(loterij|trekking|verloting|prijsvraag|tombola).{0,20}(gewonnen|geselecteerd|winnaar|uitgekozen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "NL", "ALL", 0.45f,
            "NL: Lottery/raffle won",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(claim|ophalen|opeisen|innen).{0,20}(prijs|winst|beloning|cadeau|geschenk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "NL", "ALL", 0.4f,
            "NL: Claim your prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(iPhone|Samsung|televisie|auto|reis|vlucht|cruise).{0,20}(gratis|gewonnen|prijs|verloting|cadeau)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "NL", "ALL", 0.35f,
            "NL: Product giveaway",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(tegoedbon|voucher|coupon|cadeaubon|cadeaukaart).{0,20}(gratis|cadeau|gewonnen|exclusief)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "NL", "ALL", 0.3f,
            "NL: Free voucher/coupon",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(WhatsApp|Facebook|Instagram|Google|Amazon|Albert Heijn|Jumbo|Bol\\.com|Kruidvat|Action).{0,20}(trekking|verloting|prijs|actie|cadeau|jubileum)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "NL", "ALL", 0.4f,
            "NL: Brand giveaway scam",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\bklik.{0,10}(hier|op de link|onmiddellijk|snel|nu|direct|meteen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "NL", "ALL", 0.35f,
            "NL: Click here urgently",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verifieer|bevestig).{0,15}(uw|je|jouw) (account|rekening|identiteit|adres|profiel|toegang)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "NL", "ALL", 0.35f,
            "NL: Verify your account/identity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(inlog|aanmelding|toegang).{0,15}(verdacht|ongebruikelijk|niet geautoriseerd|van een ander|nieuw)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "NL", "ALL", 0.35f,
            "NL: Suspicious login detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verloopt|verlopen|deadline|limiet).{0,15}(over \\d+|vandaag|morgen|binnenkort|uren|minuten)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "NL", "ALL", 0.3f,
            "NL: Expiring/limited time",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(werk bij|actualiseer|vernieuw).{0,20}(uw gegevens|uw informatie|uw wachtwoord|uw profiel)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "NL", "ALL", 0.35f,
            "NL: Update your information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(uw|je) (account|rekening|profiel) (wordt|zal) (verwijderd|geblokkeerd|gedeactiveerd|gesloten)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "NL", "ALL", 0.4f,
            "NL: Account will be deleted/closed",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(pakket|bezorging|levering|PostNL|DHL|DPD|UPS|GLS).{0,20}(wacht|geblokkeerd|probleem|kosten|betalen|invoer)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "NL", "ALL", 0.35f,
            "NL: Package delivery scam",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(stuur|maak over|overboek|doe) (mij|ons|hem|haar).{0,15}(geld|het bedrag|een overboeking)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "NL", "ALL", 0.35f,
            "NL: Send me money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ik heb|ik moet).{0,10}(geld|middelen) (nodig|hebben).{0,10}(dringend|snel|nu|direct)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "NL", "ALL", 0.4f,
            "NL: I need money urgently",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(cadeaukaart|tegoedkaart|opwaardering|paysafecard|steam|google play|itunes|apple).{0,15}(koop|stuur|code)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "NL", "ALL", 0.4f,
            "NL: Gift card request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(iban|rekeningnummer|bic|swift|overboeking).{0,15}(hier is|stuur|maak over naar|op deze)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "NL", "ALL", 0.35f,
            "NL: Transfer to this account (IBAN)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(tikkie|betaalverzoek).{0,15}(betaal|stuur|maak over)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "NL", "NL", 0.3f,
            "NL-NL: Tikkie/payment request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Western Union|MoneyGram|Wise|TransferWise).{0,15}(stuur|maak over|betaal|doe)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "NL", "ALL", 0.4f,
            "NL: Money transfer service request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(leen|kun je|kan je).{0,15}(\\d+|geld|euro) (lenen|voorschieten|uitlenen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "NL", "ALL", 0.3f,
            "NL: Lend me money",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mama|mam|oma|moeder) ik ben het", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "NL", "ALL", 0.45f,
            "NL: Mama ik ben het (classic impersonation)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(hallo|hey|hoi|hi).{0,10}(ik heb een nieuw|ik heb mijn) (nummer|telefoon|mobiel|toestel)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "NL", "ALL", 0.4f,
            "NL: I changed my number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ik ben|dit is) (je|jouw|uw) (zoon|dochter|kleinkind|kleinzoon|kleindochter|neef|nicht|nichtje)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "NL", "ALL", 0.35f,
            "NL: I am your son/daughter/grandchild",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mijn telefoon is|mijn mobiel is|mijn toestel is) (gestolen|kwijt|kapot|stuk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "NL", "ALL", 0.3f,
            "NL: My phone was stolen/lost",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(dit is|hier is) mijn nieuwe (nummer|telefoonnummer|mobiel|contact)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "NL", "ALL", 0.35f,
            "NL: This is my new number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(sla op|bewaar|noteer) (dit|mijn) (nieuwe )?(nummer|contact)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "NL", "ALL", 0.3f,
            "NL: Save my new number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(zeg het tegen niemand|onder ons|het is een geheim|vertel het aan niemand|hou het voor jezelf)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "NL", "ALL", 0.35f,
            "NL: Don't tell anyone (secrecy pressure)",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(belastingdienst|fiscus|toeslagen|uwv|svb|duo|rijksoverheid)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "NL", "NL", 0.2f,
            "NL-NL: Dutch tax/government mention",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(belastingdienst|fiscus|toeslagen).{0,40}(schuld|boete|aanmaning|beslag|onregelmatigheid|aanslag|teruggave)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "NL", "NL", 0.4f,
            "NL-NL: Tax debt/penalty/refund",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(politie|rechtbank|officier van justitie|openbaar ministerie).{0,20}(aangifte|dagvaarding|arrestatiebevel|onderzoek|vervolging)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "NL", "ALL", 0.35f,
            "NL: Police/court legal action",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(DigiD|BSN|rijbewijs|paspoort|identiteitskaart|zorgverzekering).{0,20}(verlopen|vernieuwen|bijwerken|geblokkeerd|activeren)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "NL", "NL", 0.35f,
            "NL-NL: DigiD/ID/document renewal",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(boete|bekeuring|overtreding|waarschuwing).{0,20}(onbetaald|betalen|voldoen|online)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "NL", "ALL", 0.35f,
            "NL: Unpaid fine/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(u bent gedagvaard|u riskeert|u wordt strafrechtelijk vervolgd|gerechtelijke procedure|arrestatiebevel)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "NL", "ALL", 0.4f,
            "NL: Summons/arrest threat",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Bitcoin|BTC|Ethereum|ETH|crypto|cryptocurrency|USDT|Binance).{0,20}(investeren|kans|winst|rendement|verdubbelen|verdrievoudigen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "NL", "ALL", 0.4f,
            "NL: Crypto investment opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verdienen|ontvangen|genereren).{0,15}(Bitcoin|crypto|makkelijk geld|passief inkomen|geld vanuit huis)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "NL", "ALL", 0.35f,
            "NL: Earn crypto/easy money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verdubbel|verdrievoudig|vermenigvuldig|vertienvoudig).{0,15}(uw|je|jouw) (geld|investering|kapitaal|inleg)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "NL", "ALL", 0.4f,
            "NL: Double/triple your money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(rendement|opbrengst|winst|resultaat).{0,15}(\\d+%|gegarandeerd|verzekerd|zeker)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "NL", "ALL", 0.4f,
            "NL: Guaranteed returns",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(trading|forex|binaire opties|beurs|aandelenmarkt).{0,20}(verdienen|winst|kans|signaal|signalen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "NL", "ALL", 0.35f,
            "NL: Trading/forex opportunity",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(uw|je|jouw) (apparaat|telefoon|computer|pc|smartphone|laptop).{0,20}(ge[ïi]nfecteerd|virus|gehackt|gecompromitteerd|bedreigd|gevaar)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "NL", "ALL", 0.4f,
            "NL: Your device is infected/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(virus|malware|trojaan|spyware|ransomware).{0,20}(gedetecteerd|gevonden|op uw|op je|in uw)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "NL", "ALL", 0.35f,
            "NL: Virus/malware detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bel|neem contact op met).{0,15}(support|klantenservice|technische dienst|helpdesk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "NL", "ALL", 0.3f,
            "NL: Call tech support",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(toegang op afstand|TeamViewer|AnyDesk|QuickSupport).{0,15}(installeren|downloaden|toestaan|toegang verlenen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "NL", "ALL", 0.45f,
            "NL: Remote access request",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ik ben|ik werk als).{0,10}(militair|soldaat|ingenieur|arts|dokter|piloot|zeeman).{0,20}(in het|in|bij het) (buitenland|Irak|Afghanistan|Syri[eë]|platform|schip|basis)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "NL", "ALL", 0.4f,
            "NL: Military/engineer abroad (classic romance scam)",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ik hou van je|je bent de liefde van mijn leven|je bent mijn zielsverwant|je bent speciaal).{0,20}(sinds ik je zag|vanaf het eerste moment|heb ik nog nooit gevoeld)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "NL", "ALL", 0.3f,
            "NL: Love declaration from unknown",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(erfenis|vermogen|testament).{0,20}(miljoenen|euro|dollar|met je delen|heb je hulp nodig)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "NL", "ALL", 0.4f,
            "NL: Inheritance to share",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(weduwe|weduwnaar|gescheiden|alleen).{0,15}(zoek|op zoek naar|heb behoefte aan) (gezelschap|liefde|een partner|iemand bijzonders)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "NL", "ALL", 0.3f,
            "NL: Widow/divorced looking for love",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(mijn schat|mijn lieverd|liefste|mijn hart|mijn engel).{0,25}(stuur|help|nodig|dringend|geld|overboeking)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "NL", "ALL", 0.35f,
            "NL: Pet name + money/help request",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(God|het lot|het universum).{0,15}(heeft ons samengebracht|heeft je op mijn pad gebracht|wil dat we samen zijn)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "NL", "ALL", 0.3f,
            "NL: God/destiny brought us together",
        ))
    }
}
