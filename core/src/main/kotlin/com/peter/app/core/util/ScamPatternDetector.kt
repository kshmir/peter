package com.peter.app.core.util

/**
 * Extensive rule-based scam pattern detector for WhatsApp messages.
 *
 * Designed to protect elderly users (particularly those with dementia) from
 * common scam patterns across Spanish, Portuguese, and English-speaking regions.
 *
 * Supports regionalized patterns for:
 * - Spanish: Argentina (AR), Spain (ES), Colombia (CO), Chile (CL), Mexico (MX), Peru (PE)
 * - Portuguese: Brazil (BR)
 * - English: US/general (US)
 *
 * Confidence scoring: 0.0-1.0
 *   >0.7 = HIGH_ALERT (almost certainly a scam)
 *   >0.4 = WARNING (likely suspicious)
 *   >0.2 = LOW (mildly suspicious, monitor)
 *   <=0.2 = NONE (normal conversation)
 */
object ScamPatternDetector {

    // ══════════════════════════════════════════════════════════════════════
    // Public API
    // ══════════════════════════════════════════════════════════════════════

    data class ScamAnalysis(
        val isSuspicious: Boolean,
        val confidence: Float,
        val threatLevel: ThreatLevel,
        val matchedPatterns: List<MatchedPattern>,
        val category: ScamCategory?,
        /** Legacy helper: the top matched pattern text, or empty string. */
        val matchedPattern: String = matchedPatterns.firstOrNull()?.pattern ?: "",
    )

    data class MatchedPattern(
        val pattern: String,
        val category: ScamCategory,
        val language: String,
        val region: String,
        val weight: Float,
    )

    enum class ThreatLevel { NONE, LOW, WARNING, HIGH_ALERT }

    enum class ScamCategory {
        BANK_FRAUD,
        PRIZE_SCAM,
        PHISHING,
        IMPERSONATION,
        MONEY_REQUEST,
        CRYPTO_SCAM,
        TECH_SUPPORT,
        GOVERNMENT_SCAM,
        ROMANCE_SCAM,
    }

    /**
     * Analyze a single message for scam patterns.
     */
    fun analyze(text: String): ScamAnalysis {
        if (text.isBlank()) {
            return ScamAnalysis(
                isSuspicious = false,
                confidence = 0f,
                threatLevel = ThreatLevel.NONE,
                matchedPatterns = emptyList(),
                category = null,
            )
        }

        val matched = mutableListOf<MatchedPattern>()
        val normalized = text.normalizeForAnalysis()

        for (rule in ALL_RULES) {
            if (rule.regex.containsMatchIn(normalized)) {
                matched.add(
                    MatchedPattern(
                        pattern = rule.description,
                        category = rule.category,
                        language = rule.language,
                        region = rule.region,
                        weight = rule.weight,
                    )
                )
            }
        }

        // URL shortener / suspicious link bonus
        val linkMatches = detectSuspiciousLinks(normalized)
        matched.addAll(linkMatches)

        // Urgency amplifier: if urgency words are present alongside other matches, boost weight
        val urgencyBoost = computeUrgencyBoost(normalized, matched)

        return buildAnalysis(matched, urgencyBoost)
    }

    /**
     * Analyze a conversation (multiple messages) for scam patterns.
     * Considers cross-message escalation patterns common in scam sequences.
     */
    fun analyzeConversation(messages: List<String>): ScamAnalysis {
        if (messages.isEmpty()) {
            return ScamAnalysis(
                isSuspicious = false,
                confidence = 0f,
                threatLevel = ThreatLevel.NONE,
                matchedPatterns = emptyList(),
                category = null,
            )
        }

        // Analyze each message individually
        val perMessage = messages.map { analyze(it) }

        // Merge all matched patterns
        val allMatched = perMessage.flatMap { it.matchedPatterns }.toMutableList()

        // Conversation-level escalation detection
        val escalationBoost = detectConversationEscalation(messages, perMessage)

        // Combine text for cross-message pattern detection
        val combined = messages.joinToString(" ")
        val crossMessageMatches = detectCrossMessagePatterns(combined)
        allMatched.addAll(crossMessageMatches)

        val urgencyBoost = perMessage.maxOfOrNull { computeUrgencyBoost(it.matchedPattern, it.matchedPatterns) } ?: 0f

        return buildAnalysis(allMatched, urgencyBoost + escalationBoost)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Internal: scoring and analysis building
    // ══════════════════════════════════════════════════════════════════════

    private fun buildAnalysis(
        matched: List<MatchedPattern>,
        urgencyBoost: Float,
    ): ScamAnalysis {
        if (matched.isEmpty()) {
            return ScamAnalysis(
                isSuspicious = false,
                confidence = 0f,
                threatLevel = ThreatLevel.NONE,
                matchedPatterns = emptyList(),
                category = null,
            )
        }

        // Group by category and compute per-category score
        val byCategory = matched.groupBy { it.category }
        val categoryScores = byCategory.mapValues { (_, patterns) ->
            // Sum weights but apply diminishing returns within a category
            val sorted = patterns.sortedByDescending { it.weight }
            var score = 0f
            for ((i, p) in sorted.withIndex()) {
                // Each additional match in same category contributes less
                score += p.weight * (1f / (1f + i * 0.3f))
            }
            score
        }

        // Apply category severity multipliers
        val severityMultiplier = mapOf(
            ScamCategory.BANK_FRAUD to 1.3f,
            ScamCategory.IMPERSONATION to 1.4f,
            ScamCategory.PHISHING to 1.2f,
            ScamCategory.MONEY_REQUEST to 1.2f,
            ScamCategory.GOVERNMENT_SCAM to 1.2f,
            ScamCategory.PRIZE_SCAM to 1.1f,
            ScamCategory.CRYPTO_SCAM to 1.1f,
            ScamCategory.TECH_SUPPORT to 1.0f,
            ScamCategory.ROMANCE_SCAM to 1.0f,
        )

        val weightedScores = categoryScores.map { (cat, score) ->
            cat to score * (severityMultiplier[cat] ?: 1f)
        }

        // Multi-category bonus: scams that hit multiple categories are more suspicious
        val multiCategoryBonus = if (byCategory.size >= 3) 0.15f
        else if (byCategory.size >= 2) 0.08f
        else 0f

        val topCategory = weightedScores.maxByOrNull { it.second }
        val rawConfidence = (weightedScores.sumOf { it.second.toDouble() }.toFloat()
            + urgencyBoost
            + multiCategoryBonus)

        // Clamp to [0, 1] with sigmoid-like smoothing for high values
        val confidence = smoothClamp(rawConfidence)

        val threatLevel = when {
            confidence > 0.7f -> ThreatLevel.HIGH_ALERT
            confidence > 0.4f -> ThreatLevel.WARNING
            confidence > 0.2f -> ThreatLevel.LOW
            else -> ThreatLevel.NONE
        }

        // Sort matched patterns by weight descending
        val sortedMatched = matched.sortedByDescending { it.weight }

        return ScamAnalysis(
            isSuspicious = confidence > 0.2f,
            confidence = confidence,
            threatLevel = threatLevel,
            matchedPatterns = sortedMatched,
            category = topCategory?.first,
        )
    }

    /** Smooth clamp: maps [0, inf) to [0, 1) using tanh-like curve. */
    private fun smoothClamp(x: Float): Float {
        if (x <= 0f) return 0f
        if (x >= 1.5f) return (0.85f + 0.15f * (1f - 1f / (1f + (x - 1.5f)))).coerceAtMost(0.99f)
        return (x / 1.5f).coerceAtMost(0.99f)
    }

    // ══════════════════════════════════════════════════════════════════════
    // Text normalization
    // ══════════════════════════════════════════════════════════════════════

    private fun String.normalizeForAnalysis(): String {
        return this
            .lowercase()
            // Normalize common character substitutions scammers use
            .replace('0', 'o')
            .replace('1', 'l')
            .replace('3', 'e')
            .replace('4', 'a')
            .replace('5', 's')
            .replace('@', 'a')
            .replace('$', 's')
            // Normalize whitespace
            .replace(Regex("\\s+"), " ")
            .trim()
    }

    // ══════════════════════════════════════════════════════════════════════
    // Urgency detection
    // ══════════════════════════════════════════════════════════════════════

    private val URGENCY_PATTERNS_ES = listOf(
        Regex("\\burgente\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(ahora mismo|inmediatamente|de inmediato|cuanto antes)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(últim[ao] oportunidad|última chance)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(no esperes|no pierdas tiempo|apúrate|apurate|date prisa)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(vence hoy|expira hoy|caduca hoy|solo por hoy|solo hoy)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(quedan pocas? horas|quedan \\d+ (horas|minutos))\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(antes de que sea tarde|no dejes pasar)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(respond[eé] (ya|ahora|rápido|rapido))\\b", RegexOption.IGNORE_CASE),
    )

    private val URGENCY_PATTERNS_PT = listOf(
        Regex("\\burgente\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(agora mesmo|imediatamente|o mais rápido possível)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(última chance|última oportunidade)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(não espere|não perca tempo|corra|se apresse)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(vence hoje|expira hoje|só hoje|somente hoje)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(restam poucas horas|faltam \\d+ (horas|minutos))\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(antes que (seja tarde|acabe)|não deixe passar)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(responda (já|agora|rápido))\\b", RegexOption.IGNORE_CASE),
    )

    private val URGENCY_PATTERNS_EN = listOf(
        Regex("\\burgent\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(right now|immediately|asap|as soon as possible)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(last chance|final opportunity|don't miss out)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(hurry|act now|act fast|don't wait|don't delay)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(expires today|ends today|today only|limited time)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(only \\d+ (hours|minutes) left|running out)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(before it'?s too late|time is running out)\\b", RegexOption.IGNORE_CASE),
        Regex("\\b(respond (now|immediately|quickly|asap))\\b", RegexOption.IGNORE_CASE),
    )

    private fun computeUrgencyBoost(text: String, currentMatches: List<MatchedPattern>): Float {
        if (currentMatches.isEmpty()) return 0f
        val normalized = text.lowercase()
        val hasUrgency = URGENCY_PATTERNS_ES.any { it.containsMatchIn(normalized) }
            || URGENCY_PATTERNS_PT.any { it.containsMatchIn(normalized) }
            || URGENCY_PATTERNS_EN.any { it.containsMatchIn(normalized) }
        return if (hasUrgency) 0.1f else 0f
    }

    // ══════════════════════════════════════════════════════════════════════
    // Suspicious link detection
    // ══════════════════════════════════════════════════════════════════════

    private val SUSPICIOUS_URL_PATTERNS = listOf(
        Regex("bit\\.ly/\\S+", RegexOption.IGNORE_CASE),
        Regex("tinyurl\\.com/\\S+", RegexOption.IGNORE_CASE),
        Regex("t\\.co/\\S+", RegexOption.IGNORE_CASE),
        Regex("goo\\.gl/\\S+", RegexOption.IGNORE_CASE),
        Regex("ow\\.ly/\\S+", RegexOption.IGNORE_CASE),
        Regex("is\\.gd/\\S+", RegexOption.IGNORE_CASE),
        Regex("buff\\.ly/\\S+", RegexOption.IGNORE_CASE),
        Regex("rebrand\\.ly/\\S+", RegexOption.IGNORE_CASE),
        Regex("cutt\\.ly/\\S+", RegexOption.IGNORE_CASE),
        Regex("short\\.io/\\S+", RegexOption.IGNORE_CASE),
        Regex("wa\\.me/\\S+", RegexOption.IGNORE_CASE),
        Regex("https?://[a-z0-9]{1,3}\\.[a-z0-9]{1,3}\\.[a-z0-9]{1,3}\\.[a-z0-9]{1,3}", RegexOption.IGNORE_CASE),
        // Suspicious domains mimicking banks/government
        Regex("https?://[a-z]*banco[a-z]*\\.[a-z]+\\.\\S+", RegexOption.IGNORE_CASE),
        Regex("https?://[a-z]*segur[a-z]*\\.[a-z]+\\.\\S+", RegexOption.IGNORE_CASE),
        Regex("https?://[a-z]*verific[a-z]*\\.[a-z]+\\.\\S+", RegexOption.IGNORE_CASE),
        Regex("https?://[a-z]*actualiz[a-z]*\\.[a-z]+\\.\\S+", RegexOption.IGNORE_CASE),
        // Typosquatting common banks
        Regex("https?://[a-z]*(whatsap[^p]|whasapp|whatssap|watsap)\\S*", RegexOption.IGNORE_CASE),
        Regex("https?://[a-z]*(faceb00k|facebok|faceboook)\\S*", RegexOption.IGNORE_CASE),
        Regex("https?://[a-z]*(g00gle|googie|gooogle)\\S*", RegexOption.IGNORE_CASE),
    )

    private fun detectSuspiciousLinks(text: String): List<MatchedPattern> {
        val result = mutableListOf<MatchedPattern>()
        for (pattern in SUSPICIOUS_URL_PATTERNS) {
            if (pattern.containsMatchIn(text)) {
                result.add(
                    MatchedPattern(
                        pattern = "Suspicious URL: ${pattern.pattern}",
                        category = ScamCategory.PHISHING,
                        language = "ALL",
                        region = "ALL",
                        weight = 0.2f,
                    )
                )
            }
        }
        return result
    }

    // ══════════════════════════════════════════════════════════════════════
    // Conversation escalation detection
    // ══════════════════════════════════════════════════════════════════════

    private fun detectConversationEscalation(
        messages: List<String>,
        analyses: List<ScamAnalysis>,
    ): Float {
        var boost = 0f

        // Pattern: early messages are friendly, later messages push for action
        if (messages.size >= 3) {
            val earlyClean = analyses.take(messages.size / 2).all { !it.isSuspicious }
            val lateSuspicious = analyses.drop(messages.size / 2).any { it.isSuspicious }
            if (earlyClean && lateSuspicious) {
                boost += 0.1f // Grooming pattern: build trust then scam
            }
        }

        // Pattern: repeated urgency across messages
        val urgentCount = messages.count { msg ->
            val lower = msg.lowercase()
            URGENCY_PATTERNS_ES.any { it.containsMatchIn(lower) }
                || URGENCY_PATTERNS_PT.any { it.containsMatchIn(lower) }
                || URGENCY_PATTERNS_EN.any { it.containsMatchIn(lower) }
        }
        if (urgentCount >= 2) {
            boost += 0.08f
        }

        // Pattern: escalating financial requests
        val moneyMessages = analyses.count { a ->
            a.matchedPatterns.any {
                it.category == ScamCategory.MONEY_REQUEST || it.category == ScamCategory.BANK_FRAUD
            }
        }
        if (moneyMessages >= 2) {
            boost += 0.1f
        }

        return boost
    }

    private val CROSS_MESSAGE_PATTERNS = listOf(
        // "I changed my number" + money request = classic impersonation
        PatternRule(
            Regex("(cambi[eé] (de|mi) n[uú]mero|mudei (de|meu) n[uú]mero|changed my number)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES/PT/EN", "ALL", 0.25f,
            "Cross-message: number change claim in conversation",
        ),
    )

    private fun detectCrossMessagePatterns(combinedText: String): List<MatchedPattern> {
        val result = mutableListOf<MatchedPattern>()
        val normalized = combinedText.normalizeForAnalysis()
        for (rule in CROSS_MESSAGE_PATTERNS) {
            if (rule.regex.containsMatchIn(normalized)) {
                result.add(
                    MatchedPattern(
                        pattern = rule.description,
                        category = rule.category,
                        language = rule.language,
                        region = rule.region,
                        weight = rule.weight,
                    )
                )
            }
        }
        return result
    }

    // ══════════════════════════════════════════════════════════════════════
    // Pattern rule definition
    // ══════════════════════════════════════════════════════════════════════

    private data class PatternRule(
        val regex: Regex,
        val category: ScamCategory,
        val language: String,
        val region: String,
        val weight: Float,
        val description: String,
    )

    // ══════════════════════════════════════════════════════════════════════
    // ══════════════════════════════════════════════════════════════════════
    //
    //  PATTERN DATABASE
    //
    //  Organized by: Category -> Language -> Region
    //  Each category has 15-20+ patterns per language.
    //
    // ══════════════════════════════════════════════════════════════════════
    // ══════════════════════════════════════════════════════════════════════

    private val ALL_RULES: List<PatternRule> by lazy {
        buildList {
            addAll(bankFraudRules())
            addAll(prizeScamRules())
            addAll(phishingRules())
            addAll(impersonationRules())
            addAll(moneyRequestRules())
            addAll(cryptoScamRules())
            addAll(techSupportRules())
            addAll(governmentScamRules())
            addAll(romanceScamRules())
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // BANK_FRAUD
    // ──────────────────────────────────────────────────────────────────

    private fun bankFraudRules(): List<PatternRule> = buildList {

        // ── Spanish (General) ──

        add(PatternRule(
            Regex("\\b(tu|su) (cuenta|tarjeta).{0,30}(suspendid|bloquead|cancelad|eliminad|cerrad)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.4f,
            "ES: Account/card suspended/blocked",
        ))
        add(PatternRule(
            Regex("\\bbanco.{0,25}(bloque|suspend|verific|actualiz|confirm)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.35f,
            "ES: Bank action required",
        ))
        add(PatternRule(
            Regex("\\b(verificar|confirmar|actualizar).{0,20}(datos bancarios|informaci[oó]n bancaria|cuenta bancaria)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.4f,
            "ES: Verify/update banking information",
        ))
        add(PatternRule(
            Regex("\\btarjeta.{0,20}(vencid|expirad|compromet|clonada|robada)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.35f,
            "ES: Card compromised/expired",
        ))
        add(PatternRule(
            Regex("\\bmovimiento.{0,15}(sospech|inusual|no autorizado|fraudulent)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.4f,
            "ES: Suspicious/unauthorized transaction",
        ))
        add(PatternRule(
            Regex("\\b(ingrese|introduzca|proporcione).{0,20}(clave|contraseña|pin|número de tarjeta|cvv|token)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.45f,
            "ES: Request for credentials/PIN/CVV",
        ))
        add(PatternRule(
            Regex("\\b(su|tu) (dinero|fondos|ahorros).{0,20}(riesgo|peligro|compromet)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.35f,
            "ES: Your money is at risk",
        ))
        add(PatternRule(
            Regex("\\b(d[eé]bito|cr[eé]dito).{0,20}(no reconocid|fraudulent|sospech)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.35f,
            "ES: Unrecognized debit/credit",
        ))
        add(PatternRule(
            Regex("\\b(operaci[oó]n|transacci[oó]n|compra).{0,20}(no reconocid|no autorizada|sospechosa|fraudulenta)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.4f,
            "ES: Unauthorized transaction detected",
        ))
        add(PatternRule(
            Regex("\\bseguridad bancaria.{0,25}(contact|llam|comunic)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.3f,
            "ES: Bank security contact request",
        ))
        add(PatternRule(
            Regex("\\bhemos detectado.{0,30}(actividad|movimiento|acceso).{0,20}(sospech|inusual|irregular)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.4f,
            "ES: Suspicious activity detected",
        ))
        add(PatternRule(
            Regex("\\bsu (cuenta|tarjeta) (será|sera|fue|ha sido) (cancelad|bloquead|cerrad)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.4f,
            "ES: Account will be/was cancelled",
        ))
        add(PatternRule(
            Regex("\\bpara (evitar|prevenir).{0,20}(bloqueo|suspensión|cancelación|cierre)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.35f,
            "ES: To avoid blocking/cancellation",
        ))
        add(PatternRule(
            Regex("\\btoken (de seguridad|dinámico|temporal|digital)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.3f,
            "ES: Security token request",
        ))
        add(PatternRule(
            Regex("\\bclave (de|del) (cajero|homebanking|home banking|banca online)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ALL", 0.45f,
            "ES: ATM/homebanking password request",
        ))

        // ── Spanish: Argentina ──

        add(PatternRule(
            Regex("\\bbanco (naci[oó]n|galicia|provincia|santander|bbva|macro|hsbc|supervielle|comafi|patagonia|hipotecario|icbc)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "AR", 0.25f,
            "ES-AR: Argentine bank name",
        ))
        add(PatternRule(
            Regex("\\b(mercadopago|mercado pago|mercado libre).{0,25}(bloque|suspend|verific|problem|compromet|actualiz)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "AR", 0.35f,
            "ES-AR: MercadoPago/MercadoLibre fraud",
        ))
        add(PatternRule(
            Regex("\\b(debin|transferencia inmediata|cbu|cvu|alias).{0,20}(verific|confirm|actualiz|problem)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "AR", 0.3f,
            "ES-AR: CBU/CVU/DEBIN verification",
        ))
        add(PatternRule(
            Regex("\\bhomebanking.{0,20}(bloque|suspend|actualiz|verific)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "AR", 0.35f,
            "ES-AR: Homebanking blocked",
        ))
        add(PatternRule(
            Regex("\\b(billetera virtual|billetera digital).{0,20}(bloquead|compromet|verific)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "AR", 0.3f,
            "ES-AR: Virtual wallet compromised",
        ))

        // ── Spanish: Spain ──

        add(PatternRule(
            Regex("\\b(caixabank|bbva|santander|bankinter|sabadell|unicaja|ibercaja|kutxabank|abanca|openbank|ing direct|evo banco)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ES", 0.2f,
            "ES-ES: Spanish bank name",
        ))
        add(PatternRule(
            Regex("\\bbizum.{0,25}(verific|problem|bloque|suspend|confirm|error)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ES", 0.35f,
            "ES-ES: Bizum verification/problem",
        ))
        add(PatternRule(
            Regex("\\b(clave de firma|firma digital|certificado digital).{0,15}(caduc|actualiz|renov|verific)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "ES", 0.35f,
            "ES-ES: Digital signature/certificate",
        ))

        // ── Spanish: Colombia ──

        add(PatternRule(
            Regex("\\b(bancolombia|davivienda|banco de bogot[aá]|banco popular|colpatria|av villas|banco agrario|nequi|daviplata)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "CO", 0.2f,
            "ES-CO: Colombian bank name",
        ))
        add(PatternRule(
            Regex("\\b(nequi|daviplata).{0,25}(bloque|suspend|verific|problem|compromet)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "CO", 0.35f,
            "ES-CO: Nequi/Daviplata fraud",
        ))
        add(PatternRule(
            Regex("\\bparcero.{0,30}(cuenta|plata|banco|bloque)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "CO", 0.25f,
            "ES-CO: Parcero + bank scam",
        ))

        // ── Spanish: Chile ──

        add(PatternRule(
            Regex("\\b(banco de chile|bancoestado|bci|scotiabank|santander|itaú|security|bice|falabella|ripley)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "CL", 0.2f,
            "ES-CL: Chilean bank name",
        ))
        add(PatternRule(
            Regex("\\b(cuenta rut|cuenta vista|cuenta corriente).{0,20}(bloquead|suspend|problem)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "CL", 0.3f,
            "ES-CL: Cuenta RUT/vista blocked",
        ))
        add(PatternRule(
            Regex("\\bmach.{0,20}(bloque|suspend|verific|problem|compromet)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "CL", 0.3f,
            "ES-CL: Mach wallet fraud",
        ))

        // ── Spanish: Mexico ──

        add(PatternRule(
            Regex("\\b(bbva (m[eé]xico|bancomer)|banamex|banorte|hsbc|scotiabank|santander|azteca|banco del bienestar|citibanamex|inbursa)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "MX", 0.2f,
            "ES-MX: Mexican bank name",
        ))
        add(PatternRule(
            Regex("\\b(spei|clabe).{0,20}(verific|confirm|actualiz|problem|error)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "MX", 0.3f,
            "ES-MX: SPEI/CLABE verification",
        ))
        add(PatternRule(
            Regex("\\bcodi.{0,20}(verific|problem|bloque|actualiz)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "MX", 0.3f,
            "ES-MX: CoDi fraud",
        ))

        // ── Spanish: Peru ──

        add(PatternRule(
            Regex("\\b(bcp|interbank|scotiabank|bbva|banco de la naci[oó]n|mibanco|banco pichincha|yape|plin)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "PE", 0.2f,
            "ES-PE: Peruvian bank/wallet name",
        ))
        add(PatternRule(
            Regex("\\b(yape|plin).{0,25}(bloque|suspend|verific|problem|compromet|error)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "ES", "PE", 0.35f,
            "ES-PE: Yape/Plin fraud",
        ))

        // ── Portuguese: Brazil ──

        add(PatternRule(
            Regex("\\b(sua|seu) (conta|cart[aã]o).{0,30}(suspens|bloquead|cancelad|encerrad|compromet)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.4f,
            "PT-BR: Account/card suspended/blocked",
        ))
        add(PatternRule(
            Regex("\\bbanco.{0,25}(bloque|suspend|verific|atualiz|confirm)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.35f,
            "PT-BR: Bank action required",
        ))
        add(PatternRule(
            Regex("\\b(verificar|confirmar|atualizar).{0,20}(dados banc[aá]rios|informa[cç][aã]o banc[aá]ria|conta banc[aá]ria)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.4f,
            "PT-BR: Verify/update banking data",
        ))
        add(PatternRule(
            Regex("\\bcart[aã]o.{0,20}(vencid|expirad|compromet|clonad|robad)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.35f,
            "PT-BR: Card compromised",
        ))
        add(PatternRule(
            Regex("\\b(movimenta[cç][aã]o|transa[cç][aã]o).{0,15}(suspeita|incomum|n[aã]o autorizada|fraudulenta)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.4f,
            "PT-BR: Suspicious transaction",
        ))
        add(PatternRule(
            Regex("\\b(informe|forne[cç]a|digite).{0,20}(senha|pin|c[oó]digo|token|cvv|n[uú]mero do cart[aã]o)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.45f,
            "PT-BR: Request for credentials/PIN/CVV",
        ))
        add(PatternRule(
            Regex("\\b(seu|sua) (dinheiro|saldo|poupan[cç]a).{0,20}(risco|perigo|compromet)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.35f,
            "PT-BR: Your money is at risk",
        ))
        add(PatternRule(
            Regex("\\bpix.{0,25}(bloque|suspend|verific|problem|compromet|erro|irregular|cancelad)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.35f,
            "PT-BR: PIX blocked/compromised",
        ))
        add(PatternRule(
            Regex("\\b(banco do brasil|bradesco|ita[uú]|santander|caixa|nubank|inter|c6 bank|btg|next|neon|pagbank|pagseguro|picpay|mercado pago)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.2f,
            "PT-BR: Brazilian bank name",
        ))
        add(PatternRule(
            Regex("\\b(nubank|picpay|mercado pago|pagseguro|pagbank).{0,25}(bloque|suspend|verific|problem|compromet|atualiz|erro)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.35f,
            "PT-BR: Fintech wallet fraud",
        ))
        add(PatternRule(
            Regex("\\bdetectamos.{0,30}(atividade|movimenta|acesso).{0,20}(suspeita|incomum|irregular)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.4f,
            "PT-BR: Suspicious activity detected",
        ))
        add(PatternRule(
            Regex("\\bpara (evitar|prevenir).{0,20}(bloqueio|suspens[aã]o|cancelamento|encerramento)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.35f,
            "PT-BR: To avoid blocking/cancellation",
        ))
        add(PatternRule(
            Regex("\\bchave pix.{0,20}(verific|atualiz|confirm|alter|compromet)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.35f,
            "PT-BR: PIX key verification",
        ))
        add(PatternRule(
            Regex("\\bcompra.{0,15}(n[aã]o reconhecida|n[aã]o autorizada|suspeita|fraudulenta|no valor de)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.4f,
            "PT-BR: Unrecognized purchase",
        ))
        add(PatternRule(
            Regex("\\blimite.{0,20}(estourado|excedido|comprometido|bloqueado)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.3f,
            "PT-BR: Credit limit exceeded",
        ))
        add(PatternRule(
            Regex("\\bitoken.{0,15}(expirou|venceu|atualiz|renov)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "PT", "BR", 0.35f,
            "PT-BR: iToken expired",
        ))

        // ── English ──

        add(PatternRule(
            Regex("\\byour (account|card).{0,30}(suspend|block|cancel|delet|clos|compromis|lock)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.4f,
            "EN: Account/card suspended/blocked",
        ))
        add(PatternRule(
            Regex("\\bbank.{0,25}(block|suspend|verif|updat|confirm)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.35f,
            "EN: Bank action required",
        ))
        add(PatternRule(
            Regex("\\b(verify|confirm|update).{0,20}(banking (details|information)|bank account|card details)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.4f,
            "EN: Verify/update banking info",
        ))
        add(PatternRule(
            Regex("\\bcard.{0,20}(expir|compromis|clon|stolen|skim)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.35f,
            "EN: Card compromised",
        ))
        add(PatternRule(
            Regex("\\b(transaction|charge|purchase).{0,20}(suspicious|unauthorized|unrecognized|fraudulent)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.4f,
            "EN: Suspicious transaction",
        ))
        add(PatternRule(
            Regex("\\b(enter|provide|share|give).{0,20}(password|pin|card number|cvv|ssn|social security|routing number|account number)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.45f,
            "EN: Request for credentials/PIN/SSN",
        ))
        add(PatternRule(
            Regex("\\byour (money|funds|savings).{0,20}(at risk|in danger|compromis)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.35f,
            "EN: Your money is at risk",
        ))
        add(PatternRule(
            Regex("\\b(wells fargo|chase|bank of america|citibank|capital one|us bank|pnc|td bank|truist|ally).{0,20}(block|suspend|verif|alert|secur)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.3f,
            "EN: US bank + security action",
        ))
        add(PatternRule(
            Regex("\\bwe (detected|noticed|found).{0,30}(suspicious|unusual|unauthorized).{0,20}(activity|access|login|transaction)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.4f,
            "EN: Suspicious activity detected",
        ))
        add(PatternRule(
            Regex("\\bto (avoid|prevent).{0,20}(suspension|blocking|closure|cancellation|deactivation)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.35f,
            "EN: To avoid suspension/blocking",
        ))
        add(PatternRule(
            Regex("\\b(zelle|venmo|cashapp|cash app|paypal).{0,25}(block|suspend|verif|problem|compromis|limit|alert)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.35f,
            "EN: Payment app fraud",
        ))
        add(PatternRule(
            Regex("\\byour (debit|credit) card.{0,20}(has been|was|will be).{0,15}(charged|used|compromised)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.4f,
            "EN: Card was charged/used",
        ))
        add(PatternRule(
            Regex("\\bunauthorized (login|access|sign.in).{0,20}(your|the) (account|profile)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.4f,
            "EN: Unauthorized access to account",
        ))
        add(PatternRule(
            Regex("\\bwire transfer.{0,20}(pending|failed|held|review|required)", RegexOption.IGNORE_CASE),
            ScamCategory.BANK_FRAUD, "EN", "US", 0.35f,
            "EN: Wire transfer issue",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // PRIZE_SCAM
    // ──────────────────────────────────────────────────────────────────

    private fun prizeScamRules(): List<PatternRule> = buildList {

        // ── Spanish ──

        add(PatternRule(
            Regex("\\b(ganaste|has ganado|ganó|eres el ganador|fuiste seleccionad[ao])", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.4f,
            "ES: You won / you were selected",
        ))
        add(PatternRule(
            Regex("\\b(premio|lotería|sorteo|rifa|bonificación).{0,20}(ganaste|ganó|seleccionad|otorgad)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.45f,
            "ES: Prize/lottery won",
        ))
        add(PatternRule(
            Regex("\\b(felicidades|felicitaciones|enhorabuena).{0,30}(ganad|premio|sorteo|seleccionad)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.4f,
            "ES: Congratulations + prize",
        ))
        add(PatternRule(
            Regex("\\b(reclamar|cobrar|retirar).{0,20}(premio|ganancia|recompensa|bonificación)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.4f,
            "ES: Claim your prize",
        ))
        add(PatternRule(
            Regex("\\bregalo.{0,15}(gratis|gratuito|sin costo|exclusivo)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.3f,
            "ES: Free gift",
        ))
        add(PatternRule(
            Regex("\\b(iphone|samsung|televisor|auto|coche|carro|viaje|vuelo|crucero).{0,20}(gratis|ganad|premio|sorteo|regalo)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.35f,
            "ES: Product giveaway",
        ))
        add(PatternRule(
            Regex("\\b(bono|voucher|cupón|cup[oó]n).{0,20}(gratis|regalo|ganad|exclusiv)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.3f,
            "ES: Free voucher/coupon",
        ))
        add(PatternRule(
            Regex("\\b(whatsapp|facebook|instagram|google|amazon|walmart|coto|carrefour|mercadolibre).{0,20}(sorteo|premio|regala|aniversario|celebra)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.4f,
            "ES: Brand giveaway scam",
        ))
        add(PatternRule(
            Regex("\\b(participar|registrarte).{0,15}(sorteo|rifa|concurso|promoción)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.25f,
            "ES: Enter raffle/contest",
        ))
        add(PatternRule(
            Regex("\\bsolo (quedan|restan) \\d+.{0,15}(premios|regalos|unidades|lugares)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.3f,
            "ES: Only N prizes left",
        ))
        add(PatternRule(
            Regex("\\b(subsidio|ayuda|bono).{0,20}(gobierno|estatal|social|anses|bienestar)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.3f,
            "ES: Government subsidy scam",
        ))
        add(PatternRule(
            Regex("\\b(comparte|reenv[ií]a|manda).{0,40}([a-z0-9]+ (contactos|amigos|grupos)|para (participar|recibir|activar))", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.35f,
            "ES: Share with N contacts to claim",
        ))
        add(PatternRule(
            Regex("\\btu n[uú]mero (fue|ha sido) (seleccionado|elegido|premiado)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.4f,
            "ES: Your number was selected",
        ))
        add(PatternRule(
            Regex("\\bpagar.{0,15}(impuesto|env[ií]o|gestión|trámite).{0,15}(para recibir|para cobrar|del premio)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.45f,
            "ES: Pay fee to receive prize",
        ))
        add(PatternRule(
            Regex("\\b(para recibir|para cobrar).{0,20}(premio|ganancia|recompensa).{0,30}pagar.{0,15}(impuesto|env[ií]o|gestión|trámite)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.45f,
            "ES: Receive prize then pay fee (reversed)",
        ))
        add(PatternRule(
            Regex("\\b(primeros|últimos) \\d+.{0,15}(en (responder|registrarse|contestar))", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.3f,
            "ES: First/last N to respond",
        ))
        add(PatternRule(
            Regex("\\b\\$\\s?\\d{1,3}([.,]\\d{3})+.{0,15}(premio|ganancia|transfer|deposit)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "ALL", 0.35f,
            "ES: Large dollar amount + prize",
        ))

        // ── Spanish: Argentina ──

        add(PatternRule(
            Regex("\\b(anses|potenciar trabajo|progresar).{0,20}(bono|subsidio|pago|cobr|inscrib)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "AR", 0.35f,
            "ES-AR: ANSES/social program scam",
        ))
        add(PatternRule(
            Regex("\\b(ife|auh|asignación universal).{0,20}(bono|extra|nuevo pago|cobrar)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "AR", 0.35f,
            "ES-AR: IFE/AUH bonus scam",
        ))
        add(PatternRule(
            Regex("\\bboludo.{0,30}(gan[eé]|sorteo|premio|plata gratis)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "AR", 0.3f,
            "ES-AR: Boludo + prize slang",
        ))

        // ── Spanish: Mexico ──

        add(PatternRule(
            Regex("\\b(bienestar|becas benito ju[aá]rez|sembrando vida).{0,20}(bono|pago|apoyo|inscrib|registro)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "MX", 0.35f,
            "ES-MX: Welfare program scam",
        ))
        add(PatternRule(
            Regex("\\b(bodega aurrer[aá]|walmart|soriana|chedraui|oxxo|liverpool).{0,20}(sorteo|premio|regala|aniversario|regalo)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "MX", 0.35f,
            "ES-MX: Mexican retailer scam",
        ))

        // ── Spanish: Colombia ──

        add(PatternRule(
            Regex("\\b(ingreso solidario|familias en acci[oó]n|renta ciudadana).{0,20}(bono|pago|inscrib)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "CO", 0.35f,
            "ES-CO: Colombian welfare scam",
        ))
        add(PatternRule(
            Regex("\\bparce.{0,30}(gan[eé]|sorteo|premio|plata gratis)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "ES", "CO", 0.25f,
            "ES-CO: Parce + prize slang",
        ))

        // ── Portuguese: Brazil ──

        add(PatternRule(
            Regex("\\b(voc[eê] ganhou|parab[eé]ns.{0,10}voc[eê]|foi (selecionado|escolhido|sorteado|contemplado))", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.4f,
            "PT-BR: You won / congratulations",
        ))
        add(PatternRule(
            Regex("\\b(pr[eê]mio|loteria|sorteio|rifa|bonifica[cç][aã]o).{0,20}(ganhou|selecionad|contemplad|sorteado)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.45f,
            "PT-BR: Prize/lottery won",
        ))
        add(PatternRule(
            Regex("\\b(resgatar|receber|retirar|sacar).{0,20}(pr[eê]mio|recompensa|bonifica|valor)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Claim your prize",
        ))
        add(PatternRule(
            Regex("\\bpresente.{0,15}(gr[aá]tis|gratuito|sem custo|exclusivo)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Free gift",
        ))
        add(PatternRule(
            Regex("\\b(iphone|samsung|televisão|tv|carro|viagem|voo|cruzeiro).{0,20}(gr[aá]tis|ganhou|pr[eê]mio|sorteio|presente)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Product giveaway",
        ))
        add(PatternRule(
            Regex("\\b(whatsapp|facebook|instagram|google|amazon|magazine luiza|magalu|casas bahia|americanas).{0,20}(sorteio|pr[eê]mio|distribu|anivers[aá]rio|promoc)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Brand giveaway scam",
        ))
        add(PatternRule(
            Regex("\\b(compartilhe|envie|mande).{0,20}(\\d+ (contatos|amigos|grupos)|para (participar|receber|ativar|concorrer))", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Share with contacts to claim",
        ))
        add(PatternRule(
            Regex("\\b(bolsa fam[ií]lia|aux[ií]lio brasil|aux[ií]lio emergencial|fgts|pis|vale g[aá]s).{0,20}(bônus|extra|novo pagamento|receber|sacar|libera)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Government benefit scam",
        ))
        add(PatternRule(
            Regex("\\bseu n[uú]mero foi (selecionado|escolhido|sorteado|premiado|contemplado)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Your number was selected",
        ))
        add(PatternRule(
            Regex("\\bpagar.{0,15}(taxa|frete|imposto|envio).{0,15}(para receber|do pr[eê]mio|para retirar|para liberar)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.45f,
            "PT-BR: Pay fee to receive prize",
        ))
        add(PatternRule(
            Regex("\\b(primeiros|[uú]ltimos) \\d+.{0,15}(a responder|que se cadastrar)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.3f,
            "PT-BR: First/last N to respond",
        ))
        add(PatternRule(
            Regex("\\br\\$\\s?\\d{1,3}([.,]\\d{3})+", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.2f,
            "PT-BR: Large BRL amount",
        ))
        add(PatternRule(
            Regex("\\bsaque.{0,15}(fgts|anivers[aá]rio|extraordin[aá]rio|emergencial).{0,15}(liber|dispon[ií]vel|aprovad)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.3f,
            "PT-BR: FGTS withdrawal scam",
        ))
        add(PatternRule(
            Regex("\\bpix.{0,15}(pr[eê]mio|gr[aá]tis|presente|bonifica|natal|anivers|governo)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "PT", "BR", 0.35f,
            "PT-BR: PIX prize/gift scam",
        ))

        // ── English ──

        add(PatternRule(
            Regex("\\b(you('ve)? won|you (are|have been) (selected|chosen)|congratulations.{0,10}winner)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.4f,
            "EN: You won / selected",
        ))
        add(PatternRule(
            Regex("\\b(prize|lottery|sweepstakes|raffle|giveaway).{0,20}(won|selected|winner|claim|collect)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.45f,
            "EN: Prize/lottery won",
        ))
        add(PatternRule(
            Regex("\\bclaim your.{0,20}(prize|reward|winnings|gift|bonus)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.4f,
            "EN: Claim your prize",
        ))
        add(PatternRule(
            Regex("\\bfree.{0,15}(gift|iphone|samsung|tv|car|trip|vacation|cruise)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.3f,
            "EN: Free product/gift",
        ))
        add(PatternRule(
            Regex("\\b(amazon|walmart|target|costco|apple|google|facebook|instagram|whatsapp).{0,20}(giveaway|raffle|sweepstakes|anniversary|celebrating)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.4f,
            "EN: Brand giveaway scam",
        ))
        add(PatternRule(
            Regex("\\b(share|forward|send).{0,15}(to|with) \\d+ (contacts|friends|groups|people)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.35f,
            "EN: Share with N contacts",
        ))
        add(PatternRule(
            Regex("\\byour number (was|has been) (selected|chosen|picked|drawn)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.4f,
            "EN: Your number was selected",
        ))
        add(PatternRule(
            Regex("\\bpay.{0,15}(fee|tax|shipping|processing).{0,15}(to (receive|claim|collect|get)|for your (prize|winnings))", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.45f,
            "EN: Pay fee to receive prize",
        ))
        add(PatternRule(
            Regex("\\b(first|last) \\d+.{0,15}(to (respond|register|reply|sign up))", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.3f,
            "EN: First/last N to respond",
        ))
        add(PatternRule(
            Regex("\\b\\$\\s?\\d{1,3}(,\\d{3})+(\\.\\d{2})?.{0,15}(prize|reward|won|deposit|transfer|gift)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.35f,
            "EN: Large dollar amount + prize",
        ))
        add(PatternRule(
            Regex("\\bstimulus.{0,15}(check|payment|deposit|money).{0,15}(available|approved|pending|claim)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.35f,
            "EN: Stimulus check scam",
        ))
        add(PatternRule(
            Regex("\\b(government|federal).{0,15}(grant|rebate|refund|benefit).{0,15}(approved|available|eligible|claim)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.35f,
            "EN: Government grant scam",
        ))
        add(PatternRule(
            Regex("\\bonly \\d+.{0,15}(prizes|gifts|units|spots) (left|remaining|available)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.3f,
            "EN: Only N prizes left",
        ))
        add(PatternRule(
            Regex("\\b(gift card|voucher|coupon).{0,15}(free|won|claim|redeem|exclusive)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.3f,
            "EN: Free gift card/voucher",
        ))
        add(PatternRule(
            Regex("\\bcongratulations!?.{0,20}(your|you).{0,10}(won|selected|chosen|winner|lucky)", RegexOption.IGNORE_CASE),
            ScamCategory.PRIZE_SCAM, "EN", "US", 0.4f,
            "EN: Congratulations + winner",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // PHISHING
    // ──────────────────────────────────────────────────────────────────

    private fun phishingRules(): List<PatternRule> = buildList {

        // ── Spanish ──

        add(PatternRule(
            Regex("\\b(haz clic|hac[eé] clic|pulsa|toca|presiona|pincha)\\s+(aqu[ií]|este enlace|este link|el link|el enlace|abajo)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.35f,
            "ES: Click here/this link",
        ))
        add(PatternRule(
            Regex("\\b(código de verificación|c[oó]digo otp|contraseña temporal|clave temporal|código temporal)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.35f,
            "ES: Verification/OTP code",
        ))
        add(PatternRule(
            Regex("\\b(env[ií]a|pas[aá]|compart[ií]|mand[aá]).{0,15}(el|tu|su|un) (c[oó]digo|clave|pin|sms|mensaje)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.4f,
            "ES: Send me the code/PIN",
        ))
        add(PatternRule(
            Regex("\\b(verificar|confirmar|validar) (tu|su) (cuenta|identidad|perfil|n[uú]mero|whatsapp)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.35f,
            "ES: Verify your account/identity",
        ))
        add(PatternRule(
            Regex("\\b(tu|su) (cuenta (de )?|whatsapp |perfil (de )?)(whatsapp )?(será|sera|va a ser) (eliminad|cerrad|suspendid|desactivad)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.4f,
            "ES: Account will be deleted/closed",
        ))
        add(PatternRule(
            Regex("\\b(ingresa|entra) (a|en|al)\\s+(este|el siguiente|el) (enlace|link|sitio)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.3f,
            "ES: Enter this link/site",
        ))
        add(PatternRule(
            Regex("\\bte (lleg[oó]|envi[eé]|mand[eé]).{0,15}(código|clave|sms|mensaje|verificación)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.35f,
            "ES: Did you get the code I sent",
        ))
        add(PatternRule(
            Regex("\\b(por error|sin querer|me equivoqu[eé]).{0,20}(código|clave|mensaje|sms|verificación)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.4f,
            "ES: Sent code by mistake (OTP harvesting)",
        ))
        add(PatternRule(
            Regex("\\b(actualizar|renovar) (tu|su) (whatsapp|app|aplicación|versión)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.3f,
            "ES: Update your WhatsApp/app",
        ))
        add(PatternRule(
            Regex("\\b(descargar|instalar|bajar) (esta|la) (aplicación|app|actualización|versión)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.3f,
            "ES: Download this app/update",
        ))
        add(PatternRule(
            Regex("\\bwhatsapp.{0,20}(nueva versión|versión premium|versión gold|versión dorada|plus|gratis)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.4f,
            "ES: WhatsApp fake version",
        ))
        add(PatternRule(
            Regex("\\b(formulario|encuesta|registro).{0,15}(completar|llenar|rellenar|datos|información)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.25f,
            "ES: Fill out form/survey",
        ))
        add(PatternRule(
            Regex("\\btu whatsapp (está|fue|ha sido|será) (hackeado|comprometido|clonado|robado)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.35f,
            "ES: Your WhatsApp was hacked",
        ))
        add(PatternRule(
            Regex("\\b(datos personales|información personal).{0,20}(verificar|confirmar|actualizar|completar|enviar)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.35f,
            "ES: Personal data verification request",
        ))
        add(PatternRule(
            Regex("\\b(lleg[oó] un código de|recibi[oó] un sms de) (\\d{4,6}|verificación|whatsapp|google)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.4f,
            "ES: Got a verification code from...",
        ))
        add(PatternRule(
            Regex("\\b(escanear?|escane[aá]) (este|el)\\s+(c[oó]digo qr|qr|código)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "ES", "ALL", 0.3f,
            "ES: Scan this QR code",
        ))

        // ── Portuguese: Brazil ──

        add(PatternRule(
            Regex("\\b(clique|toque|aperte|acesse)\\s+(aqui|este link|neste link|no link|abaixo)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.35f,
            "PT-BR: Click here/this link",
        ))
        add(PatternRule(
            Regex("\\b(c[oó]digo de verifica[cç][aã]o|c[oó]digo otp|senha tempor[aá]ria|chave tempor[aá]ria|c[oó]digo tempor[aá]rio)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.35f,
            "PT-BR: Verification/OTP code",
        ))
        add(PatternRule(
            Regex("\\b(envie|passe|compartilhe|mande).{0,15}(o|seu|um) (c[oó]digo|senha|pin|sms|mensagem)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.4f,
            "PT-BR: Send me the code/PIN",
        ))
        add(PatternRule(
            Regex("\\b(verificar|confirmar|validar) (sua|seu) (conta|identidade|perfil|n[uú]mero|whatsapp)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.35f,
            "PT-BR: Verify your account/identity",
        ))
        add(PatternRule(
            Regex("\\b(sua|seu) (conta|whatsapp|perfil) (ser[aá]|vai ser|foi) (eliminad|encerrad|suspens|desativad|bloquead)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.4f,
            "PT-BR: Account will be deleted/suspended",
        ))
        add(PatternRule(
            Regex("\\b(acesse|entre) (neste|no|nesse|no seguinte) (link|site|endere[cç]o)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.3f,
            "PT-BR: Access this link/site",
        ))
        add(PatternRule(
            Regex("\\b(te enviei|chegou|recebi).{0,15}(c[oó]digo|chave|sms|mensagem|verifica[cç][aã]o)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.35f,
            "PT-BR: Did you get the code",
        ))
        add(PatternRule(
            Regex("\\b(por engano|sem querer|me enganei|errei).{0,20}(c[oó]digo|chave|mensagem|sms|verifica[cç][aã]o)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.4f,
            "PT-BR: Sent code by mistake (OTP harvesting)",
        ))
        add(PatternRule(
            Regex("\\b(atualizar|renovar) (seu|sua) (whatsapp|app|aplicativo|vers[aã]o)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.3f,
            "PT-BR: Update your WhatsApp/app",
        ))
        add(PatternRule(
            Regex("\\b(baixar|instalar) (este|o|esse) (aplicativo|app|atualiza[cç][aã]o|vers[aã]o)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.3f,
            "PT-BR: Download this app/update",
        ))
        add(PatternRule(
            Regex("\\bwhatsapp.{0,20}(nova vers[aã]o|vers[aã]o premium|vers[aã]o gold|vers[aã]o dourada|plus|gr[aá]tis)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.4f,
            "PT-BR: WhatsApp fake version",
        ))
        add(PatternRule(
            Regex("\\bseu whatsapp (est[aá]|foi|ser[aá]) (hackeado|comprometido|clonado|roubado|invadido)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.35f,
            "PT-BR: Your WhatsApp was hacked",
        ))
        add(PatternRule(
            Regex("\\b(dados pessoais|informa[cç][oõ]es pessoais).{0,20}(verificar|confirmar|atualizar|completar|enviar)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.35f,
            "PT-BR: Personal data verification request",
        ))
        add(PatternRule(
            Regex("\\b(chegou um c[oó]digo de|recebi um sms de) (\\d{4,6}|verifica[cç][aã]o|whatsapp|google)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.4f,
            "PT-BR: Got a verification code from...",
        ))
        add(PatternRule(
            Regex("\\b(escanear?|escaneie|leia)\\s+(este|o|esse)\\s+(c[oó]digo qr|qr|c[oó]digo)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.3f,
            "PT-BR: Scan this QR code",
        ))
        add(PatternRule(
            Regex("\\bformul[aá]rio.{0,15}(preencher|completar|dados|informa)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.25f,
            "PT-BR: Fill out form",
        ))
        add(PatternRule(
            Regex("\\b(cpf|cnpj).{0,15}(verificar|confirmar|atualizar|regularizar|pendente)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "PT", "BR", 0.35f,
            "PT-BR: CPF/CNPJ verification (common BR phishing)",
        ))

        // ── English ──

        add(PatternRule(
            Regex("\\b(click|tap|press)\\s+(here|this link|below|the link|the button)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.3f,
            "EN: Click here/this link",
        ))
        add(PatternRule(
            Regex("\\b(verification code|otp|one.time (password|code)|temporary (password|code)|security code)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.3f,
            "EN: Verification/OTP code mention",
        ))
        add(PatternRule(
            Regex("\\b(send|share|give|forward).{0,15}(the|your|my) (code|pin|otp|sms|password|message)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.4f,
            "EN: Send me the code/PIN",
        ))
        add(PatternRule(
            Regex("\\b(verify|confirm|validate) your (account|identity|profile|number|phone|email|whatsapp)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.35f,
            "EN: Verify your account/identity",
        ))
        add(PatternRule(
            Regex("\\byour (account|whatsapp|profile) (will be|was|has been|is being) (deleted|closed|suspended|deactivated|terminated|locked)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.4f,
            "EN: Account will be deleted/suspended",
        ))
        add(PatternRule(
            Regex("\\b(visit|go to|open|access)\\s+(this|the following|the)\\s+(link|site|website|page|url)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.25f,
            "EN: Visit this link/site",
        ))
        add(PatternRule(
            Regex("\\b(sent you|received) a.{0,10}(code|pin|otp|verification|sms)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.3f,
            "EN: Sent you / received a code",
        ))
        add(PatternRule(
            Regex("\\b(by mistake|accidentally|by error|wrong number).{0,20}(code|pin|otp|verification|sms|message)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.4f,
            "EN: Sent code by mistake (OTP harvesting)",
        ))
        add(PatternRule(
            Regex("\\b(update|upgrade|renew) your (whatsapp|app|version|software|account)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.3f,
            "EN: Update your WhatsApp/app",
        ))
        add(PatternRule(
            Regex("\\b(download|install)\\s+(this|the|our)\\s+(app|application|update|version|software)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.3f,
            "EN: Download this app/update",
        ))
        add(PatternRule(
            Regex("\\bwhatsapp.{0,20}(new version|premium|gold|plus|pro|free|update required)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.4f,
            "EN: WhatsApp fake version",
        ))
        add(PatternRule(
            Regex("\\byour whatsapp (is|was|has been|will be) (hacked|compromised|cloned|stolen|breached)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.35f,
            "EN: Your WhatsApp was hacked",
        ))
        add(PatternRule(
            Regex("\\b(personal information|personal data).{0,20}(verify|confirm|update|complete|submit|provide)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.35f,
            "EN: Personal data verification request",
        ))
        add(PatternRule(
            Regex("\\b(scan|read)\\s+(this|the)\\s+(qr code|qr|code|barcode)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.3f,
            "EN: Scan this QR code",
        ))
        add(PatternRule(
            Regex("\\b(i|we) sent (a|the) (code|pin|otp).{0,15}(to your|on your)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.35f,
            "EN: We sent a code to your...",
        ))
        add(PatternRule(
            Regex("\\b(fill|complete|submit)\\s+(this|the|our)\\s+(form|survey|questionnaire|application)", RegexOption.IGNORE_CASE),
            ScamCategory.PHISHING, "EN", "US", 0.25f,
            "EN: Fill out form/survey",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // IMPERSONATION
    // ──────────────────────────────────────────────────────────────────

    private fun impersonationRules(): List<PatternRule> = buildList {

        // ── Spanish ──

        add(PatternRule(
            Regex("\\b(mam[aá]|mamita|mami|ma) soy yo", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.45f,
            "ES: Mama soy yo (classic impersonation)",
        ))
        add(PatternRule(
            Regex("\\b(abuela|abuelita|abu) soy yo", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.45f,
            "ES: Abuela soy yo",
        ))
        add(PatternRule(
            Regex("\\b(hola|hey).{0,10}(cambi[eé]|cambie) (de|mi|el) (n[uú]mero|celular|tel[eé]fono|l[ií]nea|chip)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.4f,
            "ES: I changed my number",
        ))
        add(PatternRule(
            Regex("\\b(soy|habla) (tu|su) (hij[ao]|niet[ao]|sobrin[ao]|prim[ao]|nieto|hermano|hermana)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.35f,
            "ES: I am your son/grandson/nephew",
        ))
        add(PatternRule(
            Regex("\\b(me robaron|perd[ií]|se me rompi[oó]) (el|mi) (celular|tel[eé]fono|celu)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.3f,
            "ES: My phone was stolen/lost",
        ))
        add(PatternRule(
            Regex("\\b(este es|este es mi|escribo desde) (mi )?nuevo (n[uú]mero|celular|tel[eé]fono|chip)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.35f,
            "ES: This is my new number",
        ))
        add(PatternRule(
            Regex("\\b(necesito|preciso|ocupo).{0,15}(ayuda|un favor|que me ayudes|que me prestes)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.2f,
            "ES: I need help/favor (low weight - common in legit messages too)",
        ))
        add(PatternRule(
            Regex("\\b(guard[aá]|anot[aá]|agend[aá]) (este|mi) (nuevo )?(n[uú]mero|celular|contacto)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.3f,
            "ES: Save my new number",
        ))
        add(PatternRule(
            Regex("\\b(no le (digas|cuentes|avises) a nadie|entre nosotros|es un secreto|no comentes nada)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.35f,
            "ES: Don't tell anyone (secrecy pressure)",
        ))
        add(PatternRule(
            Regex("\\b(estoy|me encuentro).{0,15}(en problemas|en una emergencia|en peligro|detenid[ao]|pres[ao]|en apuros|complicad[ao])", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.3f,
            "ES: I'm in trouble/emergency",
        ))
        add(PatternRule(
            Regex("\\b(tuve|tengo) un (accidente|problema|inconveniente).{0,20}(necesito|preciso|urge)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.3f,
            "ES: I had an accident, need help",
        ))
        add(PatternRule(
            Regex("\\b(me qued[eé] sin|no tengo) (plata|dinero|saldo|crédito|batería|pila)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.25f,
            "ES: I'm out of money/credit",
        ))
        add(PatternRule(
            Regex("\\bprest[aá]me.{0,20}(plata|dinero|guita|lucas|luca|pesos|dólares|efectivo)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.35f,
            "ES: Lend me money",
        ))
        add(PatternRule(
            Regex("\\b(adivina|adivín[aá]) quién (soy|es|habla|te escribe)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.35f,
            "ES: Guess who I am",
        ))
        add(PatternRule(
            Regex("\\bno (reconoc[eé]s|sab[eé]s qui[eé]n soy|te acord[aá]s de m[ií])", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "ALL", 0.3f,
            "ES: Don't you recognize me",
        ))

        // ── Spanish: Argentina ──

        add(PatternRule(
            Regex("\\b(bolud[ao]|che|loco|wacho).{0,20}(soy yo|cambi[eé] (de|el) n[uú]mero|nuevo n[uú]mero)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "AR", 0.35f,
            "ES-AR: Argentine slang + impersonation",
        ))
        add(PatternRule(
            Regex("\\b(prest[aá]me|pas[aá]me).{0,15}(guita|plata|mangos|lucas)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "AR", 0.35f,
            "ES-AR: Lend me money (Argentine slang)",
        ))
        add(PatternRule(
            Regex("\\bvos.{0,20}(me pod[eé]s|podr[ií]as).{0,15}(prestar|transferir|mandar|pasar).{0,10}(plata|guita|lucas)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "AR", 0.35f,
            "ES-AR: Vos + money request",
        ))

        // ── Spanish: Colombia ──

        add(PatternRule(
            Regex("\\b(parcero|parce|llave|ñero).{0,20}(soy yo|cambi[eé] (de|el) n[uú]mero|nuevo n[uú]mero)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "CO", 0.35f,
            "ES-CO: Colombian slang + impersonation",
        ))

        // ── Spanish: Chile ──

        add(PatternRule(
            Regex("\\b(weon|weón|we[aá]|po|huevón|compadre|compare).{0,20}(soy yo|cambi[eé] (de|el) n[uú]mero|nuevo n[uú]mero)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "CL", 0.35f,
            "ES-CL: Chilean slang + impersonation",
        ))
        add(PatternRule(
            Regex("\\b(prest[aá]me|p[aá]same).{0,15}(lucas|luca|plata)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "CL", 0.35f,
            "ES-CL: Lend me lucas (Chilean money slang)",
        ))

        // ── Spanish: Mexico ──

        add(PatternRule(
            Regex("\\b(carnal|güey|wey|compa|mano|bro).{0,20}(soy yo|cambi[eé] (de|el) n[uú]mero|nuevo n[uú]mero)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "MX", 0.35f,
            "ES-MX: Mexican slang + impersonation",
        ))
        add(PatternRule(
            Regex("\\b(prest[aá]me|p[aá]same).{0,15}(lana|feria|varo|varos|billete)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "MX", 0.35f,
            "ES-MX: Lend me money (Mexican slang)",
        ))

        // ── Spanish: Peru ──

        add(PatternRule(
            Regex("\\b(causa|broder|bróder|pata).{0,20}(soy yo|cambi[eé] (de|el) n[uú]mero|nuevo n[uú]mero)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "ES", "PE", 0.35f,
            "ES-PE: Peruvian slang + impersonation",
        ))

        // ── Portuguese: Brazil ──

        add(PatternRule(
            Regex("\\b(m[aã]e|mãe|mamãe|mãezinha|mainha) sou eu", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.45f,
            "PT-BR: Mãe sou eu (classic impersonation)",
        ))
        add(PatternRule(
            Regex("\\b(vov[oó]|vovó|vovô|v[oó]|avó|avô) sou eu", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.45f,
            "PT-BR: Avó sou eu",
        ))
        add(PatternRule(
            Regex("\\b(pai|papai|paizinho|painho) (preciso|sou eu|me ajuda|preciso de ajuda)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.45f,
            "PT-BR: Pai preciso de ajuda",
        ))
        add(PatternRule(
            Regex("\\b(oi|olá).{0,10}(mudei|troquei) (de|o|meu) (n[uú]mero|celular|telefone|chip)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.4f,
            "PT-BR: I changed my number",
        ))
        add(PatternRule(
            Regex("\\b(sou|aqui [eé]) (seu|sua|o|a) (filh[oa]|net[oa]|sobrinh[oa]|prim[oa]|irm[aã]o|irm[aã])", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.35f,
            "PT-BR: I am your son/grandson/nephew",
        ))
        add(PatternRule(
            Regex("\\b(roubaram|perdi|quebrou) (o|meu) (celular|telefone|aparelho)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.3f,
            "PT-BR: My phone was stolen/lost/broken",
        ))
        add(PatternRule(
            Regex("\\b(este [eé]|esse [eé]|estou com|escrevo de) (meu )?novo (n[uú]mero|celular|telefone|chip)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.35f,
            "PT-BR: This is my new number",
        ))
        add(PatternRule(
            Regex("\\b(salva|anota|adiciona) (esse|este|meu) (novo )?(n[uú]mero|celular|contato)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.3f,
            "PT-BR: Save my new number",
        ))
        add(PatternRule(
            Regex("\\b(n[aã]o (conta|fala|avisa) (pra |para )?ningu[eé]m|entre n[oó]s|[eé] segredo|n[aã]o comenta nada)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.35f,
            "PT-BR: Don't tell anyone",
        ))
        add(PatternRule(
            Regex("\\b(estou|tô|to).{0,15}(em (problema|emerg[eê]ncia|perigo)|detid[oa]|pres[oa]|encrencad[oa]|enrolad[oa])", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.3f,
            "PT-BR: I'm in trouble/emergency",
        ))
        add(PatternRule(
            Regex("\\b(tive|sofri) um (acidente|problema|imprevisto).{0,20}(preciso|necessito|urgente)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.3f,
            "PT-BR: I had an accident, need help",
        ))
        add(PatternRule(
            Regex("\\b(fiquei sem|n[aã]o tenho) (grana|dinheiro|saldo|cr[eé]dito|bateria)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.25f,
            "PT-BR: I'm out of money/credit",
        ))
        add(PatternRule(
            Regex("\\bme empresta.{0,20}(grana|dinheiro|reais|pila|conto|uma grana)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.35f,
            "PT-BR: Lend me money",
        ))
        add(PatternRule(
            Regex("\\b(adivinha|tenta adivinhar) quem (sou|[eé]|est[aá] falando|t[aá] escrevendo)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.35f,
            "PT-BR: Guess who I am",
        ))
        add(PatternRule(
            Regex("\\bn[aã]o (reconhece|sabe quem sou|lembra de mim)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.3f,
            "PT-BR: Don't you recognize me",
        ))
        add(PatternRule(
            Regex("\\bfaz um pix.{0,20}(pra mim|nessa conta|nesse valor|urgente|agora)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.4f,
            "PT-BR: Send me a PIX (after impersonation)",
        ))
        add(PatternRule(
            Regex("\\b(manda|faz|transfere) (um pix|uma transfer[eê]ncia).{0,15}(que|depois|amanh[aã]) (eu|te) (devolvo|pago)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "PT", "BR", 0.4f,
            "PT-BR: Send PIX, I'll pay back",
        ))

        // ── English ──

        add(PatternRule(
            Regex("\\b(mom|mum|mommy|mama|grandma|granny|nana|nan) it'?s me", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.45f,
            "EN: Mom/grandma it's me",
        ))
        add(PatternRule(
            Regex("\\b(hi|hey|hello).{0,10}(i )?changed my (number|phone|cell)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.4f,
            "EN: I changed my number",
        ))
        add(PatternRule(
            Regex("\\b(i'?m|this is|it'?s) your (son|daughter|grandson|granddaughter|nephew|niece|brother|sister|cousin)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.35f,
            "EN: I am your relative",
        ))
        add(PatternRule(
            Regex("\\b(my phone was|i got my phone) (stolen|lost|broken|damaged)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.3f,
            "EN: My phone was stolen/lost",
        ))
        add(PatternRule(
            Regex("\\bthis is my new (number|phone|cell)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.35f,
            "EN: This is my new number",
        ))
        add(PatternRule(
            Regex("\\bsave (this|my) (new )?(number|contact)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.3f,
            "EN: Save my new number",
        ))
        add(PatternRule(
            Regex("\\b(don'?t tell|keep.{0,5}(secret|between us)|don'?t mention|don'?t let.{0,10}know)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.35f,
            "EN: Don't tell anyone",
        ))
        add(PatternRule(
            Regex("\\bi'?m in (trouble|an emergency|danger|jail|custody|a bind|a fix)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.3f,
            "EN: I'm in trouble/emergency",
        ))
        add(PatternRule(
            Regex("\\bi (had|was in) an? (accident|crash|incident|emergency).{0,20}(need|help|money)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.3f,
            "EN: I had an accident, need help",
        ))
        add(PatternRule(
            Regex("\\bi'?m (broke|out of (money|cash|funds)|stranded)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.25f,
            "EN: I'm broke/stranded",
        ))
        add(PatternRule(
            Regex("\\b(lend|loan) me.{0,15}(money|cash|dollars|bucks|some funds)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.35f,
            "EN: Lend me money",
        ))
        add(PatternRule(
            Regex("\\bguess who (this is|i am|it is|is calling|is writing)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.35f,
            "EN: Guess who I am",
        ))
        add(PatternRule(
            Regex("\\b(don'?t you recognize|don'?t you remember|you don'?t know who|do you know who this is)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.3f,
            "EN: Don't you recognize me",
        ))
        add(PatternRule(
            Regex("\\b(send|wire|transfer) (me )?(some )?money.{0,15}(i'?ll|will) (pay|return|give).{0,5}back", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.4f,
            "EN: Send money, I'll pay back",
        ))
        add(PatternRule(
            Regex("\\bi need (your help|a favor|you to help me).{0,20}(money|transfer|send|wire|cash|payment)", RegexOption.IGNORE_CASE),
            ScamCategory.IMPERSONATION, "EN", "US", 0.35f,
            "EN: I need help + money request",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // MONEY_REQUEST
    // ──────────────────────────────────────────────────────────────────

    private fun moneyRequestRules(): List<PatternRule> = buildList {

        // ── Spanish ──

        add(PatternRule(
            Regex("\\b(envía|enviar|transfiere|transferir|deposita|depositar|gira|girar)\\b.{0,15}(dinero|plata|pago|transferencia)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.3f,
            "ES: Send/transfer money",
        ))
        add(PatternRule(
            Regex("\\b(necesito|preciso|urge|ocupo).{0,15}(dinero|plata|un préstamo|una transferencia|que me (mandes|envíes|transfieras))", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.3f,
            "ES: I need money/transfer",
        ))
        add(PatternRule(
            Regex("\\bpagar.{0,10}(ya|ahora|urgente|hoy|antes de|inmediatamente)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.3f,
            "ES: Pay now/urgently",
        ))
        add(PatternRule(
            Regex("\\b(deuda|multa|mora|recargo|penalización).{0,20}(pagar|abonar|saldar|cancelar|liquidar)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.3f,
            "ES: Debt/fine to pay",
        ))
        add(PatternRule(
            Regex("\\b(western union|moneygram|ria|remesa)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.25f,
            "ES: Money transfer service mention",
        ))
        add(PatternRule(
            Regex("\\b(compra|comprar).{0,15}(tarjeta[s]? (de regalo|gift)|giftcard)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.4f,
            "ES: Buy gift cards (common scam payment)",
        ))
        add(PatternRule(
            Regex("\\b(tarjeta[s]? (de regalo|gift|itunes|google play|amazon|steam)).{0,15}(compra|envía|manda|foto|código)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.45f,
            "ES: Gift card + send code/photo",
        ))
        add(PatternRule(
            Regex("\\b(mand[aá]|env[ií]a|pas[aá]).{0,10}(el|los|la) (foto|captura|imagen|comprobante).{0,10}(del|de la)? (tarjeta|código|recibo)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.4f,
            "ES: Send photo/screenshot of card/receipt",
        ))
        add(PatternRule(
            Regex("\\b(recargar|recarga).{0,15}(celular|saldo|crédito)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.2f,
            "ES: Recharge phone credit",
        ))
        add(PatternRule(
            Regex("\\b(si no (pagas|paga|abona|abonas)|de no (pagar|abonar)).{0,45}(consecuencia|acci[oó]n legal|denuncia|embargo|demanda)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.4f,
            "ES: If you don't pay - legal threat",
        ))
        add(PatternRule(
            Regex("\\b(cobro|factura|recibo).{0,15}(pendiente|vencid[ao]|impag[ao]|atrasad[ao])", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.25f,
            "ES: Pending/overdue bill",
        ))
        add(PatternRule(
            Regex("\\btransfer[ií] a (esta|la siguiente) cuenta", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.35f,
            "ES: Transfer to this account",
        ))
        add(PatternRule(
            Regex("\\b(cbu|cvu|alias|clabe|cuenta)\\s*[:=]?\\s*[a-zA-Z0-9.]{8,}", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.25f,
            "ES: Account number / CBU / CLABE provided",
        ))
        add(PatternRule(
            Regex("\\b(te (devuelvo|pago|reintegro) (mañana|después|la semana que viene|el lunes|cuando pueda))", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.25f,
            "ES: I'll pay you back later",
        ))
        add(PatternRule(
            Regex("\\b(es una emergencia|emergencia econ[oó]mica|situaci[oó]n econ[oó]mica).{0,15}(ayuda|plata|dinero|préstamo)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "ALL", 0.3f,
            "ES: Financial emergency",
        ))

        // ── Spanish: Argentina ──

        add(PatternRule(
            Regex("\\b(mand[aá]|pas[aá]|hac[eé]).{0,10}(un|una)? ?(transferencia|depósito) (a|al) (cbu|cvu|alias)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "AR", 0.35f,
            "ES-AR: Transfer to CBU/CVU",
        ))
        add(PatternRule(
            Regex("\\b(mercadopago|mercado pago).{0,15}(mand[aá]|env[ií]a|pas[aá]|transferi)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "AR", 0.25f,
            "ES-AR: MercadoPago transfer request",
        ))
        add(PatternRule(
            Regex("\\b(mand[aá]|env[ií]a|pas[aá]|transferi).{0,20}(plata|dinero|guita).{0,15}(mercadopago|mercado pago)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "AR", 0.3f,
            "ES-AR: Send money via MercadoPago (reversed)",
        ))

        // ── Spanish: Mexico ──

        add(PatternRule(
            Regex("\\b(manda|haz|realiza).{0,20}(transferencia|depósito|spei) (a|al?) (la )?(clabe|cuenta)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "MX", 0.35f,
            "ES-MX: Transfer to CLABE/SPEI",
        ))
        add(PatternRule(
            Regex("\\b(depósito|transferencia) spei.{0,15}(clabe|cuenta)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "ES", "MX", 0.3f,
            "ES-MX: SPEI deposit + CLABE",
        ))

        // ── Portuguese: Brazil ──

        add(PatternRule(
            Regex("\\b(envie|enviar|transfira|transferir|deposite|depositar)\\b.{0,15}(dinheiro|grana|pagamento|transfer[eê]ncia)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.3f,
            "PT-BR: Send/transfer money",
        ))
        add(PatternRule(
            Regex("\\b(preciso|necessito|urgente).{0,15}(dinheiro|grana|empr[eé]stimo|transfer[eê]ncia|que (mande|envie|transfira))", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.3f,
            "PT-BR: I need money/transfer",
        ))
        add(PatternRule(
            Regex("\\bpagar.{0,10}(já|agora|urgente|hoje|antes de|imediatamente)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.3f,
            "PT-BR: Pay now/urgently",
        ))
        add(PatternRule(
            Regex("\\b(d[ií]vida|multa|mora|juros|penalidade).{0,20}(pagar|quitar|saldar|liquidar)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.3f,
            "PT-BR: Debt/fine to pay",
        ))
        add(PatternRule(
            Regex("\\b(compre|comprar).{0,15}(cart[aã]o presente|cart[oõ]es presente|gift.?card)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.4f,
            "PT-BR: Buy gift cards",
        ))
        add(PatternRule(
            Regex("\\b(cart[aã]o presente|gift.?card).{0,15}(compre|envie|mande|foto|c[oó]digo)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.45f,
            "PT-BR: Gift card + send code/photo",
        ))
        add(PatternRule(
            Regex("\\b(mande|envie|fa[cç]a).{0,10}(um|uma)? ?(pix|transfer[eê]ncia|dep[oó]sito|ted|doc).{0,10}(para|pra|nessa|nesta|na)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.35f,
            "PT-BR: Send PIX/transfer to account",
        ))
        add(PatternRule(
            Regex("\\bchave pix\\s*[:=]?\\s*[a-zA-Z0-9@.+\\-]{5,}", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.25f,
            "PT-BR: PIX key provided",
        ))
        add(PatternRule(
            Regex("\\b(se n[aã]o pagar|caso n[aã]o (pague|efetue)).{0,25}(consequ[eê]ncia|a[cç][aã]o (legal|judicial)|den[uú]ncia|penhora|processo|protesto)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.4f,
            "PT-BR: If you don't pay - legal threat",
        ))
        add(PatternRule(
            Regex("\\b(cobran[cç]a|fatura|boleto|conta).{0,15}(pendente|vencid[oa]|atrasad[oa]|em aberto)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.25f,
            "PT-BR: Pending/overdue bill",
        ))
        add(PatternRule(
            Regex("\\btransfira para (essa|esta|a seguinte) conta", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.35f,
            "PT-BR: Transfer to this account",
        ))
        add(PatternRule(
            Regex("\\b(eu|te) (devolvo|pago|reembolso) (amanh[aã]|depois|na semana que vem|quando puder)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.25f,
            "PT-BR: I'll pay you back later",
        ))
        add(PatternRule(
            Regex("\\b([eé] uma emerg[eê]ncia|emerg[eê]ncia financeira|situa[cç][aã]o financeira).{0,15}(ajuda|grana|dinheiro|empr[eé]stimo)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.3f,
            "PT-BR: Financial emergency",
        ))
        add(PatternRule(
            Regex("\\bboleto.{0,15}(pague|pagar|vencendo|vence hoje|urgente|atualizado)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.3f,
            "PT-BR: Boleto urgency",
        ))
        add(PatternRule(
            Regex("\\b(recarga|recarregar|recarregue).{0,15}(celular|saldo|cr[eé]dito)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "PT", "BR", 0.2f,
            "PT-BR: Recharge phone credit",
        ))

        // ── English ──

        add(PatternRule(
            Regex("\\b(send|wire|transfer)\\b.{0,15}(money|payment|funds|cash|dollars)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.3f,
            "EN: Send/wire/transfer money",
        ))
        add(PatternRule(
            Regex("\\bi need.{0,15}(money|cash|funds|a loan|a transfer|you to (send|wire|transfer))", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.3f,
            "EN: I need money/transfer",
        ))
        add(PatternRule(
            Regex("\\bpay.{0,10}(now|today|immediately|right away|urgently|before)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.3f,
            "EN: Pay now/urgently",
        ))
        add(PatternRule(
            Regex("\\b(debt|fine|penalty|overdue|late fee).{0,20}(pay|settle|clear|resolve)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.3f,
            "EN: Debt/fine to pay",
        ))
        add(PatternRule(
            Regex("\\b(buy|purchase|get).{0,15}gift (cards?|certificates?)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.4f,
            "EN: Buy gift cards",
        ))
        add(PatternRule(
            Regex("\\b(gift card|itunes|google play|amazon|steam).{0,15}(buy|send|photo|code|scratch|redeem)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.45f,
            "EN: Gift card + send code/photo",
        ))
        add(PatternRule(
            Regex("\\bsend (me |us )?(the |a )?(photo|picture|screenshot|image) of (the )?(card|receipt|code|back)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.4f,
            "EN: Send photo of card/receipt",
        ))
        add(PatternRule(
            Regex("\\b(if you don'?t pay|failure to pay|non.?payment).{0,25}(consequence|legal action|lawsuit|arrest|prosecution|penalty)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.4f,
            "EN: If you don't pay - legal threat",
        ))
        add(PatternRule(
            Regex("\\b(bill|invoice|payment).{0,15}(overdue|outstanding|unpaid|past due|delinquent)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.25f,
            "EN: Overdue/unpaid bill",
        ))
        add(PatternRule(
            Regex("\\btransfer to (this|the following) (account|routing number|bank)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.35f,
            "EN: Transfer to this account",
        ))
        add(PatternRule(
            Regex("\\b(i'?ll|will) (pay|return|give|send) (you |it )?back (tomorrow|later|next week|soon|when i can)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.2f,
            "EN: I'll pay you back later",
        ))
        add(PatternRule(
            Regex("\\b(it'?s an emergency|financial emergency|desperate situation).{0,15}(help|money|cash|loan|funds)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.3f,
            "EN: Financial emergency",
        ))
        add(PatternRule(
            Regex("\\b(zelle|venmo|cashapp|cash app|paypal|western union|moneygram).{0,15}(send|transfer|pay|wire)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.3f,
            "EN: Payment service + send request",
        ))
        add(PatternRule(
            Regex("\\b(wire|routing|account)\\s*(number|#)?\\s*[:=]?\\s*\\d{6,}", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.25f,
            "EN: Account/routing number provided",
        ))
        add(PatternRule(
            Regex("\\b(reload|top.?up|recharge).{0,15}(phone|cell|mobile|prepaid|card)", RegexOption.IGNORE_CASE),
            ScamCategory.MONEY_REQUEST, "EN", "US", 0.2f,
            "EN: Recharge phone/card",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // CRYPTO_SCAM
    // ──────────────────────────────────────────────────────────────────

    private fun cryptoScamRules(): List<PatternRule> = buildList {

        // ── Spanish ──

        add(PatternRule(
            Regex("\\b(bitcoin|btc|ethereum|eth|cripto|criptomoneda|usdt|tether|binance).{0,20}(invert|oportunidad|ganancia|negocio|rentabilidad|duplicar|triplicar)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.4f,
            "ES: Crypto investment opportunity",
        ))
        add(PatternRule(
            Regex("\\b(inversi[oó]n|inversiones).{0,15}(crypto|cripto|bitcoin|btc|ethereum|eth)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.35f,
            "ES: Investment in crypto",
        ))
        add(PatternRule(
            Regex("\\b(ganar|gana|obtener|obtén).{0,15}(bitcoin|cripto|dinero f[aá]cil|ingresos pasivos|dinero desde casa)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.35f,
            "ES: Earn crypto/easy money",
        ))
        add(PatternRule(
            Regex("\\b(duplicar|duplic[aá]|triplicar|triplic[aá]|multiplicar|multiplic[aá]).{0,15}(tu|su) (dinero|inversi[oó]n|capital|plata)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.4f,
            "ES: Double/triple your money",
        ))
        add(PatternRule(
            Regex("\\b(retorno|rendimiento|ganancia|rentabilidad).{0,15}(\\d+%|garantizad|asegurad|segur)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.4f,
            "ES: Guaranteed returns",
        ))
        add(PatternRule(
            Regex("\\b(trading|forex|opciones binarias|mercado de valores).{0,20}(ganar|ganancia|oportunidad|se[ñn]al|señales)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.35f,
            "ES: Trading/forex opportunity",
        ))
        add(PatternRule(
            Regex("\\b(plataforma|app|aplicación).{0,15}(de inversión|para invertir|de trading|de cripto)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.25f,
            "ES: Investment platform/app",
        ))
        add(PatternRule(
            Regex("\\b(min[ií]mo|solo|apenas).{0,10}(\\$\\d+|\\d+ (d[oó]lares|pesos|euros)).{0,15}(invertir|empezar|comenzar|iniciar)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.3f,
            "ES: Minimum investment amount",
        ))
        add(PatternRule(
            Regex("\\bmi (asesor|mentor|coach).{0,15}(financi|inversi|crypto|cripto)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.3f,
            "ES: My financial advisor/mentor",
        ))
        add(PatternRule(
            Regex("\\b(ingresos pasivos|libertad financiera|independencia financiera|trabaja desde casa|dinero f[aá]cil)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.3f,
            "ES: Passive income/financial freedom",
        ))
        add(PatternRule(
            Regex("\\b(minería|mining).{0,15}(bitcoin|cripto|nube|cloud)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.3f,
            "ES: Crypto mining",
        ))
        add(PatternRule(
            Regex("\\bnft.{0,15}(oportunidad|inversi[oó]n|exclusiv|limitad|ganar|comprar)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.3f,
            "ES: NFT opportunity",
        ))
        add(PatternRule(
            Regex("\\b(wallet|billetera|monedero).{0,15}(enviar|depositar|conectar|vincular|sincronizar)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.3f,
            "ES: Connect/sync wallet",
        ))
        add(PatternRule(
            Regex("\\b(seed phrase|frase semilla|palabras de recuperación|clave privada).{0,10}(comparti|enviar|ingresar|escribir)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.5f,
            "ES: Seed phrase / private key request",
        ))
        add(PatternRule(
            Regex("\\b(compart[ií]|env[ií]a|ingres[aá]|escrib[ií]).{0,15}(tu |su )?(seed phrase|frase semilla|palabras de recuperación|clave privada)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.5f,
            "ES: Share/send seed phrase (reversed)",
        ))
        add(PatternRule(
            Regex("\\b(airdrop|lanzamiento).{0,15}(gratis|gratuito|exclusiv|reclam|recib)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "ES", "ALL", 0.3f,
            "ES: Crypto airdrop",
        ))

        // ── Portuguese: Brazil ──

        add(PatternRule(
            Regex("\\b(bitcoin|btc|ethereum|eth|cripto|criptomoeda|usdt|tether|binance).{0,20}(investir|oportunidade|ganho|lucro|neg[oó]cio|rentabilidade|duplicar|triplicar)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Crypto investment opportunity",
        ))
        add(PatternRule(
            Regex("\\b(investimento|investir).{0,15}(crypto|cripto|bitcoin|btc|ethereum|eth)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Investment in crypto",
        ))
        add(PatternRule(
            Regex("\\b(ganhar|ganhe|obter|receber).{0,15}(bitcoin|cripto|dinheiro f[aá]cil|renda passiva|dinheiro de casa)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Earn crypto/easy money",
        ))
        add(PatternRule(
            Regex("\\b(duplicar|triplicar|multiplicar).{0,15}(seu|sua) (dinheiro|investimento|capital|grana)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Double/triple your money",
        ))
        add(PatternRule(
            Regex("\\b(retorno|rendimento|ganho|lucro|rentabilidade).{0,15}(\\d+%|garantid|assegurad|segur|cert)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Guaranteed returns",
        ))
        add(PatternRule(
            Regex("\\b(trading|forex|op[cç][oõ]es bin[aá]rias|mercado de a[cç][oõ]es).{0,20}(ganhar|lucro|oportunidade|sinal|sinais)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Trading/forex opportunity",
        ))
        add(PatternRule(
            Regex("\\b(plataforma|app|aplicativo).{0,15}(de investimento|para investir|de trading|de cripto)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.25f,
            "PT-BR: Investment platform/app",
        ))
        add(PatternRule(
            Regex("\\b(m[ií]nimo|s[oó]|apenas).{0,10}(r\\$\\s?\\d+|\\d+ (reais|d[oó]lares)).{0,15}(investir|come[cç]ar|iniciar)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Minimum investment amount",
        ))
        add(PatternRule(
            Regex("\\bmeu (assessor|mentor|coach).{0,15}(financeiro|investimento|crypto|cripto)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.3f,
            "PT-BR: My financial advisor/mentor",
        ))
        add(PatternRule(
            Regex("\\b(renda passiva|liberdade financeira|independ[eê]ncia financeira|trabalhe de casa|dinheiro f[aá]cil)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Passive income/financial freedom",
        ))
        add(PatternRule(
            Regex("\\b(minera[cç][aã]o|mining).{0,15}(bitcoin|cripto|nuvem|cloud)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Crypto mining",
        ))
        add(PatternRule(
            Regex("\\bpix.{0,10}(rendendo|investir|multiplicar|dobrar)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.4f,
            "PT-BR: PIX investment scam (BR specific)",
        ))
        add(PatternRule(
            Regex("\\b(seed phrase|frase semente|palavras de recupera[cç][aã]o|chave privada).{0,10}(compartilh|enviar|digitar|escrever)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.5f,
            "PT-BR: Seed phrase / private key request",
        ))
        add(PatternRule(
            Regex("\\b(airdrop|lan[cç]amento).{0,15}(gr[aá]tis|gratuito|exclusiv|resgat|receb)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Crypto airdrop",
        ))
        add(PatternRule(
            Regex("\\b(rob[oô]|bot).{0,15}(de trading|trader|de investimento|autom[aá]tico).{0,15}(lucro|ganho|rendimento)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Trading bot/robot profits",
        ))

        // ── English ──

        add(PatternRule(
            Regex("\\b(bitcoin|btc|ethereum|eth|crypto|cryptocurrency|usdt|tether|binance).{0,20}(invest|opportunity|profit|business|returns|double|triple)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.4f,
            "EN: Crypto investment opportunity",
        ))
        add(PatternRule(
            Regex("\\b(investment|invest in).{0,15}(crypto|bitcoin|btc|ethereum|eth|altcoin)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.35f,
            "EN: Investment in crypto",
        ))
        add(PatternRule(
            Regex("\\b(earn|make|get).{0,15}(bitcoin|crypto|easy money|passive income|money from home|money online)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.35f,
            "EN: Earn crypto/easy money",
        ))
        add(PatternRule(
            Regex("\\b(double|triple|multiply|10x|100x).{0,15}your (money|investment|capital|funds|income)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.4f,
            "EN: Double/triple your money",
        ))
        add(PatternRule(
            Regex("\\b(return|yield|profit|roi).{0,15}(\\d+%|guaranteed|assured|certain)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.4f,
            "EN: Guaranteed returns",
        ))
        add(PatternRule(
            Regex("\\b(trading|forex|binary options|stock market).{0,20}(earn|profit|opportunity|signal|signals)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.35f,
            "EN: Trading/forex opportunity",
        ))
        add(PatternRule(
            Regex("\\b(platform|app|website).{0,15}(for investing|to invest|for trading|for crypto)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.25f,
            "EN: Investment platform/app",
        ))
        add(PatternRule(
            Regex("\\b(minimum|just|only).{0,10}\\$\\d+.{0,15}(to invest|to start|to begin|to get started)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.3f,
            "EN: Minimum investment amount",
        ))
        add(PatternRule(
            Regex("\\bmy (advisor|mentor|coach|manager).{0,15}(financial|investment|crypto|trading)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.3f,
            "EN: My financial advisor/mentor",
        ))
        add(PatternRule(
            Regex("\\b(passive income|financial freedom|financial independence|work from home|easy money|money online)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.25f,
            "EN: Passive income/financial freedom",
        ))
        add(PatternRule(
            Regex("\\b(mining|mine).{0,15}(bitcoin|crypto|cloud|from home)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.3f,
            "EN: Crypto mining",
        ))
        add(PatternRule(
            Regex("\\bnft.{0,15}(opportunity|invest|exclusive|limited|earn|buy|mint)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.3f,
            "EN: NFT opportunity",
        ))
        add(PatternRule(
            Regex("\\b(wallet|metamask|trust wallet).{0,15}(connect|link|sync|verify|validate|enter)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.35f,
            "EN: Connect/sync wallet",
        ))
        add(PatternRule(
            Regex("\\b(seed phrase|recovery phrase|private key|secret phrase|mnemonic).{0,10}(share|send|enter|type|provide|give)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.5f,
            "EN: Seed phrase / private key request",
        ))
        add(PatternRule(
            Regex("\\bairdrop.{0,15}(free|exclusive|claim|receive|collect|limited)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.3f,
            "EN: Crypto airdrop",
        ))
        add(PatternRule(
            Regex("\\b(trading bot|robot|automated).{0,15}(profit|earn|returns|income|trading)", RegexOption.IGNORE_CASE),
            ScamCategory.CRYPTO_SCAM, "EN", "US", 0.35f,
            "EN: Trading bot/robot profits",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // TECH_SUPPORT
    // ──────────────────────────────────────────────────────────────────

    private fun techSupportRules(): List<PatternRule> = buildList {

        // ── Spanish ──

        add(PatternRule(
            Regex("\\b(tu|su) (dispositivo|celular|computadora|teléfono|pc|computador).{0,20}(infectad|virus|malware|hackead|compromet|amenaza|peligro)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.4f,
            "ES: Your device is infected/hacked",
        ))
        add(PatternRule(
            Regex("\\b(virus|malware|troyano|spyware|ransomware).{0,20}(detectad|encontrad|tu|su|en el)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.35f,
            "ES: Virus/malware detected",
        ))
        add(PatternRule(
            Regex("\\b(llam[aá]|contact[aá]|comuníque?se).{0,15}(soporte|servicio técnico|asistencia|mesa de ayuda|help ?desk)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.3f,
            "ES: Call tech support",
        ))
        add(PatternRule(
            Regex("\\b(soporte|servicio) (t[eé]cnico|al cliente).{0,15}(de|del) (whatsapp|microsoft|apple|google|windows|mac)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.35f,
            "ES: Tech support from company",
        ))
        add(PatternRule(
            Regex("\\b(licencia|suscripci[oó]n|antivirus).{0,20}(vencid|expirad|caduc|renov|actualiz)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.3f,
            "ES: License/subscription expired",
        ))
        add(PatternRule(
            Regex("\\b(acceso remoto|teamviewer|anydesk|quicksupport).{0,15}(instalar|descargar|permitir|dar acceso)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.45f,
            "ES: Remote access request",
        ))
        add(PatternRule(
            Regex("\\binstalar.{0,15}(teamviewer|anydesk|quicksupport|remoto)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.45f,
            "ES: Install remote access tool",
        ))
        add(PatternRule(
            Regex("\\b(hemos detectado|se detect[oó]).{0,20}(amenaza|ataque|intrus|actividad maliciosa|acceso no autorizado)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.35f,
            "ES: Threat/attack detected",
        ))
        add(PatternRule(
            Regex("\\b(sus datos|su información|sus archivos).{0,20}(en riesgo|en peligro|serán eliminados|podrían perderse|comprometid)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.35f,
            "ES: Your data is at risk",
        ))
        add(PatternRule(
            Regex("\\b(windows|microsoft|apple|norton|mcafee|avast|kaspersky).{0,10}(alerta|advertencia|aviso|error|problema)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.3f,
            "ES: Company alert/warning",
        ))
        add(PatternRule(
            Regex("\\bllam[aá] al.{0,10}\\+?\\d{7,}", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.3f,
            "ES: Call this phone number",
        ))
        add(PatternRule(
            Regex("\\b(limpiar|eliminar|remover).{0,15}(virus|malware|amenaza|infección)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.25f,
            "ES: Clean/remove virus",
        ))
        add(PatternRule(
            Regex("\\b(pagar|abonar).{0,15}(para|por).{0,15}(reparación|limpieza|soporte|desbloque|recuper)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.35f,
            "ES: Pay for repair/support",
        ))
        add(PatternRule(
            Regex("\\b(tu|su) (whatsapp|cuenta).{0,15}(será|sera|va a ser) (bloqueado|eliminado|cerrado|desactivado) (en|dentro de) [a-z0-9]+ (horas|minutos|d[ií]as)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.4f,
            "ES: Account blocked in N hours",
        ))
        add(PatternRule(
            Regex("\\bsoporte oficial.{0,15}(de|del) (whatsapp|meta|google|apple|microsoft)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "ES", "ALL", 0.35f,
            "ES: Official support from company",
        ))

        // ── Portuguese: Brazil ──

        add(PatternRule(
            Regex("\\b(seu|sua) (dispositivo|celular|computador|telefone|pc).{0,20}(infectad|v[ií]rus|malware|hackeado|comprometid|amea[cç]|perigo)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.4f,
            "PT-BR: Your device is infected/hacked",
        ))
        add(PatternRule(
            Regex("\\b(v[ií]rus|malware|trojan|spyware|ransomware).{0,20}(detectad|encontrad|seu|sua|no)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.35f,
            "PT-BR: Virus/malware detected",
        ))
        add(PatternRule(
            Regex("\\b(ligue|entre em contato|contate).{0,15}(suporte|servi[cç]o t[eé]cnico|assist[eê]ncia|central de atendimento|help ?desk)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.3f,
            "PT-BR: Call tech support",
        ))
        add(PatternRule(
            Regex("\\b(suporte|servi[cç]o) (t[eé]cnico|ao cliente).{0,15}(do|da|de) (whatsapp|microsoft|apple|google|windows|mac)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.35f,
            "PT-BR: Tech support from company",
        ))
        add(PatternRule(
            Regex("\\b(licen[cç]a|assinatura|antiv[ií]rus).{0,20}(vencid|expirad|renov|atualiz)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.3f,
            "PT-BR: License/subscription expired",
        ))
        add(PatternRule(
            Regex("\\b(acesso remoto|teamviewer|anydesk|quicksupport).{0,15}(instalar|baixar|permitir|dar acesso|autorizar)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.45f,
            "PT-BR: Remote access request",
        ))
        add(PatternRule(
            Regex("\\binstalar.{0,15}(teamviewer|anydesk|quicksupport|remoto)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.45f,
            "PT-BR: Install remote access tool",
        ))
        add(PatternRule(
            Regex("\\b(detectamos|foi detectad[oa]).{0,20}(amea[cç]a|ataque|intrus|atividade maliciosa|acesso n[aã]o autorizado)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.35f,
            "PT-BR: Threat/attack detected",
        ))
        add(PatternRule(
            Regex("\\b(seus dados|suas informa[cç][oõ]es|seus arquivos).{0,20}(em risco|em perigo|ser[aã]o (eliminados|apagados)|podem ser perdid)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.35f,
            "PT-BR: Your data is at risk",
        ))
        add(PatternRule(
            Regex("\\bsuporte oficial.{0,15}(do|da|de) (whatsapp|meta|google|apple|microsoft)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.35f,
            "PT-BR: Official support from company",
        ))
        add(PatternRule(
            Regex("\\bligue para.{0,10}\\+?\\d{7,}", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.3f,
            "PT-BR: Call this phone number",
        ))
        add(PatternRule(
            Regex("\\b(pagar|efetuar pagamento).{0,15}(para|pela).{0,15}(reparo|limpeza|suporte|desbloqueio|recupera[cç])", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.35f,
            "PT-BR: Pay for repair/support",
        ))
        add(PatternRule(
            Regex("\\b(seu|sua) (whatsapp|conta).{0,15}(ser[aá]|vai ser) (bloqueado|eliminad|encerrad|desativad) (em|dentro de) \\d+ (horas|minutos|dias)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.4f,
            "PT-BR: Account blocked in N hours",
        ))
        add(PatternRule(
            Regex("\\b(limpar|eliminar|remover).{0,15}(v[ií]rus|malware|amea[cç]a|infec[cç][aã]o)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.25f,
            "PT-BR: Clean/remove virus",
        ))
        add(PatternRule(
            Regex("\\b(windows|microsoft|apple|norton|mcafee|avast|kaspersky).{0,10}(alerta|aviso|erro|problema)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "PT", "BR", 0.3f,
            "PT-BR: Company alert/warning",
        ))

        // ── English ──

        add(PatternRule(
            Regex("\\byour (device|computer|phone|laptop|pc|mac).{0,20}(infected|virus|malware|hacked|compromised|threat|danger)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.4f,
            "EN: Your device is infected/hacked",
        ))
        add(PatternRule(
            Regex("\\b(virus|malware|trojan|spyware|ransomware).{0,20}(detected|found|your|on your|in your)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.35f,
            "EN: Virus/malware detected",
        ))
        add(PatternRule(
            Regex("\\b(call|contact|reach out to).{0,15}(support|tech support|help desk|customer service|assistance)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.25f,
            "EN: Call tech support",
        ))
        add(PatternRule(
            Regex("\\b(tech )?support.{0,15}(from|of|for) (whatsapp|microsoft|apple|google|windows|mac|amazon)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.35f,
            "EN: Tech support from company",
        ))
        add(PatternRule(
            Regex("\\b(license|subscription|antivirus).{0,20}(expired|expiring|renew|update|cancelled)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.3f,
            "EN: License/subscription expired",
        ))
        add(PatternRule(
            Regex("\\b(remote access|teamviewer|anydesk|quicksupport).{0,15}(install|download|allow|grant access|give access)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.45f,
            "EN: Remote access request",
        ))
        add(PatternRule(
            Regex("\\binstall.{0,15}(teamviewer|anydesk|quicksupport|remote)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.45f,
            "EN: Install remote access tool",
        ))
        add(PatternRule(
            Regex("\\b(we (detected|found)|has been detected).{0,20}(threat|attack|intrusion|malicious activity|unauthorized access)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.35f,
            "EN: Threat/attack detected",
        ))
        add(PatternRule(
            Regex("\\byour (data|files|information|photos).{0,20}(at risk|in danger|will be deleted|could be lost|compromised)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.35f,
            "EN: Your data is at risk",
        ))
        add(PatternRule(
            Regex("\\b(windows|microsoft|apple|norton|mcafee|avast|kaspersky).{0,10}(alert|warning|error|problem|notification)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.3f,
            "EN: Company alert/warning",
        ))
        add(PatternRule(
            Regex("\\bcall.{0,5}\\+?\\d{7,}", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.25f,
            "EN: Call this phone number",
        ))
        add(PatternRule(
            Regex("\\b(pay|payment).{0,15}(for|to).{0,15}(repair|cleanup|support|unlock|recover)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.35f,
            "EN: Pay for repair/support",
        ))
        add(PatternRule(
            Regex("\\byour (whatsapp|account) will be (blocked|deleted|closed|deactivated) in \\d+ (hours|minutes|days)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.4f,
            "EN: Account blocked in N hours",
        ))
        add(PatternRule(
            Regex("\\b(clean|remove|eliminate|fix).{0,15}(virus|malware|threat|infection)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.2f,
            "EN: Clean/remove virus",
        ))
        add(PatternRule(
            Regex("\\bofficial (support|team|department).{0,15}(from|of|for) (whatsapp|meta|google|apple|microsoft)", RegexOption.IGNORE_CASE),
            ScamCategory.TECH_SUPPORT, "EN", "US", 0.35f,
            "EN: Official support from company",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // GOVERNMENT_SCAM
    // ──────────────────────────────────────────────────────────────────

    private fun governmentScamRules(): List<PatternRule> = buildList {

        // ── Spanish: Argentina ──

        add(PatternRule(
            Regex("\\b(afip|arca|arba|agip|rentas|api santa fe)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "AR", 0.2f,
            "ES-AR: Argentine tax authority mention",
        ))
        add(PatternRule(
            Regex("\\b(afip|arca).{0,40}(deuda|multa|intimación|requerimiento|embargo|irregularidad|clave fiscal|monotributo)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "AR", 0.4f,
            "ES-AR: AFIP/ARCA debt/penalty",
        ))
        add(PatternRule(
            Regex("\\b(deuda|multa|embargo|irregularidad).{0,30}(afip|arca)\\b", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "AR", 0.4f,
            "ES-AR: debt/penalty + AFIP/ARCA (reversed)",
        ))
        add(PatternRule(
            Regex("\\b(polic[ií]a|gendarmer[ií]a|juzgado|fiscal[ií]a|tribunal|justicia).{0,20}(denuncia|orden|citaci[oó]n|causa|expediente|detenci[oó]n)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "AR", 0.35f,
            "ES-AR: Police/court/legal action",
        ))
        add(PatternRule(
            Regex("\\b(clave fiscal|mi anses|trámite|gestión).{0,15}(vencid|actualiz|renov|caduc|bloqueada)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "AR", 0.3f,
            "ES-AR: Clave fiscal/ANSES renewal",
        ))

        // ── Spanish: Spain ──

        add(PatternRule(
            Regex("\\b(hacienda|agencia tributaria|aeat|seguridad social|tesorer[ií]a)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ES", 0.2f,
            "ES-ES: Spanish tax/social security",
        ))
        add(PatternRule(
            Regex("\\b(hacienda|agencia tributaria|aeat).{0,45}(deuda|multa|sanci[oó]n|requerimiento|embargo|irregularidad|declaraci[oó]n|renta)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ES", 0.4f,
            "ES-ES: Hacienda/AEAT debt/penalty",
        ))
        add(PatternRule(
            Regex("\\b(deuda|multa|sanción|embargo|irregularidad).{0,30}(hacienda|agencia tributaria|aeat)\\b", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ES", 0.4f,
            "ES-ES: debt/penalty + Hacienda (reversed)",
        ))
        add(PatternRule(
            Regex("\\b(polic[ií]a nacional|guardia civil|mossos|ertzaintza|juzgado|fiscal[ií]a).{0,20}(denuncia|orden|citaci[oó]n|causa|diligencias)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ES", 0.35f,
            "ES-ES: Spanish police/court",
        ))
        add(PatternRule(
            Regex("\\b(certificado digital|cl@ve|clave pin).{0,15}(caduc|vencid|actualiz|renov)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ES", 0.3f,
            "ES-ES: Digital certificate renewal",
        ))

        // ── Spanish: Mexico ──

        add(PatternRule(
            Regex("\\b(sat|servicio de administración tributaria|infonavit|imss|profeco)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "MX", 0.2f,
            "ES-MX: Mexican government authority",
        ))
        add(PatternRule(
            Regex("\\b(sat|infonavit|imss).{0,20}(deuda|multa|adeudo|requerimiento|embargo|irregularidad|rfc|declaraci[oó]n)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "MX", 0.4f,
            "ES-MX: SAT/IMSS debt/penalty",
        ))
        add(PatternRule(
            Regex("\\b(e\\.?firma|efirma|fiel|constancia de situaci[oó]n fiscal|rfc).{0,15}(vencid|actualiz|renov|caduc|bloqueada)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "MX", 0.3f,
            "ES-MX: e.firma/RFC renewal",
        ))

        // ── Spanish: Colombia ──

        add(PatternRule(
            Regex("\\b(dian|fiscal[ií]a general|procuradur[ií]a|contralor[ií]a)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "CO", 0.2f,
            "ES-CO: Colombian government authority",
        ))
        add(PatternRule(
            Regex("\\b(dian).{0,20}(deuda|multa|sanci[oó]n|requerimiento|embargo|irregularidad|rut|declaraci[oó]n)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "CO", 0.4f,
            "ES-CO: DIAN debt/penalty",
        ))

        // ── Spanish: Chile ──

        add(PatternRule(
            Regex("\\b(sii|servicio de impuestos internos|tesorería general|isapre|fonasa|afp)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "CL", 0.2f,
            "ES-CL: Chilean government authority",
        ))
        add(PatternRule(
            Regex("\\b(sii|tesorería).{0,20}(deuda|multa|giro|requerimiento|embargo|irregularidad|declaraci[oó]n)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "CL", 0.4f,
            "ES-CL: SII debt/penalty",
        ))

        // ── Spanish: Peru ──

        add(PatternRule(
            Regex("\\b(sunat|sunarp|reniec|onpe|ministerio p[uú]blico)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "PE", 0.2f,
            "ES-PE: Peruvian government authority",
        ))
        add(PatternRule(
            Regex("\\b(sunat).{0,20}(deuda|multa|sanci[oó]n|requerimiento|embargo|irregularidad|ruc|declaraci[oó]n)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "PE", 0.4f,
            "ES-PE: SUNAT debt/penalty",
        ))

        // ── Spanish (General) ──

        add(PatternRule(
            Regex("\\b(orden de arresto|orden de detenci[oó]n|orden judicial|mandamiento judicial|mandato judicial)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ALL", 0.45f,
            "ES: Arrest warrant/court order",
        ))
        add(PatternRule(
            Regex("\\b(será arrestad|será detenid|irá pres|enfrentar[aá] cargos).{0,15}(si no|a menos que|salvo que)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ALL", 0.45f,
            "ES: You will be arrested unless...",
        ))
        add(PatternRule(
            Regex("\\b(pagar|pague|abonar|abone).{0,10}(la )?(multa|sanci[oó]n|deuda|impuesto|tasa).{0,15}(evitar|prevenir).{0,15}(arresto|detenci[oó]n|embargo|consecuencia|acci[oó]n legal)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ALL", 0.45f,
            "ES: Pay to avoid arrest/legal action",
        ))
        add(PatternRule(
            Regex("\\b(irregularidad|anomal[ií]a|inconsistencia).{0,15}(fiscal|tributaria|impositiva|legal|en su declaraci[oó]n)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ALL", 0.3f,
            "ES: Tax/fiscal irregularity",
        ))
        add(PatternRule(
            Regex("\\b(investigaci[oó]n|proceso|expediente|causa).{0,15}(penal|judicial|criminal|legal|en su contra)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ALL", 0.35f,
            "ES: Criminal investigation against you",
        ))
        add(PatternRule(
            Regex("\\b(embargo|congelamiento|retenci[oó]n) de (su |sus )?(bienes|cuenta|fondos|propiedades)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ALL", 0.4f,
            "ES: Asset freeze/seizure",
        ))
        add(PatternRule(
            Regex("\\b(gobierno|autoridad|ente regulador|organismo).{0,10}(le informa|le notifica|le comunica|le advierte)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ALL", 0.3f,
            "ES: Government notifies you",
        ))
        add(PatternRule(
            Regex("\\b(citaci[oó]n|notificaci[oó]n|requerimiento) (judicial|legal|oficial|del juzgado|del tribunal)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ALL", 0.35f,
            "ES: Court summons/legal notice",
        ))
        add(PatternRule(
            Regex("\\b(tiene|usted tiene) (\\d+ )?(d[ií]as|horas).{0,15}(para (pagar|responder|comparecer|regularizar))", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "ES", "ALL", 0.35f,
            "ES: You have N days to pay/respond",
        ))

        // ── Portuguese: Brazil ──

        add(PatternRule(
            Regex("\\b(receita federal|pol[ií]cia federal|minist[eé]rio p[uú]blico|tribunal de justi[cç]a|serasa|spc|detran)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.2f,
            "PT-BR: Brazilian government/legal authority",
        ))
        add(PatternRule(
            Regex("\\b(receita federal).{0,20}(d[ií]vida|multa|irregularidade|pendência|cpf|cnpj|declara[cç][aã]o|imposto de renda)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Receita Federal debt/penalty",
        ))
        add(PatternRule(
            Regex("\\b(pol[ií]cia|delegacia|minist[eé]rio p[uú]blico|tribunal).{0,20}(den[uú]ncia|mandado|intima[cç][aã]o|processo|inqu[eé]rito|deten[cç][aã]o)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Police/court/legal action",
        ))
        add(PatternRule(
            Regex("\\b(mandado|ordem) de (pris[aã]o|busca|deten[cç][aã]o|arresto)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.45f,
            "PT-BR: Arrest/search warrant",
        ))
        add(PatternRule(
            Regex("\\b(ser[aá] preso|ser[aá] detido|enfrentar[aá] processo|responder[aá] criminalmente).{0,15}(se n[aã]o|caso n[aã]o|a menos que)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.45f,
            "PT-BR: You will be arrested unless...",
        ))
        add(PatternRule(
            Regex("\\b(pagar|efetuar pagamento).{0,10}(multa|d[ií]vida|imposto|taxa).{0,15}(evitar|prevenir).{0,15}(pris[aã]o|deten[cç][aã]o|penhora|processo)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.45f,
            "PT-BR: Pay to avoid arrest/seizure",
        ))
        add(PatternRule(
            Regex("\\b(irregularidade|anomalia|inconsist[eê]ncia).{0,15}(fiscal|tribut[aá]ria|no cpf|no cnpj|na declara[cç][aã]o)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Tax/fiscal irregularity",
        ))
        add(PatternRule(
            Regex("\\b(investiga[cç][aã]o|processo|inqu[eé]rito).{0,15}(penal|criminal|judicial|contra voc[eê])", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Criminal investigation",
        ))
        add(PatternRule(
            Regex("\\b(penhora|bloqueio|reten[cç][aã]o) de (bens|conta|fundos|im[oó]veis|sal[aá]rio)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Asset freeze/seizure",
        ))
        add(PatternRule(
            Regex("\\b(governo|autoridade|[oó]rg[aã]o regulador).{0,10}(informa|notifica|comunica|adverte)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Government notifies you",
        ))
        add(PatternRule(
            Regex("\\b(cpf.{0,5}(irregular|pendente|bloqueado|cancelado|suspenso)|seu cpf.{0,15}(ser[aá]|foi|est[aá]) (cancelado|suspenso|bloqueado))", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.4f,
            "PT-BR: CPF irregular/cancelled (very common BR scam)",
        ))
        add(PatternRule(
            Regex("\\b(serasa|spc).{0,15}(negativado|d[ií]vida|cobran[cç]a|regularizar|limpar.{0,5}nome)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Serasa/SPC negative credit",
        ))
        add(PatternRule(
            Regex("\\b(cita[cç][aã]o|notifica[cç][aã]o|intima[cç][aã]o) (judicial|legal|oficial|do tribunal)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Court summons/legal notice",
        ))
        add(PatternRule(
            Regex("\\bvoc[eê] tem (\\d+ )?(dias|horas).{0,15}(para (pagar|responder|comparecer|regularizar))", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.35f,
            "PT-BR: You have N days to pay/respond",
        ))
        add(PatternRule(
            Regex("\\bdetran.{0,20}(multa|d[ií]vida|cnh|suspens[aã]o|infra[cç][aã]o|renova[cç][aã]o)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "PT", "BR", 0.3f,
            "PT-BR: DETRAN fine/CNH suspension",
        ))

        // ── English ──

        add(PatternRule(
            Regex("\\b(irs|internal revenue|social security administration|ssa|fbi|dea|ice|customs)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.2f,
            "EN: US government authority mention",
        ))
        add(PatternRule(
            Regex("\\b(irs|internal revenue).{0,20}(debt|fine|penalty|back taxes|audit|lien|levy|garnish|unpaid|overdue)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.4f,
            "EN: IRS debt/penalty",
        ))
        add(PatternRule(
            Regex("\\b(police|fbi|dea|marshal|sheriff|law enforcement|court).{0,20}(warrant|arrest|charge|summons|subpoena|investigation|case)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.35f,
            "EN: Police/FBI/court action",
        ))
        add(PatternRule(
            Regex("\\b(arrest warrant|bench warrant|court order|legal order)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.45f,
            "EN: Arrest/court warrant",
        ))
        add(PatternRule(
            Regex("\\b(you will be arrested|face arrest|face prosecution|face criminal charges).{0,15}(if you|unless|until you)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.45f,
            "EN: You will be arrested unless...",
        ))
        add(PatternRule(
            Regex("\\bpay.{0,10}(fine|penalty|tax|debt|fee).{0,15}(to avoid|to prevent).{0,15}(arrest|jail|prosecution|seizure|legal action)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.45f,
            "EN: Pay to avoid arrest/legal action",
        ))
        add(PatternRule(
            Regex("\\b(irregularity|discrepancy|violation).{0,15}(tax|fiscal|legal|on your (return|filing|account))", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.3f,
            "EN: Tax/legal irregularity",
        ))
        add(PatternRule(
            Regex("\\b(investigation|case|proceeding).{0,15}(criminal|federal|against you|in your name)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.35f,
            "EN: Criminal investigation",
        ))
        add(PatternRule(
            Regex("\\b(seizure|freeze|garnishment|levy|lien) (of|on) (your )?(assets|account|property|funds|wages)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.4f,
            "EN: Asset seizure/freeze",
        ))
        add(PatternRule(
            Regex("\\b(government|authority|agency).{0,10}(notif|inform|warn|alert)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.25f,
            "EN: Government notifies you",
        ))
        add(PatternRule(
            Regex("\\b(social security (number|benefits?)).{0,20}(suspend|compromis|cancel|frozen|block|terminat)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.4f,
            "EN: SSN suspended/compromised",
        ))
        add(PatternRule(
            Regex("\\b(summons|subpoena|citation|notice).{0,10}(court|legal|judicial|official|federal)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.35f,
            "EN: Court summons/legal notice",
        ))
        add(PatternRule(
            Regex("\\byou have (\\d+ )?(days|hours).{0,15}(to (pay|respond|appear|comply|settle))", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.35f,
            "EN: You have N days to pay/respond",
        ))
        add(PatternRule(
            Regex("\\b(dmv|department of motor vehicles).{0,20}(suspend|fine|penalty|revok|overdue|renew)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.3f,
            "EN: DMV fine/suspension",
        ))
        add(PatternRule(
            Regex("\\b(your (visa|immigration|passport|green card)).{0,20}(revok|cancel|suspend|denied|problem|issue|expired)", RegexOption.IGNORE_CASE),
            ScamCategory.GOVERNMENT_SCAM, "EN", "US", 0.35f,
            "EN: Visa/immigration threat",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // ROMANCE_SCAM
    // ──────────────────────────────────────────────────────────────────

    private fun romanceScamRules(): List<PatternRule> = buildList {

        // ── Spanish ──

        add(PatternRule(
            Regex("\\b(me encantar[ií]a|quiero|deseo|sue[ñn]o con) (conocerte|verte|encontrarte|estar contigo)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.2f,
            "ES: Want to meet/see you (low weight - common in normal messages)",
        ))
        add(PatternRule(
            Regex("\\b(te amo|te quiero|eres el amor de mi vida|eres mi alma gemela|eres especial).{0,20}(desde que te vi|desde el primer momento|nunca sent[ií] esto|por primera vez)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.3f,
            "ES: Love declaration from unknown",
        ))
        add(PatternRule(
            Regex("\\b(soy|trabajo como).{0,10}(militar|soldado|ingeniero|doctor|médico|piloto|marino).{0,20}(en|de|del) (exterior|irak|afganistán|siria|plataforma|barco|base)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.4f,
            "ES: Military/engineer abroad (classic romance scam)",
        ))
        add(PatternRule(
            Regex("\\b(necesito|quiero).{0,15}(enviarte|mandarte) (un regalo|un paquete|dinero|una herencia|oro|joyas)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.35f,
            "ES: Want to send you gift/package",
        ))
        add(PatternRule(
            Regex("\\b(herencia|fortuna|testamento).{0,20}(millones|dólares|euros|compartir contigo|necesito tu ayuda)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.4f,
            "ES: Inheritance to share",
        ))
        add(PatternRule(
            Regex("\\b(viuda|viudo|divorciada|divorciado|sola|solo).{0,15}(busco|buscando|necesito) (compañía|amor|pareja|alguien especial)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.3f,
            "ES: Widow/divorced looking for love",
        ))
        add(PatternRule(
            Regex("\\b(encontr[eé] tu (perfil|foto|número)|te vi en (facebook|instagram|whatsapp)|me dieron tu (número|contacto))", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.3f,
            "ES: Found your profile/photo/number",
        ))
        add(PatternRule(
            Regex("\\b(dios|el destino|el universo).{0,15}(nos juntó|te puso en mi camino|quiere que estemos juntos)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.3f,
            "ES: God/destiny brought us together",
        ))
        add(PatternRule(
            Regex("\\b(tengo|poseo).{0,15}(negocio|empresa|inversiones|propiedades).{0,15}(exitoso|millonario|en el exterior)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.25f,
            "ES: Wealthy person/business owner",
        ))
        add(PatternRule(
            Regex("\\b(necesito dinero|ayuda económica|préstamo).{0,15}(para (viajar|el vuelo|el pasaje|la visa|verte|el hospital|operación|tratamiento))", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.4f,
            "ES: Need money for travel/hospital",
        ))
        add(PatternRule(
            Regex("\\b(estoy (varado|atrapado|retenido)|no puedo salir|me retuvieron).{0,20}(aeropuerto|aduana|frontera|hotel|país)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.35f,
            "ES: Stranded at airport/customs",
        ))
        add(PatternRule(
            Regex("\\b(conf[ií]a en m[ií]|confianza|no desconf[ií]es|por qu[eé] no me crees|si me amaras|si me quisieras)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.25f,
            "ES: Trust manipulation",
        ))
        add(PatternRule(
            Regex("\\b(envíame|mándame) (fotos?|video|tu ubicación) (íntim|privad|desnud|sensual)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.4f,
            "ES: Request for intimate photos (sextortion risk)",
        ))
        add(PatternRule(
            Regex("\\b(no le (digas|cuentes) a (tu familia|tus hijos|nadie)|nuestro secreto|esto queda entre nosotros)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "ES", "ALL", 0.35f,
            "ES: Keep relationship secret from family",
        ))

        // ── Portuguese: Brazil ──

        add(PatternRule(
            Regex("\\b(adoraria|quero|desejo|sonho em) (te conhecer|te ver|te encontrar|estar com voc[eê])", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.2f,
            "PT-BR: Want to meet/see you",
        ))
        add(PatternRule(
            Regex("\\b(te amo|te adoro|voc[eê] [eé] o amor da minha vida|voc[eê] [eé] minha alma g[eê]mea|voc[eê] [eé] especial).{0,20}(desde que te vi|desde o primeiro momento|nunca senti isso)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Love declaration from unknown",
        ))
        add(PatternRule(
            Regex("\\b(sou|trabalho como).{0,10}(militar|soldado|engenheiro|m[eé]dico|piloto|marinheiro).{0,20}(no|na|do|da) (exterior|iraque|afeganist[aã]o|s[ií]ria|plataforma|navio|base)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Military/engineer abroad",
        ))
        add(PatternRule(
            Regex("\\b(preciso|quero).{0,15}(te enviar|te mandar) (um presente|um pacote|dinheiro|uma heran[cç]a|ouro|j[oó]ias)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Want to send you gift/package",
        ))
        add(PatternRule(
            Regex("\\b(heran[cç]a|fortuna|testamento).{0,20}(milh[oõ]es|d[oó]lares|reais|compartilhar com voc[eê]|preciso da sua ajuda)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Inheritance to share",
        ))
        add(PatternRule(
            Regex("\\b(vi[uú]v[ao]|divorciad[ao]|sozinh[ao]).{0,15}(procuro|procurando|preciso de|busco) (companhia|amor|parceiro|algu[eé]m especial)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Widow/divorced looking for love",
        ))
        add(PatternRule(
            Regex("\\b(encontrei (seu|sua) (perfil|foto|n[uú]mero)|te vi no (facebook|instagram|whatsapp)|me deram (seu|o seu) (n[uú]mero|contato))", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.3f,
            "PT-BR: Found your profile/photo/number",
        ))
        add(PatternRule(
            Regex("\\b(deus|o destino|o universo).{0,15}(nos juntou|te colocou no meu caminho|quer que fiquemos juntos)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.3f,
            "PT-BR: God/destiny brought us together",
        ))
        add(PatternRule(
            Regex("\\b(preciso de dinheiro|ajuda financeira|empr[eé]stimo).{0,15}(para (viajar|a passagem|o voo|o visto|te ver|o hospital|opera[cç][aã]o|tratamento))", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Need money for travel/hospital",
        ))
        add(PatternRule(
            Regex("\\b(estou (preso|retido|parado)|n[aã]o consigo sair|me retiveram).{0,20}(aeroporto|alfândega|fronteira|hotel|pa[ií]s)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Stranded at airport/customs",
        ))
        add(PatternRule(
            Regex("\\b(confia em mim|confian[cç]a|n[aã]o desconfie|por que n[aã]o (acredita|confia)|se me amasse)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.25f,
            "PT-BR: Trust manipulation",
        ))
        add(PatternRule(
            Regex("\\b(me envia|me manda) (fotos?|v[ií]deo|sua localiza[cç][aã]o) ([ií]ntim|privad|sensual)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.4f,
            "PT-BR: Request for intimate photos",
        ))
        add(PatternRule(
            Regex("\\b(n[aã]o (conta|fala) (pra|para) (sua fam[ií]lia|seus filhos|ningu[eé]m)|nosso segredo|fica entre n[oó]s)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.35f,
            "PT-BR: Keep relationship secret from family",
        ))
        add(PatternRule(
            Regex("\\b(tenho|possuo).{0,15}(neg[oó]cio|empresa|investimentos|propriedades).{0,15}(de sucesso|milion[aá]rio|no exterior)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.25f,
            "PT-BR: Wealthy person/business owner",
        ))
        add(PatternRule(
            Regex("\\b(meu cora[cç][aã]o|meu amor|minha vida|meu bem|meu anjo).{0,20}(s[oó] voc[eê]|[eé] voc[eê]|preciso de voc[eê]|me ajuda)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "PT", "BR", 0.2f,
            "PT-BR: Pet names + need (low weight - common in normal messages)",
        ))

        // ── English ──

        add(PatternRule(
            Regex("\\b(i'?d love to|i want to|i dream of) (meet|see|find|be with) you", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.2f,
            "EN: Want to meet/see you",
        ))
        add(PatternRule(
            Regex("\\b(i love you|you are the love of my life|you are my soulmate|you are special).{0,20}(since i saw|from the first moment|never felt this|for the first time)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.3f,
            "EN: Love declaration from unknown",
        ))
        add(PatternRule(
            Regex("\\b(i'?m a|i work as a?n?).{0,10}(military|soldier|army|engineer|doctor|pilot|sailor|marine).{0,20}(in|from|deployed|stationed|on).{0,10}(overseas|abroad|iraq|afghanistan|syria|oil rig|ship|base|platform)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.4f,
            "EN: Military/engineer abroad",
        ))
        add(PatternRule(
            Regex("\\b(i need to|i want to).{0,15}(send you|ship you) (a gift|a package|money|an inheritance|gold|jewel)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.35f,
            "EN: Want to send you gift/package",
        ))
        add(PatternRule(
            Regex("\\b(inheritance|fortune|will|estate).{0,20}(millions?|dollars|share with you|need your help)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.4f,
            "EN: Inheritance to share",
        ))
        add(PatternRule(
            Regex("\\b(widow|widower|divorced|alone|lonely).{0,15}(looking for|seeking|need) (companionship|love|partner|someone special)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.3f,
            "EN: Widow/divorced looking for love",
        ))
        add(PatternRule(
            Regex("\\b(found your (profile|photo|number|pic)|saw you on (facebook|instagram|whatsapp)|someone gave me your (number|contact))", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.3f,
            "EN: Found your profile/photo/number",
        ))
        add(PatternRule(
            Regex("\\b(god|destiny|fate|the universe).{0,15}(brought us together|put you in my life|wants us to be together)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.3f,
            "EN: God/destiny brought us together",
        ))
        add(PatternRule(
            Regex("\\bi (have|own).{0,15}(business|company|investments|properties).{0,15}(successful|millionaire|overseas|abroad)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.25f,
            "EN: Wealthy person/business owner",
        ))
        add(PatternRule(
            Regex("\\b(i need money|financial help|a loan).{0,15}(to travel|for (the )?flight|for (the )?ticket|for (the )?visa|to see you|for (the )?hospital|for (the )?surgery|for (the )?treatment)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.4f,
            "EN: Need money for travel/hospital",
        ))
        add(PatternRule(
            Regex("\\b(i'?m (stranded|stuck|trapped|detained)|can'?t (leave|get out)|they detained me).{0,20}(airport|customs|border|hotel|country)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.35f,
            "EN: Stranded at airport/customs",
        ))
        add(PatternRule(
            Regex("\\b(trust me|have faith|don'?t doubt|why don'?t you believe|if you loved me|if you cared)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.2f,
            "EN: Trust manipulation",
        ))
        add(PatternRule(
            Regex("\\bsend me (your )?(intimate|private|naked|nude|sexy) (photos?|pictures?|videos?)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.4f,
            "EN: Request for intimate photos",
        ))
        add(PatternRule(
            Regex("\\b(don'?t tell (your family|your kids|anyone)|our secret|this stays between us|keep this between us)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.35f,
            "EN: Keep relationship secret from family",
        ))
        add(PatternRule(
            Regex("\\b(my darling|my love|my dear|my sweetheart|my honey|my angel|my beloved).{0,20}(i need|help me|send me|please)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.3f,
            "EN: Pet names + request",
        ))
        add(PatternRule(
            Regex("\\b(un officer|un military|united nations).{0,20}(retirement|leave|box|package|fund|gold|trunk)", RegexOption.IGNORE_CASE),
            ScamCategory.ROMANCE_SCAM, "EN", "US", 0.4f,
            "EN: UN/military package/fund scam",
        ))
    }
}
