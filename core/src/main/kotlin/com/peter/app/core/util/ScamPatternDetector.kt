package com.peter.app.core.util

/**
 * Conservative scam/spam pattern detector for WhatsApp messages.
 * Only flags high-confidence matches to avoid hiding real messages.
 */
object ScamPatternDetector {

    private val SUSPICIOUS_PATTERNS = listOf(
        // Prize / lottery scams
        Regex("(?i)(ganaste|has ganado|premio|lotería|sorteo)", RegexOption.IGNORE_CASE),
        Regex("(?i)(you('ve)? won|prize|lottery|giveaway)", RegexOption.IGNORE_CASE),

        // Urgency + action
        Regex("(?i)urgente.{0,20}(acción|responde|contacta)", RegexOption.IGNORE_CASE),
        Regex("(?i)urgent.{0,20}(action|reply|respond)", RegexOption.IGNORE_CASE),

        // Account threats
        Regex("(?i)(tu cuenta|su cuenta).{0,20}(suspendid|bloquead|eliminad|cerrad)", RegexOption.IGNORE_CASE),
        Regex("(?i)your (account|whatsapp).{0,20}(suspend|block|delet|clos)", RegexOption.IGNORE_CASE),

        // Verification / OTP harvesting
        Regex("(?i)(código de verificación|OTP|contraseña temporal)", RegexOption.IGNORE_CASE),
        Regex("(?i)(verification code|one.time.password)", RegexOption.IGNORE_CASE),

        // Bank / financial scams
        Regex("(?i)banco.{0,20}(bloque|suspend|verific|actualiz)", RegexOption.IGNORE_CASE),
        Regex("(?i)bank.{0,20}(block|suspend|verify|update)", RegexOption.IGNORE_CASE),

        // Money requests
        Regex("(?i)(envía|enviar|transfiere).{0,15}(dinero|pago|transferencia)", RegexOption.IGNORE_CASE),
        Regex("(?i)send.{0,15}(money|payment|transfer)", RegexOption.IGNORE_CASE),

        // Crypto scams
        Regex("(?i)(bitcoin|crypto).{0,15}(invert|oportunidad|ganancia)", RegexOption.IGNORE_CASE),
        Regex("(?i)(bitcoin|crypto).{0,15}(invest|opportunity|profit)", RegexOption.IGNORE_CASE),

        // Click bait
        Regex("(?i)(haz clic|pulsa|toca) (aquí|este enlace|el link)", RegexOption.IGNORE_CASE),
        Regex("(?i)click (here|this link|below)", RegexOption.IGNORE_CASE),
    )

    data class ScamAnalysis(
        val isSuspicious: Boolean,
        val matchedPattern: String = "",
    )

    fun analyze(text: String): ScamAnalysis {
        for (pattern in SUSPICIOUS_PATTERNS) {
            val match = pattern.find(text)
            if (match != null) {
                return ScamAnalysis(
                    isSuspicious = true,
                    matchedPattern = match.value,
                )
            }
        }
        return ScamAnalysis(isSuspicious = false)
    }
}
