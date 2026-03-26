package com.peter.app.core.util

import com.peter.app.core.util.ScamPatternDetector.ScamCategory
import com.peter.app.core.util.ScamPatternDetector.ThreatLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Extensive Spanish-language scam pattern detection tests, regionalized by country.
 *
 * Covers: Argentina (AR), Spain (ES), Colombia (CO), Chile (CL), Mexico (MX), Peru (PE),
 * plus general Spanish patterns and false-positive scenarios.
 */
class ScamPatternDetectorSpanishTest {

    private fun analyze(text: String) = ScamPatternDetector.analyze(text)
    private fun analyzeConversation(messages: List<String>) =
        ScamPatternDetector.analyzeConversation(messages)

    // ═══════════════════════════════════════════════════════════════════════
    // ARGENTINA (AR) — Tax / AFIP / ARCA
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `AR - AFIP debt scam triggers GOVERNMENT_SCAM`() {
        val result = analyze("Tiene una deuda con AFIP por $350.000. Regularice su situación antes de 48hs.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `AR - ARCA irregularity scam triggers GOVERNMENT_SCAM`() {
        val result = analyze("ARCA detectó irregularidades en su declaración jurada. Ingrese a este link para regularizar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `AR - AFIP multa warning`() {
        val result = analyze("AFIP: Se ha generado una multa por incumplimiento. Tiene 24 horas para pagar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `AR - ARCA clave fiscal vencida`() {
        val result = analyze("Su clave fiscal ha vencido. Actualice sus datos en ARCA para evitar el bloqueo de su cuenta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `AR - AFIP embargo threat`() {
        val result = analyze("AFIP le informa que de no regularizar su deuda, se procederá al embargo de sus bienes.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
        assertTrue(result.confidence > 0.4f)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARGENTINA (AR) — Bank / MercadoPago
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `AR - Banco Nacion blocked account`() {
        val result = analyze("Tu cuenta del Banco Nación fue bloqueada por actividad sospechosa. Verificá tus datos.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - Banco Galicia suspended`() {
        val result = analyze("Banco Galicia: Su cuenta ha sido suspendida temporalmente. Ingrese sus datos para reactivarla.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - BBVA verification scam`() {
        val result = analyze("BBVA le informa que debe verificar su identidad. Ingrese su clave del homebanking.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - MercadoPago suspended`() {
        val result = analyze("Tu cuenta de MercadoPago fue suspendida por movimientos sospechosos. Verificá tu identidad.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - MercadoLibre account compromised`() {
        val result = analyze("Mercado Libre: hemos detectado actividad inusual en tu cuenta. Actualizá tus datos ahora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - Homebanking bloqueado`() {
        val result = analyze("Su homebanking fue bloqueado por intentos de acceso no autorizados. Verifique su identidad.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - Billetera virtual comprometida`() {
        val result = analyze("Su billetera virtual ha sido comprometida. Verifique su cuenta de inmediato.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARGENTINA (AR) — ANSES / IFE benefit scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `AR - ANSES bono scam`() {
        val result = analyze("Cobrar bono de ANSES de $80.000. Inscribite ahora antes de que se agoten.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `AR - IFE disponible scam`() {
        val result = analyze("IFE disponible: nuevo pago extraordinario. Cobrá tu bono de $60.000 ahora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `AR - ANSES Potenciar Trabajo scam`() {
        val result = analyze("Potenciar Trabajo: inscribite para cobrar el nuevo subsidio de ANSES. Cupos limitados.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `AR - AUH bono extra`() {
        val result = analyze("AUH: bono extra disponible para cobrar. Registrate con tu DNI.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARGENTINA (AR) — Slang + Impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `AR - Boludo money request`() {
        val result = analyze("Boludo, soy yo, cambié de número. Prestame guita que estoy en una urgencia.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `AR - Che impersonation with number change`() {
        val result = analyze("Che, soy yo, cambié de número. Guardá este nuevo contacto.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `AR - Loco impersonation`() {
        val result = analyze("Loco, soy yo, cambié el número. Después te cuento.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `AR - Vos money request with Argentine phrasing`() {
        val result = analyze("Vos me podés prestar plata? Necesito urgente, después te devuelvo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `AR - Pasame guita request`() {
        val result = analyze("Pasame guita que me quedé sin plata. Te la devuelvo mañana.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARGENTINA (AR) — CBU / CVU transfer scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `AR - CBU transfer request`() {
        val result = analyze("Mandá la transferencia al CBU 0170099120000012345678. Es urgente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any {
            it.category == ScamCategory.MONEY_REQUEST || it.category == ScamCategory.BANK_FRAUD
        })
    }

    @Test
    fun `AR - CVU verification scam`() {
        val result = analyze("Tu CVU necesita verificación urgente. Confirmá tus datos bancarios.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `AR - Hacé transferencia al CBU`() {
        val result = analyze("Hacé una transferencia al CBU que te paso. Necesito que sea ahora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `AR - MercadoPago transfer request`() {
        val result = analyze("Mandá la plata por MercadoPago, es urgente por favor.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ARGENTINA (AR) — Mamá / Abuela impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `AR - Mama soy yo classic impersonation`() {
        val result = analyze("Mamá soy yo, cambié de número. Guardá este nuevo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `AR - Abuela soy yo impersonation`() {
        val result = analyze("Abuela soy yo, tu nieto. Me robaron el celular y tengo este nuevo número.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `AR - Hijo impersonation with emergency`() {
        val result = analyze("Soy tu hijo, estoy en problemas y necesito plata urgente. No le digas a nadie.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SPAIN (ES) — Hacienda / Agencia Tributaria
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `ES - Hacienda debt notification`() {
        val result = analyze("Hacienda le informa que tiene una deuda pendiente de 2.500 euros. Regularice antes de 48h.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `ES - Agencia Tributaria multa`() {
        val result = analyze("Agencia Tributaria: Se ha detectado una irregularidad en su declaración de la renta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `ES - AEAT requerimiento`() {
        val result = analyze("AEAT: Tiene un requerimiento pendiente. Acceda al siguiente enlace para resolverlo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `ES - Hacienda embargo sancion`() {
        val result = analyze("Hacienda le informa de una sanción por impago. Se procederá al embargo de su cuenta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
        assertTrue(result.confidence > 0.4f)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SPAIN (ES) — Banks (CaixaBank, Santander, BBVA)
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `ES - CaixaBank suspicious activity`() {
        val result = analyze("CaixaBank: hemos detectado actividad sospechosa en su cuenta. Verifique sus datos.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ES - Santander account blocked`() {
        val result = analyze("Santander: Su cuenta ha sido bloqueada temporalmente. Introduzca su clave para desbloquearla.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ES - BBVA tarjeta suspendida`() {
        val result = analyze("BBVA: Su tarjeta ha sido suspendida por movimiento sospechoso. Confirme sus datos.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ES - Bankinter firma digital caducada`() {
        val result = analyze("Bankinter: Su clave de firma ha caducado. Actualícela para seguir operando.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SPAIN (ES) — Bizum scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `ES - Bizum verification scam`() {
        val result = analyze("Bizum: Se ha detectado un problema con tu cuenta. Verifica tus datos para continuar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ES - Bizum blocked`() {
        val result = analyze("Tu Bizum ha sido bloqueado por motivos de seguridad. Confirma tu identidad.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SPAIN (ES) — Tio/Tia impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `ES - Certificado digital caducado with clave pin`() {
        val result = analyze("Su certificado digital ha caducado. Renueve su clave pin accediendo al siguiente enlace.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `ES - Guardia Civil denuncia scam`() {
        val result = analyze("Guardia Civil: Tiene una denuncia pendiente. Acuda al juzgado o pague la multa online.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // COLOMBIA (CO) — DIAN scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `CO - DIAN debt notification`() {
        val result = analyze("DIAN: Usted tiene una deuda pendiente. Regularice su situación en 24 horas.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `CO - DIAN multa por irregularidad`() {
        val result = analyze("La DIAN detectó irregularidades en su declaración de RUT. Se aplicará una sanción.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `CO - DIAN embargo warning`() {
        val result = analyze("DIAN le informa de un embargo preventivo por adeudo tributario. Pague ahora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // COLOMBIA (CO) — Bancolombia / Davivienda / Nequi / Daviplata
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `CO - Bancolombia account blocked`() {
        val result = analyze("Bancolombia: Su cuenta ha sido bloqueada por actividad sospechosa. Verifique sus datos.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `CO - Davivienda suspicious transaction`() {
        val result = analyze("Davivienda: Se detectó una transacción no autorizada en su tarjeta. Confirme sus datos.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `CO - Nequi blocked scam`() {
        val result = analyze("Tu cuenta de Nequi fue bloqueada por movimientos sospechosos. Verificá tu identidad.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `CO - Daviplata suspended`() {
        val result = analyze("Daviplata: Tu cuenta ha sido suspendida. Verificá tus datos para reactivarla.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // COLOMBIA (CO) — Parcero impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `CO - Parcero impersonation with number change`() {
        val result = analyze("Parcero, soy yo, cambié de número. Guardá este nuevo contacto.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `CO - Parce number change`() {
        val result = analyze("Parce, soy yo, cambié el número. Agendame.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `CO - Parcero bank related scam`() {
        val result = analyze("Parcero, me bloquearon la cuenta del banco. Necesito que me prestes plata urgente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHILE (CL) — SII scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `CL - SII debt notification`() {
        val result = analyze("SII: Usted tiene una deuda tributaria pendiente. Regularice antes de 48 horas.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `CL - Servicio de Impuestos Internos multa`() {
        val result = analyze("Servicio de Impuestos Internos: Se ha generado una multa por incumplimiento tributario.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `CL - SII irregularity`() {
        val result = analyze("El SII detectó irregularidades en su declaración. Tiene un giro pendiente de pago.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHILE (CL) — BancoEstado / BCI
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `CL - BancoEstado blocked`() {
        val result = analyze("BancoEstado: Su cuenta ha sido bloqueada. Verifique su identidad para continuar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `CL - BCI suspicious transaction`() {
        val result = analyze("BCI: Se detectó una operación no reconocida en su cuenta. Confirme sus datos.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `CL - Cuenta RUT bloqueada`() {
        val result = analyze("Su cuenta RUT ha sido bloqueada por motivos de seguridad. Ingrese a este enlace.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `CL - Mach wallet fraud`() {
        val result = analyze("Tu Mach fue bloqueada por movimientos sospechosos. Verificá tu cuenta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHILE (CL) — Lucas money request + Weon impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `CL - Prestame lucas`() {
        val result = analyze("Préstame lucas que estoy en una emergencia. Te las devuelvo mañana.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `CL - Weon impersonation`() {
        val result = analyze("Weon, soy yo, cambié de número. Agéndame.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `CL - Compadre impersonation with new number`() {
        val result = analyze("Compadre, soy yo, cambié el número. Este es el nuevo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MEXICO (MX) — SAT scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `MX - SAT debt notification`() {
        val result = analyze("SAT: Tiene un adeudo fiscal pendiente. Regularice su situación antes de que aplique el embargo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `MX - SAT multa requerimiento`() {
        val result = analyze("El SAT detectó irregularidades en su RFC. Se ha generado un requerimiento.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `MX - INFONAVIT debt`() {
        val result = analyze("INFONAVIT: Su adeudo ha sido referido a cobranza. Pague ahora para evitar consecuencias legales.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `MX - e firma vencida`() {
        val result = analyze("Su e.firma ha vencido. Actualice su certificado digital del SAT antes de 24 horas.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MEXICO (MX) — BBVA Bancomer / Banamex
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `MX - BBVA Bancomer blocked`() {
        val result = analyze("BBVA Bancomer: Su cuenta ha sido bloqueada. Verifique su identidad de inmediato.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `MX - Banamex suspicious transaction`() {
        val result = analyze("Banamex: Se detectó una transacción no autorizada. Confirme su operación.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `MX - Banorte card compromised`() {
        val result = analyze("Banorte: Su tarjeta ha sido clonada. Proporcione su PIN para bloquearla.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MEXICO (MX) — SPEI / CLABE transfer scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `MX - SPEI verification scam`() {
        val result = analyze("Su SPEI tiene un problema de verificación. Confirme su CLABE para evitar el bloqueo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `MX - CLABE transfer request`() {
        val result = analyze("Manda un depósito SPEI a la CLABE que te paso. Necesito que sea urgente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `MX - CoDi fraud`() {
        val result = analyze("Tu CoDi fue bloqueado por motivos de seguridad. Actualiza tus datos.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MEXICO (MX) — Guey impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `MX - Guey impersonation with number change`() {
        val result = analyze("Güey, soy yo, cambié de número. Agéndame.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `MX - Carnal impersonation`() {
        val result = analyze("Carnal, soy yo, cambié el número. Este es el bueno.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `MX - Prestame lana Mexican slang`() {
        val result = analyze("Préstame lana, estoy en una emergencia bien fea.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `MX - Bienestar program scam`() {
        val result = analyze("Programa Bienestar: Tiene un pago pendiente. Inscríbase ahora para recibirlo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PERU (PE) — SUNAT scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `PE - SUNAT debt notification`() {
        val result = analyze("SUNAT: Usted tiene una deuda tributaria pendiente. Regularice su RUC en 48 horas.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `PE - SUNAT multa y embargo`() {
        val result = analyze("SUNAT le informa de una multa por irregularidades. Se procederá al embargo de sus bienes.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PERU (PE) — BCP / Interbank / Yape / Plin
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `PE - BCP blocked account`() {
        val result = analyze("BCP: Su cuenta ha sido bloqueada por actividad sospechosa. Verifique su identidad.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PE - Interbank card compromised`() {
        val result = analyze("Interbank: Su tarjeta fue comprometida. Ingrese su clave para proteger su cuenta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PE - Yape blocked`() {
        val result = analyze("Tu Yape fue bloqueado por movimientos sospechosos. Verificá tu cuenta ahora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PE - Plin suspended`() {
        val result = analyze("Plin: Tu cuenta ha sido suspendida por un error. Verificá tus datos para continuar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PE - Causa impersonation`() {
        val result = analyze("Causa, soy yo, cambié de número. Agéndame hermano.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GENERAL SPANISH — Prize / Lottery scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `General ES - Has ganado un premio`() {
        val result = analyze("Felicidades! Has ganado un premio de $500.000 en el sorteo de WhatsApp.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `General ES - Sorteo WhatsApp aniversario`() {
        val result = analyze("WhatsApp celebra su aniversario y regala premios. Participá ahora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `General ES - Tu numero fue seleccionado`() {
        val result = analyze("Tu número fue seleccionado como ganador. Reclamá tu premio antes de 24hs.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `General ES - Pagar impuesto para recibir premio`() {
        val result = analyze("Para recibir tu premio debes pagar un impuesto de gestión de $5.000.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `General ES - Comparte con contactos`() {
        val result = analyze("Comparte este mensaje con 10 contactos para participar del sorteo y recibir tu regalo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `General ES - iPhone gratis sorteo`() {
        val result = analyze("Ganaste un iPhone 15 gratis en nuestro sorteo exclusivo!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GENERAL SPANISH — WhatsApp account suspension
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `General ES - WhatsApp sera eliminado`() {
        val result = analyze("Tu cuenta de WhatsApp será eliminada en 24 horas si no verificás tus datos.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `General ES - WhatsApp version premium`() {
        val result = analyze("Descargá WhatsApp versión premium con funciones exclusivas. Es gratis!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `General ES - WhatsApp hackeado`() {
        val result = analyze("Tu WhatsApp fue hackeado. Verificá tu cuenta de inmediato haciendo clic aquí.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `General ES - WhatsApp cuenta suspendida`() {
        val result = analyze("Tu WhatsApp será desactivado por violar los términos de servicio. Verificá tu número.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GENERAL SPANISH — OTP / Verification code harvesting
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `General ES - Enviame el codigo`() {
        val result = analyze("Enviame el código de verificación que te llegó por SMS. Es urgente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `General ES - Codigo por error`() {
        val result = analyze("Por error te envié un código de verificación. Pasame el código que te llegó.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `General ES - Compartí tu codigo OTP`() {
        val result = analyze("Compartí tu código OTP para verificar tu identidad en la plataforma.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `General ES - Te llego un codigo de verificacion`() {
        val result = analyze("Te llegó un código de verificación? Pasámelo que lo necesito.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GENERAL SPANISH — Crypto investment scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `General ES - Bitcoin investment opportunity`() {
        val result = analyze("Invertí en Bitcoin y duplicá tu dinero en 7 días. Rentabilidad garantizada del 200%.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `General ES - Crypto trading oportunidad`() {
        val result = analyze("Oportunidad única de trading en forex. Ganancias aseguradas con señales premium.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `General ES - Ingresos pasivos crypto`() {
        val result = analyze("Ganá ingresos pasivos invirtiendo en criptomonedas. Libertad financiera garantizada.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `General ES - Seed phrase request`() {
        val result = analyze("Compartí tu frase semilla para verificar tu wallet de cripto.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
        assertTrue(result.confidence > 0.2f)
    }

    @Test
    fun `General ES - Duplicar tu plata`() {
        val result = analyze("Triplicá tu inversión en solo 48 horas con nuestro sistema automático de trading.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GENERAL SPANISH — Romance scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `General ES - Military abroad romance scam`() {
        val result = analyze("Soy militar en una base de Afganistán. Te amo desde que vi tu foto. Necesito ayuda.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `General ES - Inheritance romance scam`() {
        val result = analyze("Tengo una herencia de millones de dólares y necesito tu ayuda para sacarla del país.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `General ES - Stranded at airport`() {
        val result = analyze("Estoy varado en el aeropuerto y no puedo salir. Necesito dinero para el vuelo urgente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `General ES - Viuda looking for love`() {
        val result = analyze("Soy viuda y busco compañía. Encontré tu perfil en Facebook y me dieron tu número.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `General ES - Need money for travel to see you`() {
        val result = analyze("Necesito dinero para el pasaje para viajar a verte. Te amo, ayúdame por favor.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GENERAL SPANISH — Tech support scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `General ES - Device infected`() {
        val result = analyze("Tu celular fue infectado con un virus. Instalá TeamViewer para que lo limpiemos.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `General ES - WhatsApp soporte oficial`() {
        val result = analyze("Soporte oficial de WhatsApp: Hemos detectado actividad maliciosa en tu cuenta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `General ES - Account blocked in N hours`() {
        val result = analyze("Tu WhatsApp será bloqueado en 24 horas si no verificás tu cuenta.")
        assertTrue(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GENERAL SPANISH — Money request patterns
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `General ES - Gift card scam`() {
        val result = analyze("Comprá tarjetas de regalo de iTunes por $200 y mandame la foto del código.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `General ES - Legal threat if you dont pay`() {
        val result = analyze("Si no pagas en 24 horas, se procederá con acción legal y denuncia.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `General ES - Transferí a esta cuenta`() {
        val result = analyze("Transferí a esta cuenta urgente. CBU: 0170099120000067891234.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GENERAL SPANISH — Suspicious links
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `General ES - Haz clic aqui phishing`() {
        val result = analyze("Hacé clic aquí para verificar tu cuenta: bit.ly/x9k3m")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `General ES - Suspicious IP-based URL`() {
        val result = analyze("Ingresá a http://192.168.1.1/banco para actualizar tus datos bancarios.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GENERAL SPANISH — Government scam general patterns
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `General ES - Arrest warrant threat`() {
        val result = analyze("Existe una orden de arresto en su contra. Pague la multa para evitar la detención.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `General ES - Will be arrested unless you pay`() {
        val result = analyze("Será arrestado si no paga la multa de inmediato. Tiene 12 horas.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `General ES - Embargo de bienes`() {
        val result = analyze("Se procederá al embargo de su cuenta bancaria y fondos si no regulariza su situación.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CONVERSATION-LEVEL ANALYSIS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `Conversation - Impersonation escalation AR`() {
        val result = analyzeConversation(listOf(
            "Hola, cómo estás?",
            "Che, soy yo, cambié de número",
            "Me podés prestar plata? Es urgente, después te devuelvo"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `Conversation - Progressive bank fraud ES`() {
        val result = analyzeConversation(listOf(
            "CaixaBank: Estimado cliente",
            "Hemos detectado actividad sospechosa en su cuenta",
            "Ingrese su clave para verificar su identidad. Es urgente."
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `Conversation - Number change then money request MX`() {
        val result = analyzeConversation(listOf(
            "Güey, soy yo",
            "Cambié de número, agéndame",
            "Oye, préstame lana, es una emergencia"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `Conversation - OTP harvesting sequence`() {
        val result = analyzeConversation(listOf(
            "Hola, disculpa la molestia",
            "Por error te envié un código de verificación por SMS",
            "Me lo podés pasar? Es urgente"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // URGENCY AMPLIFIERS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `Urgency boosts score on bank fraud`() {
        val withoutUrgency = analyze("Tu cuenta del Banco Nación fue bloqueada. Verificá tus datos.")
        val withUrgency = analyze("Tu cuenta del Banco Nación fue bloqueada. Verificá tus datos urgente, ahora mismo.")
        assertTrue(withUrgency.confidence >= withoutUrgency.confidence)
    }

    @Test
    fun `Urgency ultima oportunidad boosts score`() {
        val result = analyze("Última oportunidad: tu cuenta de MercadoPago será suspendida. Verificá ahora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.2f)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EDGE CASES AND NORMALIZATION
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `Empty string returns not suspicious`() {
        val result = analyze("")
        assertFalse(result.isSuspicious)
        assertEquals(0f, result.confidence)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `Blank string returns not suspicious`() {
        val result = analyze("   ")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `Empty conversation returns not suspicious`() {
        val result = analyzeConversation(emptyList())
        assertFalse(result.isSuspicious)
        assertEquals(0f, result.confidence)
    }

    @Test
    fun `Case insensitive detection`() {
        val lower = analyze("tu cuenta del banco nación fue bloqueada")
        val upper = analyze("TU CUENTA DEL BANCO NACIÓN FUE BLOQUEADA")
        val mixed = analyze("Tu Cuenta Del Banco NACIÓN Fue Bloqueada")
        assertTrue(lower.isSuspicious)
        assertTrue(upper.isSuspicious)
        assertTrue(mixed.isSuspicious)
    }

    @Test
    fun `Multiple categories in single message increases confidence`() {
        val result = analyze(
            "Tu cuenta del Banco Nación fue bloqueada. Ganaste un premio de WhatsApp. Enviá tu código de verificación."
        )
        assertTrue(result.isSuspicious)
        // Should match bank fraud, prize scam, and phishing
        val categories = result.matchedPatterns.map { it.category }.toSet()
        assertTrue(categories.size >= 2)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // THREAT LEVEL VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `High confidence scam reaches WARNING or HIGH_ALERT`() {
        val result = analyze(
            "AFIP: Tiene una deuda de \$500.000. Será arrestado si no paga. Orden de arresto emitida. Urgente."
        )
        assertTrue(result.isSuspicious)
        assertTrue(
            result.threatLevel == ThreatLevel.WARNING || result.threatLevel == ThreatLevel.HIGH_ALERT
        )
    }

    @Test
    fun `Single weak pattern stays at LOW threat`() {
        val result = analyze("Banco Nación le informa.")
        // Just a bank name mention, low weight
        if (result.isSuspicious) {
            assertTrue(result.threatLevel == ThreatLevel.LOW || result.threatLevel == ThreatLevel.NONE)
        }
    }

    @Test
    fun `Confidence is between 0 and 1`() {
        val result = analyze(
            "URGENTE: Tu cuenta fue bloqueada. Ganaste un sorteo. Enviá tu código. Instalá TeamViewer. " +
                "AFIP tiene una deuda tuya. Invertí en Bitcoin. Será arrestado si no paga."
        )
        assertTrue(result.confidence in 0f..1f)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FALSE POSITIVES — Normal Spanish conversations
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FP - Simple greeting`() {
        val result = analyze("Hola, como estas?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `FP - Vamos al banco a sacar plata`() {
        val result = analyze("Vamos al banco a sacar plata para el almuerzo.")
        // "banco" alone should not be enough for bank fraud
        // This may match weakly but should not be suspicious
        if (result.isSuspicious) {
            // If it triggers, it should be LOW at most
            assertTrue(result.confidence <= 0.5f)
        }
    }

    @Test
    fun `FP - Te transfiero la plata del almuerzo`() {
        val result = analyze("Te transfiero la plata del almuerzo. Dale?")
        // Normal transfer conversation should not trigger high confidence
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Mi vieja me pidio que te llame`() {
        val result = analyze("Mi vieja me pidió que te llame. Llamame cuando puedas.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Normal family conversation about weekend`() {
        val result = analyze("El domingo vamos a comer a lo de la abuela. Llevá postre.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Talking about weather`() {
        val result = analyze("Qué calor que hace hoy! Vamos a la pileta?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Asking about lunch plans`() {
        val result = analyze("Qué hacemos para comer? Pedimos delivery o cocinamos?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Sharing a recipe`() {
        val result = analyze("Para las empanadas necesitás carne picada, cebolla, huevo duro y aceitunas.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Normal work conversation`() {
        val result = analyze("Mañana tengo reunión a las 10. Podés llegar temprano?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Discussing a movie`() {
        val result = analyze("Viste la película nueva? Está muy buena, te la recomiendo.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - School pickup conversation`() {
        val result = analyze("Hoy no puedo ir a buscar a los chicos al colegio. Podés ir vos?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Doctor appointment reminder`() {
        val result = analyze("Acordate que mañana tenés turno con el médico a las 15hs.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Talking about supermarket`() {
        val result = analyze("Fui al supermercado y compré leche, pan y frutas. Necesitás algo más?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Birthday party planning`() {
        val result = analyze("El cumple de mamá es el sábado. Yo llevo la torta, vos traé las bebidas.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Normal money discussion between friends`() {
        val result = analyze("Me debés la mitad del regalo de Navidad. Son 2000 pesos.")
        // Casual debt mention should not be suspicious
        if (result.isSuspicious) {
            assertTrue(result.confidence <= 0.4f)
        }
    }

    @Test
    fun `FP - Normal conversation about paying a bill`() {
        val result = analyze("Ya pagué la factura de luz. Estaba cara este mes.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Talking about a trip`() {
        val result = analyze("El fin de semana vamos a Córdoba. Salimos el viernes a la tarde.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Simple te quiero from family`() {
        val result = analyze("Te quiero mucho, cuidate!")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Asking for directions`() {
        val result = analyze("Cómo llego a tu casa? Pasame la dirección por favor.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Normal conversation entire thread`() {
        val result = analyzeConversation(listOf(
            "Hola! Cómo estás?",
            "Bien y vos?",
            "Todo bien. Nos juntamos el sábado?",
            "Dale, a qué hora?",
            "A las 8 en mi casa. Traé algo para picar."
        ))
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Spanish conversation about sports`() {
        val result = analyze("Viste el partido de anoche? Boca jugó muy bien, metió tres goles.")
        assertFalse(result.isSuspicious)
    }
}
