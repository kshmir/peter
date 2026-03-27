package com.peter.app.core.util

import com.peter.app.core.util.ScamPatternDetector.ScamCategory
import com.peter.app.core.util.ScamPatternDetector.ThreatLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Extensive European-language scam pattern detection tests.
 *
 * Covers: French (FR), Italian (IT), Romanian (RO), German (DE), Dutch (NL)
 * plus false-positive scenarios for each language.
 */
class ScamPatternDetectorEuropeanTest {

    private fun analyze(text: String) = ScamPatternDetector.analyze(text)
    private fun analyzeConversation(messages: List<String>) =
        ScamPatternDetector.analyzeConversation(messages)

    // ═══════════════════════════════════════════════════════════════════════
    // FRENCH (FR) — Bank Fraud
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FR - bank account suspended scam`() {
        val result = analyze("Votre compte bancaire a été suspendu en raison d'une activité suspecte. Cliquez ici pour le débloquer immédiatement.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `FR - Crédit Agricole suspicious activity`() {
        val result = analyze("Crédit Agricole: Nous avons détecté une activité suspecte sur votre compte. Veuillez vérifier vos données bancaires.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `FR - card compromised urgent action`() {
        val result = analyze("Votre carte a été piratée. Saisissez votre code secret et numéro de carte pour la sécuriser.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `FR - BNP Paribas verify banking info`() {
        val result = analyze("BNP Paribas: Pour éviter la fermeture de votre compte, veuillez confirmer vos coordonnées bancaires dans les 24 heures.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `FR - unauthorized transaction detected`() {
        val result = analyze("Alerte: Une transaction suspecte de 890 euros a été détectée sur votre compte. Fournissez votre PIN pour bloquer l'opération.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `FR - Lydia payment app fraud`() {
        val result = analyze("Lydia: Votre compte a été compromis. Vérifiez immédiatement votre identité pour éviter le blocage définitif.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `FR - your savings at risk`() {
        val result = analyze("Attention: Votre épargne est en danger suite à un accès non autorisé. Mettez à jour vos informations bancaires maintenant.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FRENCH (FR) — Prize / Lottery Scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FR - lottery winner congratulations`() {
        val result = analyze("Félicitations! Vous avez gagné un prix de 50.000 euros lors du tirage au sort de la loterie nationale.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `FR - claim your iPhone prize`() {
        val result = analyze("Bravo! Vous avez gagné un iPhone 15 gratuit dans notre jeu concours. Réclamez votre cadeau maintenant.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `FR - Carrefour brand giveaway`() {
        val result = analyze("Carrefour fête son anniversaire! Participez à notre tirage pour gagner un bon d'achat de 500 euros.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `FR - WhatsApp prize scam`() {
        val result = analyze("WhatsApp tirage exclusif: Vous avez été sélectionné pour obtenir votre prix en cliquant ici.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FRENCH (FR) — Phishing
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FR - click here to verify account`() {
        val result = analyze("Cliquez ici immédiatement pour vérifier votre compte avant qu'il ne soit supprimé.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `FR - account will be deleted`() {
        val result = analyze("Votre compte sera désactivé dans 48 heures si vous ne mettez pas à jour vos informations personnelles.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `FR - Chronopost package delivery scam`() {
        val result = analyze("Chronopost: Votre colis est bloqué en raison de frais de douane impayés. Payez 2,99 euros pour le débloquer.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `FR - suspicious login from another device`() {
        val result = analyze("Connexion suspecte détectée depuis un autre appareil. Confirmez votre identité pour sécuriser votre compte.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FRENCH (FR) — Money Requests
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FR - urgent money transfer request`() {
        val result = analyze("J'ai besoin d'argent urgent! Envoie-moi un virement de 500 euros sur ce RIB maintenant.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `FR - PCS prepaid card request`() {
        val result = analyze("Achète une carte PCS, envoie-moi le code par SMS. C'est urgent, j'en ai besoin de 200 euros.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `FR - Western Union transfer`() {
        val result = analyze("Western Union, fais un envoi de 1000 euros à ce nom. Je suis dans une situation désespérée.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `FR - lend me money urgently`() {
        val result = analyze("Prête-moi 300 euros. J'ai besoin des sous urgent, je te rembourse demain.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FRENCH (FR) — Impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FR - maman c'est moi classic impersonation`() {
        val result = analyze("Maman c'est moi, j'ai cassé mon téléphone. Voici mon nouveau numéro, enregistre-le.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `FR - grandchild new number with secrecy`() {
        val result = analyze("C'est ton petit-fils. J'ai changé de numéro. Ne dis rien à personne, c'est un secret.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `FR - phone stolen new number`() {
        val result = analyze("Coucou, j'ai un nouveau numéro, on m'a volé mon portable hier soir. Sauvegarde ce contact.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FRENCH (FR) — Government Scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FR - DGFIP tax debt urgent`() {
        val result = analyze("DGFIP: Vous avez une dette de 1.250 euros auprès des impôts. Régularisez votre situation sous 48h pour éviter la saisie.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `FR - Carte Vitale renewal phishing`() {
        val result = analyze("Votre carte vitale a expiré. Mettez à jour vos données sur Ameli pour éviter la suspension de vos remboursements.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `FR - police arrest warrant threat`() {
        val result = analyze("Vous êtes convoqué devant le tribunal pour fraude fiscale. Un mandat d'arrêt sera émis si vous ne payez pas l'amende.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `FR - unpaid fine online payment`() {
        val result = analyze("Contravention impayée: Vous avez une amende de 135 euros à régler en ligne sous 72 heures.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FRENCH (FR) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FR - FP - normal family chat`() {
        val result = analyze("Salut maman, on se voit dimanche pour le déjeuner?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FR - FP - asking about weather`() {
        val result = analyze("Il fait beau aujourd'hui, on va au parc cet après-midi?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FR - FP - grocery shopping list`() {
        val result = analyze("Je vais au supermarché. Il faut du pain, du lait et des fruits. Tu veux autre chose?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FR - FP - normal doctor appointment`() {
        val result = analyze("N'oublie pas ton rendez-vous chez le médecin demain à 14h30.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FR - FP - casual bank mention`() {
        val result = analyze("Je passe à la banque retirer de l'argent pour les courses.")
        if (result.isSuspicious) {
            assertTrue(result.confidence <= 0.5f)
        }
    }

    @Test
    fun `FR - FP - birthday planning`() {
        val result = analyze("L'anniversaire de papa est samedi. J'apporte le gâteau, tu t'occupes des boissons?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FR - FP - discussing a recipe`() {
        val result = analyze("Pour la ratatouille il te faut des courgettes, des aubergines, des tomates et des poivrons.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FR - FP - normal work meeting`() {
        val result = analyze("J'ai une réunion à 10h demain matin. On déjeune ensemble après?")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ITALIAN (IT) — Bank Fraud
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `IT - Intesa Sanpaolo account blocked`() {
        val result = analyze("Intesa Sanpaolo: Il tuo conto è stato bloccato per attività sospetta. Verifica i tuoi dati bancari immediatamente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `IT - PostePay compromised card`() {
        val result = analyze("La tua PostePay è stata compromessa. Inserisci il tuo PIN e numero di carta per proteggerla.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `IT - unauthorized transaction alert`() {
        val result = analyze("Abbiamo rilevato una transazione sospetta di 750 euro sul tuo conto. Conferma le tue credenziali per bloccarla.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `IT - account will be closed unless you act`() {
        val result = analyze("Il tuo conto sarà chiuso per evitare ulteriori danni. Aggiorna i tuoi dati bancari entro 24 ore.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `IT - Unicredit verify credentials`() {
        val result = analyze("Unicredit: Abbiamo riscontrato un accesso anomalo al tuo conto. Verificare le tue informazioni bancarie per evitare il blocco.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `IT - your money at risk`() {
        val result = analyze("Il tuo denaro è a rischio a causa di un accesso non autorizzato. Fornisci il tuo codice OTP per proteggere i tuoi fondi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `IT - card cloned warning`() {
        val result = analyze("Avviso urgente: La tua carta è stata clonata. Inserisci il CVV e il numero di carta per disattivarla.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ITALIAN (IT) — Prize / Lottery Scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `IT - congratulations lottery winner`() {
        val result = analyze("Congratulazioni! Hai vinto un premio di 25.000 euro nella nostra lotteria annuale. Riscuoti il tuo premio adesso.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `IT - Amazon brand giveaway`() {
        val result = analyze("Amazon festeggia il suo anniversario! Sei stato selezionato per un sorteggio esclusivo. Ritira il tuo regalo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `IT - free Samsung phone giveaway`() {
        val result = analyze("Complimenti! Hai vinto un Samsung Galaxy gratis nel nostro concorso a premi. Richiedi il tuo omaggio.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `IT - Esselunga voucher scam`() {
        val result = analyze("Esselunga concorso esclusivo: vinci un buono sconto da 500 euro! Partecipa per ricevere il tuo premio.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ITALIAN (IT) — Phishing
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `IT - click here to verify identity`() {
        val result = analyze("Clicca qui subito per verificare la tua identità. Il tuo profilo sarà eliminato entro 48 ore.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `IT - package delivery BRT scam`() {
        val result = analyze("BRT: Il tuo pacco è in attesa a causa di spese doganali non pagate. Pagare 1,99 euro per sbloccarlo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `IT - suspicious login from unknown device`() {
        val result = analyze("Accesso sospetto rilevato da un altro dispositivo. Conferma il tuo accesso immediatamente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `IT - account will be deactivated`() {
        val result = analyze("Il tuo account sarà disattivato se non aggiorni le tue informazioni entro 24 ore. Aggiorna i tuoi dati subito.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ITALIAN (IT) — Money Requests
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `IT - send money urgently via bonifico`() {
        val result = analyze("Ho bisogno di soldi urgente! Inviami un bonifico su questo IBAN adesso. È una questione di vita o di morte.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `IT - gift card purchase request`() {
        val result = analyze("Comprami una carta regalo iTunes da 200 euro e inviami il codice subito. Non posso spiegarti ora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `IT - Western Union money transfer`() {
        val result = analyze("Western Union, invia 500 euro a questo nome. Fai il trasferimento, ti restituisco tutto domani.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `IT - lend me money plea`() {
        val result = analyze("Prestami 400 euro, sono in una situazione disperata. Trasferisci a questo conto IBAN.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ITALIAN (IT) — Impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `IT - mamma sono io classic impersonation`() {
        val result = analyze("Mamma sono io, ho rotto il cellulare. Questo è il mio nuovo numero, salvalo per favore.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `IT - son changed number with secrecy`() {
        val result = analyze("Ciao, sono tuo figlio. Ho cambiato il mio numero di telefono. Non dire niente a nessuno.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `IT - phone stolen new contact`() {
        val result = analyze("Ehi, ho un nuovo cellulare. Mi hanno rubato il telefono ieri. Salva questo nuovo numero.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ITALIAN (IT) — Government Scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `IT - Agenzia delle Entrate tax debt`() {
        val result = analyze("Agenzia delle Entrate: Lei ha un debito fiscale di 3.500 euro. Una cartella esattoriale è stata emessa. Paghi entro 48 ore.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `IT - SPID renewal urgent`() {
        val result = analyze("Il tuo SPID è scaduto. Rinnova immediatamente la tua identità digitale per evitare la sospensione dei servizi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `IT - arrest warrant threat from carabinieri`() {
        val result = analyze("Sei convocato dalla procura della Repubblica per procedimento giudiziario. Un mandato d'arresto sarà emesso se non paghi la multa.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `IT - unpaid traffic fine`() {
        val result = analyze("Multa non pagata: Ha una contravvenzione di 280 euro da saldare online entro 72 ore per evitare maggiorazioni.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ITALIAN (IT) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `IT - FP - normal family lunch`() {
        val result = analyze("Ciao mamma, ci vediamo domenica per il pranzo?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `IT - FP - asking about dinner plans`() {
        val result = analyze("Cosa prepariamo per cena stasera? Ho voglia di pasta al forno.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `IT - FP - casual bank mention going to ATM`() {
        val result = analyze("Passo al bancomat a ritirare dei soldi per la spesa.")
        if (result.isSuspicious) {
            assertTrue(result.confidence <= 0.5f)
        }
    }

    @Test
    fun `IT - FP - normal doctor reminder`() {
        val result = analyze("Ricordati che domani hai la visita dal dottore alle 15. Ti accompagno io.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `IT - FP - discussing the weather`() {
        val result = analyze("Che bella giornata oggi! Andiamo al mare questo pomeriggio?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `IT - FP - school pickup`() {
        val result = analyze("Oggi non posso andare a prendere i bambini a scuola. Puoi andarci tu?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `IT - FP - normal grocery shopping`() {
        val result = analyze("Sono al supermercato. Servono latte, pane, uova e formaggio. Ti serve altro?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `IT - FP - weekend trip plans`() {
        val result = analyze("Questo fine settimana andiamo al lago. Partiamo sabato mattina presto.")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ROMANIAN (RO) — Bank Fraud
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RO - Banca Transilvania account blocked`() {
        val result = analyze("Banca Transilvania: Contul tău a fost blocat din cauza unei activități suspecte. Verifică datele bancare imediat.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RO - suspicious transaction unauthorized`() {
        val result = analyze("Am detectat o tranzacție suspectă de 2.500 lei pe contul dumneavoastră. Introduceți PIN-ul pentru a o bloca.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RO - BCR card compromised`() {
        val result = analyze("BCR: Cardul tău a fost clonat. Furnizează codul CVV și numărul cardului pentru securizare imediată.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RO - Revolut account suspended`() {
        val result = analyze("Revolut: Contul tău a fost suspendat. Verifică-ți identitatea pentru a evita blocarea definitivă.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RO - your savings at risk`() {
        val result = analyze("Banii tăi sunt în pericol din cauza unui acces neautorizat. Actualizează datele bancare acum.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RO - BRD verify banking information`() {
        val result = analyze("BRD: Pentru a evita blocarea contului, vă rugăm să confirmați informațiile bancare în 24 de ore.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RO - card expired fraud warning`() {
        val result = analyze("Cardul dumneavoastră a expirat. Actualizează datele bancare pentru a evita suspendarea contului.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ROMANIAN (RO) — Prize / Lottery Scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RO - eMAG brand giveaway`() {
        val result = analyze("eMAG aniversare! Ai câștigat un premiu special în tombola noastră. Revendică premiul tău acum.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `RO - lottery winner notification`() {
        val result = analyze("Felicitări! Ați câștigat un premiu de 10.000 euro la extragerea loteriei naționale.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `RO - free iPhone prize`() {
        val result = analyze("Ai câștigat un iPhone gratis în concursul nostru! Ridică cadoul tău de la sediul nostru.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `RO - WhatsApp contest scam`() {
        val result = analyze("WhatsApp: Ai fost selectat în tombola noastră exclusivă. Obține premiul tău imediat.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ROMANIAN (RO) — Phishing
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RO - click here urgently to verify`() {
        val result = analyze("Dă click aici imediat pentru a-ți verifica contul. Profilul tău va fi dezactivat în 24 de ore.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `RO - Fan Courier package blocked`() {
        val result = analyze("Fan Courier: Coletul tău este blocat din cauza unei taxe neplătite. Plătește 5 lei pentru deblocare.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `RO - suspicious login detected`() {
        val result = analyze("Conectare suspectă detectată de pe alt dispozitiv. Confirmă identitatea ta pentru securitate.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `RO - update your information or lose access`() {
        val result = analyze("Actualizează-ți informațiile personale. Contul tău expiră mâine dacă nu confirmi datele.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ROMANIAN (RO) — Money Requests
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RO - urgent money transfer IBAN`() {
        val result = analyze("Am nevoie de bani urgent! Transferă-mi pe acest IBAN suma de 1.000 lei acum.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `RO - gift card purchase request`() {
        val result = analyze("Cumpără-mi un card cadou Steam de 200 lei și trimite-mi codul. Este urgent.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `RO - Western Union money service`() {
        val result = analyze("Western Union, trimite bani la acest nume. Fă transferul de 500 euro cât mai repede.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `RO - lend me money desperate`() {
        val result = analyze("Împrumută-mi 300 lei, sunt disperat. Dă-mi banii urgent, îți dau înapoi săptămâna viitoare.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ROMANIAN (RO) — Impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RO - mama sunt eu classic impersonation`() {
        val result = analyze("Mamă sunt eu, mi s-a stricat telefonul. Acesta este noul meu număr, salvează-l te rog.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `RO - son new number with secrecy`() {
        val result = analyze("Bună, sunt fiul tău. Mi-am schimbat numărul de telefon. Nu spune nimănui, e între noi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `RO - phone stolen save new number`() {
        val result = analyze("Salut, am un nou telefon. Mi s-a furat telefonul ieri. Iată noul meu număr.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ROMANIAN (RO) — Government Scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RO - ANAF tax debt warning`() {
        val result = analyze("ANAF: Aveți o datorie fiscală de 5.000 lei. Achitați amenda în 48 de ore pentru a evita executarea.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `RO - carte de identitate renewal`() {
        val result = analyze("Carte de identitate expirat. Actualizați-vă documentele imediat pentru a evita suspendarea serviciilor.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `RO - police arrest warrant threat`() {
        val result = analyze("Ești citat la tribunal pentru fraudă fiscală. Un mandat de arestare va fi emis dacă nu plătești.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `RO - unpaid fine urgent`() {
        val result = analyze("Amendă neplătită: Aveți o contravenție de 1.500 lei de achitat online în 72 de ore.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ROMANIAN (RO) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RO - FP - normal family chat`() {
        val result = analyze("Bună mama, ne vedem duminică la prânz?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RO - FP - weather conversation`() {
        val result = analyze("E frumos afară azi. Mergem în parc cu copiii?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RO - FP - grocery shopping list`() {
        val result = analyze("Mă duc la magazin. Trebuie pâine, lapte și fructe. Mai vrei ceva?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RO - FP - doctor appointment`() {
        val result = analyze("Nu uita că mâine ai consultația la doctor la ora 14.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RO - FP - normal bank visit mention`() {
        val result = analyze("Trec pe la bancă să scot bani pentru piață.")
        if (result.isSuspicious) {
            assertTrue(result.confidence <= 0.5f)
        }
    }

    @Test
    fun `RO - FP - birthday planning`() {
        val result = analyze("Ziua lui tata e sâmbătă. Eu aduc tortul, tu aduci băuturile.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RO - FP - discussing weekend trip`() {
        val result = analyze("Mergem la munte în weekend. Plecăm vineri seara.")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GERMAN (DE) — Bank Fraud
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `DE - Sparkasse account blocked`() {
        val result = analyze("Sparkasse: Ihr Konto wurde wegen verdächtiger Aktivität gesperrt. Verifizieren Sie Ihre Bankdaten sofort.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `DE - suspicious transaction detected`() {
        val result = analyze("Wir haben eine verdächtige Transaktion von 1.200 Euro auf Ihrem Konto festgestellt. Geben Sie Ihre PIN ein, um sie zu stoppen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `DE - card stolen warning`() {
        val result = analyze("Ihre Karte wurde gehackt. Senden Sie uns Ihr Passwort und Ihre Kartennummer zur Sicherung.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `DE - Deutsche Bank verify info urgently`() {
        val result = analyze("Deutsche Bank: Um die Sperrung Ihres Kontos zu vermeiden, aktualisieren Sie Ihre Kontodaten innerhalb von 24 Stunden.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `DE - PayPal account compromised`() {
        val result = analyze("PayPal: Ihr Konto wurde kompromittiert. Verifizieren Sie sofort Ihre Zugangsdaten, um die Blockierung zu vermeiden.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `DE - your savings at risk`() {
        val result = analyze("Ihr Geld ist in Gefahr wegen eines nicht autorisierten Zugriffs. Bestätigen Sie Ihre Bankverbindung jetzt.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `DE - N26 app fraud alert`() {
        val result = analyze("N26: Verdächtige Aktivität erkannt. Ihr Konto wird gesperrt, wenn Sie Ihre Daten nicht sofort verifizieren.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GERMAN (DE) — Prize / Lottery Scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `DE - congratulations lottery winner`() {
        val result = analyze("Herzlichen Glückwunsch! Sie haben einen Preis von 50.000 Euro bei unserer Verlosung gewonnen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `DE - Lidl brand giveaway`() {
        val result = analyze("Lidl feiert Jubiläum! Nehmen Sie an unserem Gewinnspiel teil und gewinnen Sie einen Gutschein über 500 Euro.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `DE - free iPhone won in drawing`() {
        val result = analyze("Sie haben ein iPhone 15 gratis in unserer Tombola gewonnen! Fordern Sie Ihren Gewinn jetzt ein.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `DE - Amazon gift card prize`() {
        val result = analyze("Amazon: Du hast eine exklusive Geschenkkarte gewonnen! Hol dir deinen Preis jetzt kostenlos ab.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GERMAN (DE) — Phishing
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `DE - click here to verify account`() {
        val result = analyze("Klicken Sie hier sofort, um Ihr Konto zu verifizieren. Ihr Zugang wird deaktiviert wenn Sie nicht handeln.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `DE - DHL package delivery scam`() {
        val result = analyze("DHL: Ihr Paket wartet auf Zustellung. Bezahlen Sie die Zollgebühr von 2,99 Euro, um es freizugeben.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `DE - suspicious login from new device`() {
        val result = analyze("Verdächtige Anmeldung von einem neuen Gerät erkannt. Bestätigen Sie Ihre Identität umgehend.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `DE - account will be deleted`() {
        val result = analyze("Ihr Konto wird gelöscht, wenn Sie Ihre Daten nicht innerhalb von 48 Stunden aktualisieren. Erneuern Sie Ihr Profil jetzt.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GERMAN (DE) — Money Requests
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `DE - urgent money transfer IBAN`() {
        val result = analyze("Ich brauche Geld dringend! Überweise mir 500 Euro auf diese IBAN sofort. Es ist ein Notfall.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `DE - gift card purchase request`() {
        val result = analyze("Google Play Geschenkkarte, kauf mir eine über 100 Euro und schick mir den Code per SMS.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `DE - Western Union transfer request`() {
        val result = analyze("Western Union, schick Geld an diesen Namen. Mach die Überweisung von 800 Euro sofort bitte.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `DE - lend me money plea`() {
        val result = analyze("Kannst du mir 200 Euro lenen? Ich benötige Geld dringend, ich zahle es nächste Woche zurück.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GERMAN (DE) — Impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `DE - Mama ich bins classic impersonation`() {
        val result = analyze("Mama ich bin's! Mein Handy ist kaputt. Das ist meine neue Nummer, speicher sie bitte.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `DE - grandchild new number with secrecy`() {
        val result = analyze("Hallo, ich bin dein Enkel. Ich habe eine neue Nummer. Sag niemandem Bescheid, behalt das für dich.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `DE - phone stolen save new contact`() {
        val result = analyze("Hey, ich habe ein neues Handy. Mir wurde mein Telefon gestohlen. Notier diese neue Nummer bitte.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GERMAN (DE) — Government Scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `DE - Finanzamt tax debt warning`() {
        val result = analyze("Finanzamt: Sie haben eine Steuerschuld von 3.200 Euro. Begleichen Sie die Nachzahlung innerhalb von 48 Stunden, um eine Pfändung zu vermeiden.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `DE - Personalausweis renewal scam`() {
        val result = analyze("Ihr Personalausweis ist abgelaufen. Aktualisieren Sie Ihre Daten sofort, um die Sperrung Ihrer Dienste zu vermeiden.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `DE - police arrest warrant threat`() {
        val result = analyze("Sie sind vorgeladen wegen Steuerhinterziehung. Ein Haftbefehl wird ausgestellt, wenn Sie die Strafe nicht bezahlen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `DE - unpaid traffic fine`() {
        val result = analyze("Bußgeld unbezahlt: Sie haben einen Strafzettel über 180 Euro online zu begleichen innerhalb von 72 Stunden.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GERMAN (DE) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `DE - FP - normal family chat`() {
        val result = analyze("Hallo Mama, sehen wir uns am Sonntag zum Mittagessen?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `DE - FP - weather conversation`() {
        val result = analyze("Schönes Wetter heute! Gehen wir nachmittags in den Park?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `DE - FP - grocery shopping`() {
        val result = analyze("Ich gehe zum Supermarkt. Wir brauchen Brot, Milch und Obst. Brauchst du noch etwas?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `DE - FP - doctor appointment reminder`() {
        val result = analyze("Vergiss nicht, morgen hast du einen Arzttermin um 14 Uhr.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `DE - FP - casual bank visit mention`() {
        val result = analyze("Ich gehe kurz zur Bank, Geld abheben für den Einkauf.")
        if (result.isSuspicious) {
            assertTrue(result.confidence <= 0.5f)
        }
    }

    @Test
    fun `DE - FP - birthday party planning`() {
        val result = analyze("Papas Geburtstag ist am Samstag. Ich bringe den Kuchen, du bringst die Getränke.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `DE - FP - discussing dinner`() {
        val result = analyze("Was kochen wir heute Abend? Ich hätte Lust auf Schnitzel mit Kartoffelsalat.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `DE - FP - work meeting reminder`() {
        val result = analyze("Morgen habe ich um 10 Uhr ein Meeting. Wollen wir danach zusammen Mittag essen?")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DUTCH (NL) — Bank Fraud
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `NL - ING account blocked suspicious activity`() {
        val result = analyze("ING: Uw rekening is geblokkeerd vanwege verdachte activiteit. Verifieer uw bankgegevens onmiddellijk.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `NL - unauthorized transaction detected`() {
        val result = analyze("We hebben een verdachte transactie gedetecteerd van 900 euro op uw rekening. Voer uw pincode in om deze te blokkeren.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `NL - Rabobank card compromised`() {
        val result = analyze("Rabobank: Uw bankpas is gecompromitteerd. Stuur uw wachtwoord en kaartnummer om uw rekening te beveiligen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `NL - ABN AMRO verify banking data`() {
        val result = analyze("ABN AMRO: Om blokkering te voorkomen, werk uw bankgegevens bij binnen 24 uur.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `NL - iDEAL payment app fraud`() {
        val result = analyze("iDEAL: Uw betaalverzoek is geblokkeerd vanwege een probleem met uw rekening. Verifieer nu.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `NL - your money at risk`() {
        val result = analyze("Uw spaargeld is in gevaar door ongeautoriseerde toegang. Bevestig uw rekeninggegevens direct.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `NL - card stolen hacked warning`() {
        val result = analyze("Je bankpas is gehackt. Geef je beveiligingscode en kaartnummer door om je rekening te beschermen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DUTCH (NL) — Prize / Lottery Scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `NL - congratulations lottery winner`() {
        val result = analyze("Gefeliciteerd! U heeft een prijs van 25.000 euro gewonnen bij onze loterij. Claim uw winst nu.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `NL - Albert Heijn brand giveaway`() {
        val result = analyze("Albert Heijn viert jubileum! Je bent geselecteerd voor onze verloting. Haal je cadeau op.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `NL - free Samsung phone won`() {
        val result = analyze("Je hebt een Samsung Galaxy gratis gewonnen in onze trekking! Claim je prijs onmiddellijk.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `NL - Bol com voucher prize`() {
        val result = analyze("Bol.com: U heeft een exclusieve cadeaubon van 500 euro gewonnen! Neem deel aan onze actie.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DUTCH (NL) — Phishing
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `NL - click here to verify`() {
        val result = analyze("Klik hier direct om uw account te verifiëren. Uw profiel wordt verwijderd als u niet reageert.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `NL - PostNL package delivery scam`() {
        val result = analyze("PostNL: Uw pakket wacht op levering. Betaal de invoerkosten van 1,95 euro om het vrij te geven.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `NL - suspicious login from another device`() {
        val result = analyze("Verdachte inlog gedetecteerd van een ander apparaat. Bevestig uw identiteit onmiddellijk.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `NL - account will be deactivated`() {
        val result = analyze("Je account wordt gedeactiveerd als je je gegevens niet binnen 48 uur bijwerkt. Werk je profiel nu bij.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DUTCH (NL) — Money Requests
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `NL - urgent money transfer IBAN`() {
        val result = analyze("Ik heb geld nodig dringend! Maak over naar deze IBAN het bedrag van 500 euro nu meteen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `NL - gift card purchase request`() {
        val result = analyze("Google Play cadeaukaart, koop er een van 100 euro en stuur mij de code. Het is dringend.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `NL - Western Union money transfer`() {
        val result = analyze("Western Union, stuur geld naar deze naam. Doe de overboeking van 600 euro zo snel mogelijk.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `NL - Tikkie payment request scam`() {
        val result = analyze("Je hebt een Tikkie betaalverzoek niet betaald. Betaal nu 350 euro via deze link.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DUTCH (NL) — Impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `NL - mama ik ben het classic impersonation`() {
        val result = analyze("Mama ik ben het! Mijn telefoon is kapot. Dit is mijn nieuwe nummer, sla het op alsjeblieft.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `NL - son new number with secrecy`() {
        val result = analyze("Hallo, ik ben je zoon. Ik heb een nieuw nummer. Zeg het tegen niemand, hou het voor jezelf.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `NL - phone stolen save new contact`() {
        val result = analyze("Hey, ik heb een nieuw mobiel. Mijn telefoon is gestolen gisteren. Bewaar dit nieuwe nummer.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DUTCH (NL) — Government Scams
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `NL - Belastingdienst tax debt`() {
        val result = analyze("Belastingdienst: U heeft een openstaande schuld van 2.800 euro. Betaal de aanmaning binnen 48 uur om beslag te voorkomen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `NL - DigiD renewal scam`() {
        val result = analyze("Uw DigiD is verlopen. Vernieuw uw inloggegevens onmiddellijk om uw toegang tot overheidsdiensten te behouden.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `NL - police arrest warrant threat`() {
        val result = analyze("U bent gedagvaard wegens belastingfraude. Een arrestatiebevel wordt uitgevaardigd als u de boete niet betaalt.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `NL - unpaid traffic fine`() {
        val result = analyze("Boete onbetaald: U heeft een bekeuring van 240 euro online te voldoen binnen 72 uur.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DUTCH (NL) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `NL - FP - normal family chat`() {
        val result = analyze("Hallo mama, zien we elkaar zondag voor de lunch?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `NL - FP - weather talk`() {
        val result = analyze("Lekker weer vandaag! Zullen we naar het strand gaan?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `NL - FP - grocery shopping list`() {
        val result = analyze("Ik ga naar de Albert Heijn. We hebben brood, melk en kaas nodig. Nog iets anders?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `NL - FP - doctor appointment`() {
        val result = analyze("Vergeet niet, morgen heb je een afspraak bij de huisarts om 14 uur.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `NL - FP - casual bank mention`() {
        val result = analyze("Ik ga even naar de bank om geld te pinnen voor boodschappen.")
        if (result.isSuspicious) {
            assertTrue(result.confidence <= 0.5f)
        }
    }

    @Test
    fun `NL - FP - birthday party plans`() {
        val result = analyze("Het verjaardagsfeest van opa is zaterdag. Ik neem de taart mee, jij de drankjes.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `NL - FP - weekend plans discussion`() {
        val result = analyze("Dit weekend gaan we naar Texel. We vertrekken vrijdagavond.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `NL - FP - discussing dinner plans`() {
        val result = analyze("Wat zullen we vanavond eten? Ik heb zin in stamppot met rookworst.")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CONVERSATION-LEVEL ANALYSIS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `Conversation - FR impersonation escalation`() {
        val result = analyzeConversation(listOf(
            "Coucou, comment ça va?",
            "Maman c'est moi, j'ai changé de numéro",
            "Prête-moi de l'argent urgent, je t'expliquerai plus tard"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `Conversation - DE bank fraud progressive`() {
        val result = analyzeConversation(listOf(
            "Sparkasse: Sehr geehrter Kunde",
            "Wir haben verdächtige Aktivität auf Ihrem Konto festgestellt",
            "Geben Sie Ihre PIN und TAN ein, um Ihr Konto zu sichern. Es ist dringend."
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `Conversation - NL number change then money request`() {
        val result = analyzeConversation(listOf(
            "Hoi mam",
            "Ik heb een nieuw nummer, mijn telefoon is kapot",
            "Kun je me 500 euro lenen? Het is dringend."
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `Conversation - IT impersonation then gift card`() {
        val result = analyzeConversation(listOf(
            "Ciao mamma sono io",
            "Ho cambiato il mio numero di telefono",
            "Carta regalo iTunes, compra il codice da 200 euro e inviamelo"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `Conversation - RO scam progression`() {
        val result = analyzeConversation(listOf(
            "Bună, mamă sunt eu",
            "Mi-am schimbat numărul de telefon, nu spune nimănui",
            "Trimite-mi bani urgent pe acest IBAN, am o problemă gravă"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EDGE CASES AND NORMALIZATION
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FR - case insensitive detection`() {
        val lower = analyze("votre compte bancaire a été suspendu")
        val upper = analyze("VOTRE COMPTE BANCAIRE A ÉTÉ SUSPENDU")
        val mixed = analyze("Votre Compte Bancaire A Été Suspendu")
        assertTrue(lower.isSuspicious)
        assertTrue(upper.isSuspicious)
        assertTrue(mixed.isSuspicious)
    }

    @Test
    fun `DE - case insensitive detection`() {
        val lower = analyze("ihr konto wurde gesperrt wegen verdächtiger aktivität")
        val upper = analyze("IHR KONTO WURDE GESPERRT WEGEN VERDÄCHTIGER AKTIVITÄT")
        assertTrue(lower.isSuspicious)
        assertTrue(upper.isSuspicious)
    }

    @Test
    fun `Multiple categories in single FR message`() {
        val result = analyze(
            "Votre compte a été suspendu. Vous avez gagné un prix de 10.000 euros. Cliquez ici immédiatement."
        )
        assertTrue(result.isSuspicious)
        val categories = result.matchedPatterns.map { it.category }.toSet()
        assertTrue(categories.size >= 2)
    }

    @Test
    fun `Multiple categories in single DE message`() {
        val result = analyze(
            "Ihr Konto wurde gesperrt. Sie haben 50.000 Euro gewonnen. Klicken Sie hier sofort."
        )
        assertTrue(result.isSuspicious)
        val categories = result.matchedPatterns.map { it.category }.toSet()
        assertTrue(categories.size >= 2)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // URGENCY AMPLIFIERS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FR - urgency boosts confidence`() {
        val withoutUrgency = analyze("Votre compte a été suspendu. Vérifiez vos données.")
        val withUrgency = analyze("Votre compte a été suspendu. Vérifiez vos données immédiatement, c'est urgent!")
        assertTrue(withUrgency.confidence >= withoutUrgency.confidence)
    }

    @Test
    fun `DE - urgency boosts confidence`() {
        val withoutUrgency = analyze("Ihr Konto wurde gesperrt. Verifizieren Sie Ihre Daten.")
        val withUrgency = analyze("Ihr Konto wurde gesperrt. Verifizieren Sie Ihre Daten sofort, es ist dringend!")
        assertTrue(withUrgency.confidence >= withoutUrgency.confidence)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // THREAT LEVEL VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FR - high confidence scam reaches WARNING or HIGH_ALERT`() {
        val result = analyze(
            "DGFIP: Vous avez une dette de 10.000 euros. Vous serez poursuivi et un mandat d'arrêt sera émis. Cliquez ici immédiatement. C'est urgent!"
        )
        assertTrue(result.isSuspicious)
        assertTrue(
            result.threatLevel == ThreatLevel.WARNING || result.threatLevel == ThreatLevel.HIGH_ALERT
        )
    }

    @Test
    fun `DE - high confidence scam reaches WARNING or HIGH_ALERT`() {
        val result = analyze(
            "Finanzamt: Sie haben eine Steuerschuld. Haftbefehl wird ausgestellt. Klicken Sie hier sofort. Geben Sie Ihre PIN ein."
        )
        assertTrue(result.isSuspicious)
        assertTrue(
            result.threatLevel == ThreatLevel.WARNING || result.threatLevel == ThreatLevel.HIGH_ALERT
        )
    }

    @Test
    fun `Confidence is between 0 and 1 for all languages`() {
        val frResult = analyze(
            "URGENT: Votre compte est suspendu. Vous avez gagné un prix. Cliquez ici. Installez TeamViewer."
        )
        assertTrue(frResult.confidence in 0f..1f)

        val deResult = analyze(
            "DRINGEND: Ihr Konto wurde gesperrt. Sie haben gewonnen. Klicken Sie hier. Geben Sie Ihre TAN ein."
        )
        assertTrue(deResult.confidence in 0f..1f)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FALSE POSITIVE — Normal multi-language conversations
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `FP - normal FR conversation thread`() {
        val result = analyzeConversation(listOf(
            "Salut! Comment ça va?",
            "Ça va bien et toi?",
            "Très bien. On se voit samedi?",
            "Oui, à quelle heure?",
            "À 20h chez moi. Apporte du vin."
        ))
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - normal DE conversation thread`() {
        val result = analyzeConversation(listOf(
            "Hallo! Wie geht es dir?",
            "Mir geht es gut, und dir?",
            "Auch gut. Treffen wir uns am Samstag?",
            "Ja, um wie viel Uhr?",
            "Um 19 Uhr bei mir. Bring Kuchen mit."
        ))
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - normal IT conversation thread`() {
        val result = analyzeConversation(listOf(
            "Ciao! Come stai?",
            "Bene, e tu?",
            "Tutto bene. Ci vediamo sabato?",
            "Sì, a che ora?",
            "Alle 20 a casa mia. Porta il dolce."
        ))
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - normal NL conversation thread`() {
        val result = analyzeConversation(listOf(
            "Hoi! Hoe gaat het?",
            "Goed, en met jou?",
            "Ook goed. Zien we elkaar zaterdag?",
            "Ja, hoe laat?",
            "Om 8 uur bij mij thuis. Neem wat borrelhapjes mee."
        ))
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - normal RO conversation thread`() {
        val result = analyzeConversation(listOf(
            "Bună! Ce faci?",
            "Bine, tu?",
            "Și eu bine. Ne vedem sâmbătă?",
            "Da, la ce oră?",
            "La 20 la mine acasă. Adu și tu ceva de băut."
        ))
        assertFalse(result.isSuspicious)
    }
}
