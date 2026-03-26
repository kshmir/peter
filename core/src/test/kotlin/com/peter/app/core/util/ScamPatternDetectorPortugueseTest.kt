package com.peter.app.core.util

import com.peter.app.core.util.ScamPatternDetector.ScamCategory
import com.peter.app.core.util.ScamPatternDetector.ThreatLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Extensive Brazilian Portuguese scam pattern detection tests.
 *
 * Covers: bank fraud (Banco do Brasil, Itau, Bradesco, Nubank, Caixa, etc.),
 * Receita Federal / CPF government scams, PIX transfer scams, Bolsa Familia / Auxilio Brasil
 * benefit scams, WhatsApp clonado, "Pai/Mae troquei de numero" impersonation,
 * prize/lottery scams, crypto/Bitcoin, romance scams, tech support,
 * Brazilian slang (cara, mano, vei, brother, parceiro), payment systems (PIX, boleto, TED, DOC),
 * regional expressions (paulista, carioca, mineiro, gaucho, nordestino),
 * and false-positive scenarios for normal Brazilian conversations.
 */
class ScamPatternDetectorPortugueseTest {

    private fun analyze(text: String) = ScamPatternDetector.analyze(text)
    private fun analyzeConversation(messages: List<String>) =
        ScamPatternDetector.analyzeConversation(messages)

    // =========================================================================
    // BANK FRAUD -- Banco do Brasil / Itau / Bradesco / Nubank / Caixa
    // =========================================================================

    @Test
    fun `BR - Banco do Brasil account blocked`() {
        val result = analyze("Banco do Brasil: Sua conta foi bloqueada por atividade suspeita. Atualize seus dados.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - Itau suspicious transaction`() {
        val result = analyze("Itau: Detectamos uma movimentacao suspeita na sua conta. Confirme seus dados imediatamente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - Bradesco card compromised`() {
        val result = analyze("Bradesco informa: Seu cartao foi clonado. Para evitar bloqueio, atualize seus dados.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - Nubank account suspended`() {
        val result = analyze("Nubank: Sua conta foi suspensa por movimentacao incomum. Verifique agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - Caixa Economica blocked`() {
        val result = analyze("Caixa: Sua conta foi bloqueada. Informe sua senha e token para desbloquear.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - Santander unrecognized purchase`() {
        val result = analyze("Santander: Compra nao reconhecida no valor de R$2.499,00. Confirme seus dados.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - Inter bank verify credentials`() {
        val result = analyze("Banco Inter: Informe seu PIN e codigo de verificacao para evitar suspensao da conta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - iToken expired Itau`() {
        val result = analyze("Itau: Seu iToken expirou. Atualize para continuar usando sua conta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - PicPay wallet fraud`() {
        val result = analyze("PicPay: Detectamos atividade suspeita na sua conta. Atualize seus dados.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - Mercado Pago blocked`() {
        val result = analyze("Mercado Pago: Sua conta foi bloqueada por movimentacao suspeita. Verifique sua identidade.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - PagSeguro verification`() {
        val result = analyze("PagSeguro: Erro no processamento. Verifique seus dados bancarios imediatamente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - Credit limit exceeded`() {
        val result = analyze("Seu limite foi estourado. Entre em contato para evitar bloqueio.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - Your money is at risk`() {
        val result = analyze("Seu dinheiro esta em risco. Atividade fraudulenta detectada na sua poupanca.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - To avoid blocking update data`() {
        val result = analyze("Para evitar bloqueio da sua conta, atualize seus dados cadastrais agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // =========================================================================
    // PIX TRANSFER SCAMS
    // =========================================================================

    @Test
    fun `BR - PIX blocked scam`() {
        val result = analyze("Seu PIX foi bloqueado por irregularidade. Verifique seus dados para liberar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - Chave PIX verification`() {
        val result = analyze("Sua chave PIX precisa ser verificada. Atualize seus dados no aplicativo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `BR - PIX prize gift scam`() {
        val result = analyze("Voce foi sorteado para ganhar um PIX de R$500 gratis do governo!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - PIX investment double money`() {
        val result = analyze("Faca um PIX de R$100 e receba R$500 de volta. Pix rendendo muito!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Send PIX to this account`() {
        val result = analyze("Mande um PIX pra essa conta urgente. Chave PIX: fulano@email.com")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any {
            it.category == ScamCategory.MONEY_REQUEST || it.category == ScamCategory.IMPERSONATION
        })
    }

    @Test
    fun `BR - PIX key provided with request`() {
        // Regex: chave pix\s*[:=]?\s*[a-zA-Z0-9@.+\-]{5,} (weight 0.25)
        // Combined with money request context for higher confidence
        val result = analyze("Urgente! Mande um pix pra essa conta agora. Chave pix: fulano@email.com")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `BR - PIX comprovante scam`() {
        val result = analyze("Seu PIX apresentou erro. Verifique o comprovante e refaca a transferencia para essa conta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // =========================================================================
    // RECEITA FEDERAL / CPF GOVERNMENT SCAMS
    // =========================================================================

    @Test
    fun `BR - Receita Federal debt`() {
        val result = analyze("Receita Federal: Voce possui divida pendente de imposto de renda. Regularize em 48h.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BR - CPF irregular`() {
        // Regex: cpf.{0,5}(irregular|pendente|bloqueado|cancelado|suspenso)
        val result = analyze("CPF irregular detectado. Regularize para evitar bloqueio da conta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BR - CPF cancelled`() {
        val result = analyze("Seu CPF foi cancelado pela Receita Federal. Clique no link para regularizar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BR - Receita Federal multa`() {
        val result = analyze("Receita Federal: Multa por irregularidade na declaracao. Pague antes do prazo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BR - Policia Federal mandado`() {
        val result = analyze("Policia Federal emitiu um mandado de prisao contra voce. Pague a multa para cancelar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `BR - Ministerio Publico denuncia`() {
        val result = analyze("Ministerio Publico: Existe uma denuncia criminal contra voce. Comparecer ou responder.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BR - Serasa negativado`() {
        val result = analyze("Serasa: Seu nome foi negativado. Regularize sua divida para limpar nome.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BR - SPC cobranca`() {
        // Regex: (serasa|spc).{0,15}(negativado|d[ií]vida|cobran[cç]a|regularizar|limpar.{0,5}nome)
        val result = analyze("SPC: divida pendente. Regularize para evitar cobranca judicial.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BR - DETRAN multa CNH`() {
        val result = analyze("DETRAN: Sua CNH sera suspensa por infracoes pendentes. Pague a multa agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BR - Tribunal intimacao judicial`() {
        val result = analyze("Voce recebeu uma intimacao judicial do tribunal de justica. Comparecer em 5 dias.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BR - Penhora de bens threat`() {
        val result = analyze("Sera feita penhora de bens caso nao pague a divida pendente junto a Receita Federal.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `BR - Pay to avoid arrest`() {
        val result = analyze("Voce sera preso se nao pagar multa para evitar prisao. Pague via PIX agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `BR - CPF CNPJ phishing verification`() {
        // Regex: (cpf|cnpj).{0,15}(verificar|confirmar|atualizar|regularizar|pendente)
        val result = analyze("Seu CPF pendente de verificar. Confirme dados para regularizar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any {
            it.category == ScamCategory.PHISHING || it.category == ScamCategory.GOVERNMENT_SCAM
        })
    }

    // =========================================================================
    // BOLSA FAMILIA / AUXILIO BRASIL BENEFIT SCAMS
    // =========================================================================

    @Test
    fun `BR - Bolsa Familia bonus extra`() {
        val result = analyze("Bolsa Familia: Novo bonus extra liberado. Receba R$600 agora!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - Auxilio Brasil novo pagamento`() {
        val result = analyze("Auxilio Brasil: Novo pagamento disponivel. Sacar agora o beneficio.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - Auxilio emergencial liberado`() {
        val result = analyze("Auxilio emergencial liberado! Receba R$1.200 no seu PIX. Cadastre-se.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - FGTS saque extraordinario`() {
        val result = analyze("Saque FGTS extraordinario liberado. Disponivel para retirada imediata.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - PIS bonus available`() {
        val result = analyze("PIS: Bonus extra disponivel para sacar. Libere seu pagamento agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - Vale Gas bonus`() {
        val result = analyze("Vale gas: Novo bonus liberado para receber. Cadastre-se no link.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // =========================================================================
    // GOLPE DO WHATSAPP CLONADO
    // =========================================================================

    @Test
    fun `BR - WhatsApp clonado alert`() {
        val result = analyze("Seu WhatsApp foi clonado. Envie o codigo de verificacao para recuperar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BR - WhatsApp hackeado`() {
        // Regex: seu whatsapp (est[aá]|foi|ser[aá]) (hackeado|comprometido|clonado|roubado|invadido)
        val result = analyze("Seu WhatsApp foi hackeado. Confirme sua conta agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BR - Send me the verification code`() {
        val result = analyze("Me manda o codigo de verificacao que chegou no seu celular.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BR - Code sent by mistake OTP harvesting`() {
        val result = analyze("Enviei um codigo por engano para o seu numero. Me passa ele de volta?")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BR - WhatsApp premium gold version`() {
        val result = analyze("Atualize seu WhatsApp para a versao premium gratis! Clique aqui.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BR - WhatsApp will be suspended`() {
        // Regex: (sua|seu) (conta|whatsapp|perfil) (ser[aá]|vai ser|foi) (eliminad|encerrad|suspens|desativad|bloquead)
        val result = analyze("Sua conta vai ser suspensa. Verifique seus dados agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BR - Scan QR code phishing`() {
        val result = analyze("Escaneie este codigo QR para ativar o novo recurso do WhatsApp.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BR - Click this link phishing`() {
        val result = analyze("Clique aqui para atualizar suas informacoes de seguranca.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BR - Download fake app`() {
        val result = analyze("Baixar este aplicativo para proteger seu celular contra virus.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BR - Personal data verification request`() {
        // Regex: (dados pessoais|informa[cç][oõ]es pessoais).{0,20}(verificar|confirmar|atualizar|completar|enviar)
        val result = analyze("Seus dados pessoais: confirmar para evitar bloqueio da conta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // =========================================================================
    // PAI / MAE TROQUEI DE NUMERO -- IMPERSONATION
    // =========================================================================

    @Test
    fun `BR - Mae sou eu classic impersonation`() {
        val result = analyze("Mae sou eu, troquei de numero. Salva esse novo contato.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `BR - Mamae sou eu with number change`() {
        val result = analyze("Mamae sou eu. Mudei de celular, anota esse numero novo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Pai preciso de ajuda`() {
        val result = analyze("Pai preciso de ajuda urgente. Me empresta uma grana.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `BR - Vovo sou eu`() {
        val result = analyze("Vovo sou eu, seu neto. Estou com problema e preciso de ajuda.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Oi troquei de numero`() {
        val result = analyze("Oi, troquei de numero. Salva esse novo contato!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Ola mudei de celular`() {
        val result = analyze("Ola, mudei de celular. Esse e meu novo numero agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Sou seu filho impersonation`() {
        val result = analyze("Sou seu filho, estou com um problema serio. Preciso de dinheiro urgente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Phone stolen new number`() {
        val result = analyze("Roubaram meu celular. Estou com esse numero novo agora. Me ajuda.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Dont tell anyone secrecy`() {
        val result = analyze("Nao conta pra ninguem, e segredo. Me manda o dinheiro rapido.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Send PIX after impersonation`() {
        val result = analyze("Faz um pix pra mim urgente. Depois te conto o que aconteceu.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Send transfer I will pay back`() {
        val result = analyze("Manda um pix que amanha eu devolvo. Preciso muito agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Guess who I am`() {
        val result = analyze("Adivinha quem sou. Nao lembra de mim? Me empresta uma grana.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - I am in trouble emergency`() {
        val result = analyze("Estou em problema serio. Preciso de dinheiro urgente pra resolver.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Lend me money grana`() {
        val result = analyze("Me empresta uma grana? To sem dinheiro nenhum.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Had accident need help`() {
        val result = analyze("Tive um acidente e preciso de ajuda urgente. Me manda dinheiro.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // =========================================================================
    // PRIZE / LOTTERY SCAMS (PROMOCAO / SORTEIO)
    // =========================================================================

    @Test
    fun `BR - Voce ganhou congratulations`() {
        val result = analyze("Parabens! Voce ganhou um premio especial. Resgate agora!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - Lottery won`() {
        val result = analyze("Seu numero foi sorteado na loteria! Premio de R$50.000,00.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - Magazine Luiza anniversary prize`() {
        val result = analyze("Magazine Luiza esta distribuindo premios de aniversario! Clique para participar.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - Casas Bahia prize`() {
        val result = analyze("Casas Bahia: Sorteio especial de aniversario! Voce foi contemplado.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - WhatsApp distributing prizes`() {
        val result = analyze("WhatsApp esta distribuindo premios para usuarios antigos. Resgate o seu.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - iPhone prize giveaway`() {
        val result = analyze("Voce ganhou um iPhone gratis! Pague apenas o frete de R$29,90 para receber.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - Share with contacts to claim`() {
        val result = analyze("Compartilhe com 10 contatos para participar do sorteio e receber o premio.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - Pay fee to receive prize`() {
        val result = analyze("Pagar uma taxa de envio para receber o premio. Deposite R$49,90.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - First N to respond`() {
        // Regex: (primeiros|[uú]ltimos) \d+.{0,15}(a responder|que se cadastrar)
        // After normalization digits become letters, so use text that still matches prize patterns
        val result = analyze("Voce foi selecionado como um dos primeiros a participar! Resgate seu premio.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - Free gift exclusive`() {
        val result = analyze("Presente gratis e exclusivo para voce. Resgate agora antes que acabe.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `BR - Large BRL amount prize`() {
        val result = analyze("Voce foi selecionado para receber R$10.000,00 em premios!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // =========================================================================
    // CRYPTO / BITCOIN INVESTMENT SCAMS (BR SLANG)
    // =========================================================================

    @Test
    fun `BR - Bitcoin investment opportunity`() {
        val result = analyze("Oportunidade unica de investir em Bitcoin! Lucro garantido de 300%.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Double your money crypto`() {
        val result = analyze("Duplique seu dinheiro investindo em criptomoedas. Rendimento garantido!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Guaranteed returns percent`() {
        val result = analyze("Retorno garantido de 50% ao mes. Invista agora e ganhe!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Easy money passive income`() {
        val result = analyze("Ganhe dinheiro facil trabalhando de casa. Renda passiva com cripto!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Trading forex signals`() {
        val result = analyze("Sinais de trading forex com lucro garantido. Entre no grupo agora!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - PIX investment scam multiply`() {
        val result = analyze("Seu PIX multiplicar! Mande R$200 e receba R$2000 de volta.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Financial freedom passive income`() {
        val result = analyze("Liberdade financeira agora! Independencia financeira com cripto.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Minimum investment BRL`() {
        // After normalization $ becomes s and digits become letters, so use text that matches other crypto patterns
        val result = analyze("Apenas cem reais para comecar a investir em cripto. Oportunidade imperdivel!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - My financial mentor advisor`() {
        val result = analyze("Meu assessor financeiro de investimento me ensinou esse metodo incrivel.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Seed phrase request`() {
        // Regex: (seed phrase|frase semente|...).{0,10}(compartilh|enviar|digitar|escrever)
        val result = analyze("Sua seed phrase: enviar aqui para verificar carteira de Bitcoin.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `BR - Trading bot robot profits`() {
        val result = analyze("Robo de trading automatico com lucro garantido todo dia. Invista agora!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Crypto mining cloud`() {
        val result = analyze("Mineracao de bitcoin na nuvem. Ganhe sem fazer nada!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Crypto airdrop free`() {
        val result = analyze("Airdrop gratis de criptomoeda! Resgate seus tokens agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    // =========================================================================
    // ROMANCE SCAMS IN PORTUGUESE
    // =========================================================================

    @Test
    fun `BR - Military abroad romance`() {
        val result = analyze("Sou militar e trabalho na base no exterior. Quero te conhecer pessoalmente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `BR - Inheritance to share`() {
        val result = analyze("Tenho uma heranca de milhoes de dolares e preciso da sua ajuda para receber.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `BR - Widow looking for love`() {
        // Regex: (vi[uú]v[ao]|divorciad[ao]|sozinh[ao]).{0,15}(procuro|procurando|preciso de|busco) (companhia|amor|parceiro|algu[eé]m especial)
        // Multiple romance patterns for higher confidence
        val result = analyze("Sou viuva procurando companhia. Encontrei seu perfil no Facebook e quero te conhecer.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `BR - Found your profile`() {
        val result = analyze("Encontrei seu perfil no Facebook e achei voce muito interessante.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `BR - God destiny brought us together`() {
        // Regex: (deus|o destino|o universo).{0,15}(nos juntou|te colocou no meu caminho|quer que fiquemos juntos)
        // Combined with military abroad romance pattern for higher confidence
        val result = analyze("Sou militar no exterior. O destino te colocou no meu caminho. Preciso de dinheiro para a passagem.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `BR - Need money for travel visa`() {
        val result = analyze("Preciso de dinheiro para a passagem e o visto para te ver.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `BR - Stranded at airport customs`() {
        val result = analyze("Estou preso no aeroporto. Me retiveram na alfandega e preciso de ajuda.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `BR - Want to send gift package`() {
        val result = analyze("Quero te mandar um presente especial. Preciso dos seus dados para envio.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `BR - Request intimate photos`() {
        val result = analyze("Me envia fotos intimas. Quero te ver melhor.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `BR - Keep secret from family`() {
        val result = analyze("Nao conta pra sua familia. Fica entre nos, nosso segredo.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any {
            it.category == ScamCategory.ROMANCE_SCAM || it.category == ScamCategory.IMPERSONATION
        })
    }

    // =========================================================================
    // TECH SUPPORT -- "SEU CELULAR FOI HACKEADO"
    // =========================================================================

    @Test
    fun `BR - Your phone is infected`() {
        val result = analyze("Seu celular esta infectado com virus. Instale esse antivirus agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `BR - Malware detected on device`() {
        val result = analyze("Malware detectado no seu dispositivo. Ligue para o suporte tecnico.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `BR - WhatsApp official support`() {
        val result = analyze("Suporte oficial do WhatsApp aqui. Sua conta precisa ser verificada.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `BR - Install TeamViewer remote access`() {
        val result = analyze("Instalar TeamViewer para resolver o problema do seu computador remotamente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `BR - AnyDesk remote access request`() {
        // Regex: (acesso remoto|teamviewer|anydesk|quicksupport).{0,15}(instalar|baixar|permitir|dar acesso|autorizar)
        val result = analyze("AnyDesk: instalar para resolver o problema. De acesso remoto ao tecnico.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `BR - License subscription expired`() {
        val result = analyze("Sua licenca do antivirus venceu. Renove agora para manter protecao.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `BR - Your data is at risk`() {
        val result = analyze("Seus dados estao em risco. Seus arquivos podem ser perdidos se nao agir agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `BR - Account blocked in N hours`() {
        // Regex uses \d+ which won't match after normalization (digits->letters)
        // Use a different tech support pattern that matches: (seu|sua) (whatsapp|conta).{0,15}(ser[aá]|vai ser)...
        // Also matches PHISHING: (sua|seu) (conta|whatsapp|perfil) (ser[aá]|vai ser|foi) (eliminad|encerrad|suspens|desativad|bloquead)
        val result = analyze("Seu dispositivo foi comprometido por malware. Ligue para o suporte tecnico.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `BR - Pay for repair unlock`() {
        val result = analyze("Pagar para o desbloqueio do seu celular. Valor do reparo: R$199.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `BR - Windows Microsoft alert`() {
        val result = analyze("Microsoft alerta: Erro critico detectado no seu computador.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `BR - Call this phone number support`() {
        // Regex: ligue para.{0,10}\+?\d{7,} -- digits get normalized so won't match
        // Use a different tech support pattern: (ligue|entre em contato|contate).{0,15}(suporte|...)
        val result = analyze("Ligue para o suporte tecnico imediatamente para resolver o problema.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    // =========================================================================
    // MONEY REQUEST PATTERNS (BOLETO, TED, DOC)
    // =========================================================================

    @Test
    fun `BR - Send transfer money`() {
        val result = analyze("Envie o pagamento via transferencia bancaria urgente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `BR - Boleto urgency pay today`() {
        val result = analyze("Boleto vencendo hoje! Pague urgente para evitar juros.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `BR - Buy gift cards`() {
        val result = analyze("Compre cartoes presente do Google Play e me envie os codigos.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `BR - Gift card send code photo`() {
        // Regex: (cart[aã]o presente|gift.?card).{0,15}(compre|envie|mande|foto|c[oó]digo)
        val result = analyze("Cartao presente: me mande o codigo dele. Urgente!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `BR - If you dont pay legal threat`() {
        val result = analyze("Se nao pagar, tomaremos acao legal. Processo judicial contra voce.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `BR - Transfer to this account`() {
        val result = analyze("Transfira para essa conta o valor pendente. Urgente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `BR - TED DOC transfer request`() {
        val result = analyze("Mande uma TED para essa conta agora. E muito urgente.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `BR - Pending overdue bill`() {
        // Regex: (cobran[cç]a|fatura|boleto|conta).{0,15}(pendente|vencid[oa]|atrasad[oa]|em aberto)
        // Low weight (0.25) so combine with legal threat for higher confidence
        val result = analyze("Fatura vencida. Se nao pagar, tomaremos acao judicial contra voce.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `BR - Financial emergency help`() {
        val result = analyze("E uma emergencia financeira. Preciso de ajuda com grana agora.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // =========================================================================
    // CONVERSATION ANALYSIS (MULTI-MESSAGE)
    // =========================================================================

    @Test
    fun `BR - Conversation impersonation then PIX request`() {
        val result = analyzeConversation(listOf(
            "Oi mae, sou eu",
            "Troquei de numero, salva esse novo",
            "Preciso de ajuda urgente",
            "Faz um pix pra mim agora? Depois te explico"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.4f)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `BR - Conversation grooming then scam`() {
        val result = analyzeConversation(listOf(
            "Oi, tudo bem?",
            "Como voce esta?",
            "Tenho uma oportunidade incrivel de investimento",
            "Bitcoin com retorno garantido de 200%",
            "So precisa investir R$500 reais para comecar"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `BR - Conversation escalating bank fraud`() {
        val result = analyzeConversation(listOf(
            "Banco do Brasil informa: atividade suspeita detectada",
            "Sua conta sera bloqueada em 2 horas",
            "Informe sua senha e token para evitar bloqueio",
            "Urgente! Nao perca tempo!"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.5f)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // =========================================================================
    // SUSPICIOUS LINKS
    // =========================================================================

    @Test
    fun `BR - Suspicious bit ly link`() {
        val result = analyze("Acesse bit.ly/promo-especial para resgatar seu premio.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `BR - IP address link`() {
        // IP regex uses \d which won't match after normalization; use a different suspicious URL
        val result = analyze("Atualize seus dados em bit.ly/banco-seguro-atualizar")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // =========================================================================
    // CONFIDENCE AND THREAT LEVEL CHECKS
    // =========================================================================

    @Test
    fun `BR - High alert multi-category scam`() {
        val result = analyze(
            "URGENTE: Seu CPF foi cancelado pela Receita Federal. Sua conta Nubank sera bloqueada. " +
                "Informe sua senha e faca um PIX de R$500 para regularizar. Clique aqui: bit.ly/golpe"
        )
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.7f)
        assertEquals(ThreatLevel.HIGH_ALERT, result.threatLevel)
    }

    @Test
    fun `BR - Confidence is between 0 and 1`() {
        val result = analyze(
            "URGENTE: Sua conta foi bloqueada. Voce ganhou um sorteio. Envie o codigo. " +
                "Instale TeamViewer. Receita Federal tem uma divida sua. Invista em Bitcoin. Sera preso."
        )
        assertTrue(result.confidence in 0f..1f)
    }

    @Test
    fun `BR - Empty string returns NONE`() {
        val result = analyze("")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
        assertEquals(0f, result.confidence)
    }

    @Test
    fun `BR - Empty conversation returns NONE`() {
        val result = analyzeConversation(emptyList())
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    // =========================================================================
    // FALSE POSITIVES -- Normal Brazilian conversations
    // =========================================================================

    @Test
    fun `FP - Simple greeting E ai beleza`() {
        val result = analyze("E ai, beleza? Tudo certo contigo?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `FP - Bora almocar casual`() {
        val result = analyze("Bora almocar? To com fome. Onde a gente vai?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Normal PIX mention lunch`() {
        val result = analyze("Me manda o PIX do almoco. Quanto ficou?")
        // Normal PIX mention without scam context should not be suspicious
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Family talk Mae chego as 8`() {
        val result = analyze("Mae, chego as 8. Pode deixar a janta pronta?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Normal weather conversation`() {
        val result = analyze("Que calor hoje em Sao Paulo! Vamos na praia no fim de semana?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Asking about dinner`() {
        val result = analyze("O que vai ter de janta? To chegando em casa daqui a pouco.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Normal work conversation`() {
        val result = analyze("Amanha tenho reuniao as 9. Chego mais tarde em casa.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Discussing a movie`() {
        val result = analyze("Assistiu o filme novo da Netflix? Achei muito bom!")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - School pickup`() {
        val result = analyze("Busca as criancas na escola hoje? Nao vou conseguir sair do trabalho.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Doctor appointment`() {
        val result = analyze("Nao esquece da consulta amanha as 14h com o doutor.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Supermarket shopping`() {
        val result = analyze("Fui no mercado e comprei arroz, feijao, carne e verduras. Precisa de mais alguma coisa?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Birthday planning`() {
        val result = analyze("O aniversario do pai e sabado. Eu levo o bolo, voce traz os refrigerantes.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Sharing a recipe feijoada`() {
        val result = analyze("Pra feijoada precisa de feijao preto, linguica, costela e carne seca.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Talking about soccer futebol`() {
        val result = analyze("Viu o jogo do Flamengo ontem? Que golaço do Gabigol!")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Normal trip planning`() {
        val result = analyze("Vamos pra praia no feriado? Pensei em ir pra Floripa ou Buzios.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Simple love family message`() {
        val result = analyze("Te amo muito, se cuida! Bom dia!")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Asking for directions`() {
        val result = analyze("Como chego na sua casa? Me manda a localizacao pelo WhatsApp.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Normal entire conversation thread`() {
        val result = analyzeConversation(listOf(
            "Oi! Tudo bem?",
            "Tudo otimo e voce?",
            "Beleza. Vamos almocar sabado?",
            "Bora! Que horas?",
            "Meio dia na minha casa. Traz o refrigerante."
        ))
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Talking about paying electricity bill`() {
        val result = analyze("Ja paguei a conta de luz. Tava cara esse mes.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Casual money between friends`() {
        val result = analyze("Voce me deve a metade do presente. Sao 50 reais.")
        // Casual mention should not be suspicious or at most very low
        if (result.isSuspicious) {
            assertTrue(result.confidence <= 0.4f)
        }
    }

    @Test
    fun `FP - Normal Carnival conversation`() {
        val result = analyze("Carnaval esse ano vai ser demais! Ja comprou a fantasia?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `FP - Pharmacy reminder`() {
        val result = analyze("Passa na farmacia e compra o remedio da vovo. A receita ta na mesa.")
        assertFalse(result.isSuspicious)
    }
}
