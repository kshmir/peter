package com.peter.app.core.util

import com.peter.app.core.util.ScamPatternDetector.ScamCategory
import com.peter.app.core.util.ScamPatternDetector.ThreatLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Extensive English-language (US/general) scam pattern detection tests.
 *
 * Covers: IRS/Tax, Bank fraud, Social Security, Tech support, Package delivery,
 * Prize/lottery, Crypto/Bitcoin, Romance, Impersonation, Phishing, Money request,
 * Job scams, Nigerian prince / advance fee, Sextortion, Grandparent scam,
 * URL patterns, and false-positive scenarios.
 */
class ScamPatternDetectorEnglishTest {

    private fun analyze(text: String) = ScamPatternDetector.analyze(text)
    private fun analyzeConversation(messages: List<String>) =
        ScamPatternDetector.analyzeConversation(messages)

    // ═══════════════════════════════════════════════════════════════════════
    // IRS / TAX SCAMS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `IRS debt warning triggers GOVERNMENT_SCAM`() {
        val result = analyze("The IRS has identified unpaid back taxes on your account. Pay immediately to avoid penalties.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `IRS audit threat triggers GOVERNMENT_SCAM`() {
        val result = analyze("The IRS has identified an audit on your tax return. Settle your debt now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `IRS levy on wages triggers GOVERNMENT_SCAM`() {
        val result = analyze("The IRS will garnish your wages unless you settle your outstanding tax debt today.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `IRS lien warning triggers GOVERNMENT_SCAM`() {
        val result = analyze("A federal tax lien has been placed on your property by the IRS for overdue taxes.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `Internal Revenue fine triggers GOVERNMENT_SCAM`() {
        val result = analyze("Internal Revenue Service: You have an outstanding fine of $2,500. Pay to avoid arrest.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `IRS arrest threat with urgency`() {
        val result = analyze("You will be arrested if you don't pay your IRS debt immediately. Call this number now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `tax irregularity scam`() {
        val result = analyze("An irregularity on your tax return has been flagged. Contact us to resolve it.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `pay fine to avoid arrest triggers multiple categories`() {
        val result = analyze("Pay this fine to avoid arrest. You have 24 hours to respond before legal action.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BANK FRAUD
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `Wells Fargo account suspension`() {
        val result = analyze("Wells Fargo ALERT: Your account has been suspended due to suspicious activity. Verify now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `Chase bank blocked account`() {
        val result = analyze("Chase: We've blocked your account due to unauthorized access. Click here to restore it.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `Bank of America security alert`() {
        val result = analyze("Bank of America security alert: Unusual login detected. Verify your identity immediately.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `Citibank card compromised`() {
        val result = analyze("Citibank: Your debit card has been compromised. Call us immediately to block your card.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `Capital One suspicious transaction`() {
        val result = analyze("Capital One Alert: A suspicious transaction of $892 was made on your account.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `account suspended generic`() {
        val result = analyze("Your account has been suspended due to suspicious activity. Verify your information now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `request for PIN and SSN`() {
        val result = analyze("Please provide your PIN and social security number to verify your identity.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `credit card was charged fraudulently`() {
        val result = analyze("Your credit card has been charged $450 for a purchase you didn't authorize.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `unauthorized login to account`() {
        val result = analyze("Unauthorized login to your account was detected from an unknown device.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `wire transfer pending review`() {
        val result = analyze("Your wire transfer of $5,000 is pending review. Confirm your identity to proceed.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `Zelle account verification`() {
        val result = analyze("Zelle: Your account has been suspended. Verify your details to restore access.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `funds at risk warning`() {
        val result = analyze("Your money is at risk due to a security breach. Transfer funds to a safe account now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `to avoid account closure`() {
        val result = analyze("To avoid suspension of your account, please update your banking information immediately.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `we detected unauthorized transaction`() {
        val result = analyze("We detected a suspicious unauthorized transaction on your account. Please verify immediately.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `provide your card number and CVV`() {
        val result = analyze("Enter your card number and CVV to complete the refund process.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SOCIAL SECURITY SCAMS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `SSN suspended scam`() {
        val result = analyze("Your Social Security Number has been suspended due to suspicious activity.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `SSN compromised warning`() {
        val result = analyze("Your social security number has been compromised. Contact us immediately to protect your identity.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `Social Security benefits frozen`() {
        val result = analyze("Your Social Security benefits have been frozen due to irregularities in your account.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `SSA investigation warning`() {
        val result = analyze("The Social Security Administration has opened an investigation against your account.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TECH SUPPORT SCAMS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `Microsoft virus detected`() {
        val result = analyze("Microsoft alert: A virus has been detected on your computer. Call our support line immediately.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `Apple ID locked scam`() {
        val result = analyze("Apple warning: Your device has been compromised. Call support to fix the virus on your phone.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `your computer has been hacked`() {
        val result = analyze("Your computer has been hacked! Install this security software to protect your data.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `install TeamViewer for remote access`() {
        val result = analyze("Please install TeamViewer so our technician can fix your computer remotely.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `AnyDesk remote access request`() {
        val result = analyze("Download AnyDesk and allow access so we can remove the malware from your device.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `Norton subscription expired`() {
        val result = analyze("Norton alert: Your antivirus subscription has expired. Your device is infected with malware. Renew now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `your phone has malware`() {
        val result = analyze("WARNING: Your phone is infected with malware. Your data is at risk of being stolen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `pay for virus removal`() {
        val result = analyze("Your computer has a virus. Pay for the repair to clean the malware from your device.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `WhatsApp blocked in 72 hours`() {
        val result = analyze("Your WhatsApp will be blocked in 72 hours. Verify your account to avoid deletion.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `official support from Microsoft`() {
        val result = analyze("This is from the official support team from Microsoft. We detected unauthorized access to your PC.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `call this phone number for tech help`() {
        val result = analyze("Your device has a virus. Call +1-800-555-1234 to speak with our support team.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    @Test
    fun `your files will be deleted`() {
        val result = analyze("Your files will be deleted if you don't act now. Our team can help recover them.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.TECH_SUPPORT })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PRIZE / LOTTERY SCAMS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `you have won a prize`() {
        val result = analyze("Congratulations! You've won a $10,000 prize! Claim it now before it expires!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `Amazon gift card giveaway`() {
        val result = analyze("Amazon is celebrating its anniversary! You've been selected to receive a $500 Amazon gift card.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `Walmart sweepstakes winner`() {
        val result = analyze("Walmart sweepstakes: You are the lucky winner! Claim your prize now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `free iPhone offer`() {
        val result = analyze("You have been selected for a free iPhone 15! Click the link to claim yours.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `share with 8 contacts`() {
        val result = analyze("Share this with 8 contacts to claim your prize! You've been selected as a winner!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `your number was selected`() {
        val result = analyze("Your number has been selected in our monthly draw. You've won a cash prize!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `pay fee to receive prize`() {
        val result = analyze("Pay a small processing fee to receive your $5,000 prize money.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `government grant approved`() {
        val result = analyze("You are eligible for a federal government grant of $9,500. Claim it now!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `stimulus check scam`() {
        val result = analyze("Your stimulus payment of $1,400 is available. Claim your deposit now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `only 8 prizes left`() {
        val result = analyze("Hurry! Only 8 prizes left! Click now to claim yours before they're gone.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `free gift card voucher`() {
        val result = analyze("Claim your free $100 gift card now! Exclusive offer, limited time only.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `congratulations winner notification`() {
        val result = analyze("Congratulations! You are the lucky winner of our special prize lottery!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CRYPTO / BITCOIN INVESTMENT SCAMS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `Bitcoin investment opportunity`() {
        val result = analyze("Amazing Bitcoin investment opportunity! Double your money in just 7 days.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `guaranteed crypto returns`() {
        val result = analyze("Invest in crypto and get guaranteed 300% returns. No risk involved!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `Ethereum profit scam`() {
        val result = analyze("Invest in Ethereum now and watch your profits grow. Join thousands of successful investors.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `double your money crypto`() {
        val result = analyze("Double your investment in 48 hours with our trading platform. Minimum $250.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `forex trading signals`() {
        val result = analyze("Join our forex trading group. Profit signals daily. 95% win rate guaranteed.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `passive income financial freedom`() {
        val result = analyze("Earn passive income with Bitcoin. Guaranteed 200% returns in just one month!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `seed phrase request`() {
        val result = analyze("We need your seed phrase. Send it to us to verify your wallet and process the withdrawal.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
        assertTrue(result.confidence > 0.3f)
    }

    @Test
    fun `connect MetaMask wallet`() {
        val result = analyze("Your MetaMask wallet needs to sync with our platform. Double your investment today!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `NFT investment opportunity`() {
        val result = analyze("Exclusive NFT opportunity! Buy now before the limited mint sells out.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `crypto airdrop free tokens`() {
        val result = analyze("Claim your free airdrop tokens! Limited supply, first come first served.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `trading bot automated profits`() {
        val result = analyze("Our trading bot earns automated profit every day. Set it up in 5 minutes!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `my financial advisor crypto`() {
        val result = analyze("My advisor financial helped me make $10,000 in crypto last month. DM me for details.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `Binance investment returns`() {
        val result = analyze("Binance investment plan: guaranteed 200% returns in 30 days. Start with just $100.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `minimum investment to start`() {
        val result = analyze("Only $250 to start investing in our platform. Triple your capital in a week!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `earn easy money from home`() {
        val result = analyze("Earn easy money from home! Make $500 daily with this simple crypto trick.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ROMANCE SCAMS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `military stationed abroad`() {
        val result = analyze("I'm a soldier deployed overseas in Afghanistan and I need someone to talk to.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `need money for flight to visit`() {
        val result = analyze("I need money for the flight to come see you, my love. I'll pay you back, I promise.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `stranded at airport customs`() {
        val result = analyze("I'm stuck at the airport and they detained me at customs. I need help!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `widow looking for love`() {
        val result = analyze("I'm a widow looking for love. I found your profile on Facebook and couldn't resist reaching out. God brought us together.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `found your profile online`() {
        val result = analyze("I found your profile on Facebook. I'm a military soldier stationed overseas and I'd love to meet you.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `inheritance millions to share`() {
        val result = analyze("I have an inheritance of millions of dollars and I need your help to receive it.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `UN military package fund`() {
        val result = analyze("I am a UN officer and I have a trunk with gold that I need to ship to you.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `God brought us together`() {
        val result = analyze("God brought us together for a reason. I need money for the flight to come see you, my darling.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `keep relationship secret from family`() {
        val result = analyze("Don't tell your family about us. This stays between us for now, okay?")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `request for intimate photos sextortion`() {
        val result = analyze("Send me your intimate photos so I know you are real. I want to see you.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `pet names plus money request`() {
        val result = analyze("My darling, I need you to send me some money. I'm in a very difficult situation.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `engineer on oil rig abroad`() {
        val result = analyze("I work as an engineer on an oil rig overseas. I want to send you a package of gold.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // IMPERSONATION / GRANDPARENT SCAM
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `grandma it is me classic scam`() {
        val result = analyze("Grandma it's me! I'm in trouble and I need your help urgently.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `mom its me I changed my number`() {
        val result = analyze("Mom it's me. I changed my number. This is my new phone. Please send me some money, I'm in trouble.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `this is my new number save it`() {
        val result = analyze("This is my new number. Save this contact and delete the old one please.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `I am your grandson in jail`() {
        val result = analyze("I'm your grandson and I'm in jail. Please don't tell mom. I need bail money.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `I had an accident need money`() {
        val result = analyze("I had an accident and I need money for the hospital. Please help me.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `my phone was stolen new number`() {
        val result = analyze("Hey, my phone was stolen so this is a new number. Can you help me out?")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `guess who this is`() {
        val result = analyze("Hey! Guess who this is! Long time no talk, right?")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `don't tell anyone keep secret`() {
        val result = analyze("Please don't tell anyone about this situation. Keep it between us.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `send money I will pay back`() {
        val result = analyze("Can you send me money? I'll pay you back tomorrow, I promise!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `lend me some cash please`() {
        val result = analyze("Can you lend me some dollars? I'm in a really tight spot right now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `I need your help with money`() {
        val result = analyze("I need your help urgently. Can you wire some money to this account?")
        assertTrue(result.isSuspicious)
    }

    @Test
    fun `don't you recognize me`() {
        val result = analyze("Don't you recognize me? It's been so long! How are you?")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PHISHING
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `verify your account identity`() {
        val result = analyze("You need to verify your account immediately or it will be permanently closed.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `click here to update`() {
        val result = analyze("Click here to update your security settings. Your account is at risk.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `send me your verification code`() {
        val result = analyze("Can you send me the verification code I just sent to your phone? I need it urgently.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `your WhatsApp will be deleted`() {
        val result = analyze("Your WhatsApp account will be deleted if you don't confirm your identity now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `WhatsApp Gold fake version`() {
        val result = analyze("Download WhatsApp Gold now! Premium features available for free, limited time.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `OTP code by mistake`() {
        val result = analyze("Sorry, I sent a code to your number by mistake. Can you forward it to me?")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `update your WhatsApp version`() {
        val result = analyze("Update your WhatsApp to the latest version or your account will be deactivated.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `your WhatsApp was hacked`() {
        val result = analyze("Your WhatsApp has been hacked. Click this link to secure your account.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `scan this QR code`() {
        val result = analyze("Scan this QR code to verify your WhatsApp account and prevent suspension.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `personal information verification`() {
        val result = analyze("Your personal information needs to be updated. Your account will be deleted unless you confirm now.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `we sent a code to your phone`() {
        val result = analyze("We sent a code to your phone. Please share it with us to verify your identity.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `visit this link to confirm`() {
        val result = analyze("Visit this link to confirm your identity and restore your account access.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MONEY REQUEST
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `send money via Zelle`() {
        val result = analyze("Please send the payment via Zelle to this number right away.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `Venmo transfer request`() {
        val result = analyze("Use Venmo to send me the money right now. It's an emergency, I need it urgently.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `CashApp payment demand`() {
        val result = analyze("Pay me through CashApp right now. Send it immediately please.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `buy gift cards and send codes`() {
        val result = analyze("I need you to buy Google Play gift cards and send me the codes on the back.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `iTunes gift card scratch and send`() {
        val result = analyze("Buy iTunes gift cards, scratch them and send me a photo of the codes.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `send photo of card receipt`() {
        val result = analyze("Send me a photo of the card so I can redeem it. Front and back please.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `if you don't pay legal action`() {
        val result = analyze("If you don't pay this debt, we will take legal action and have you arrested.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `overdue bill warning`() {
        val result = analyze("Your bill is overdue. Failure to pay will result in additional penalties.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `transfer to this account number`() {
        val result = analyze("Transfer to the following account immediately: routing number 021000021.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `Western Union wire transfer`() {
        val result = analyze("Western Union: Send $500 to this account now. It's extremely urgent.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `PayPal pay immediately`() {
        val result = analyze("You must pay through PayPal right now to avoid losing your order.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `financial emergency need help`() {
        val result = analyze("It's a financial emergency, I need money right now! Please wire funds to this account immediately.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // NIGERIAN PRINCE / ADVANCE FEE SCAMS
    // (Covered by ROMANCE_SCAM and PRIZE_SCAM patterns)
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `inheritance from foreign country needs help`() {
        val result = analyze("I have an inheritance of $4.5 million and I need your help to transfer it. You will get 30%.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any {
            it.category == ScamCategory.ROMANCE_SCAM || it.category == ScamCategory.PRIZE_SCAM
        })
    }

    @Test
    fun `fortune to share with you`() {
        val result = analyze("I have a fortune from my late husband's estate. I need your help to move the funds.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `pay processing fee to unlock fortune`() {
        val result = analyze("Pay a small processing fee of $200 to receive your share of $2 million.")
        assertTrue(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SEXTORTION
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `send intimate photos request`() {
        val result = analyze("Send me your private photos now. I want to see the real you.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    @Test
    fun `send nude videos request`() {
        val result = analyze("Send me your nude videos to prove you are serious about us.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.ROMANCE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // JOB SCAMS
    // (Covered by CRYPTO_SCAM passive income / work from home patterns)
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `work from home easy money`() {
        val result = analyze("Work from home and earn easy money! No experience needed, start today!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `make money online daily`() {
        val result = analyze("Make money online every day with this simple system. Anyone can do it!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    @Test
    fun `passive income opportunity`() {
        val result = analyze("Get passive income with zero effort. Financial freedom is just a click away!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.CRYPTO_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // URL PATTERNS / SUSPICIOUS LINKS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `bit ly shortened link`() {
        val result = analyze("Click on this link to claim your prize: bit.ly/abc123")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `tinyurl shortened link`() {
        val result = analyze("Verify your account here: tinyurl.com/xyz789")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `IP address URL`() {
        val result = analyze("Visit http://192.168.1.100 to confirm your account details.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `typosquatting WhatsApp URL`() {
        val result = analyze("Update your account at https://whasapp.com/verify to avoid suspension.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `typosquatting Facebook URL`() {
        val result = analyze("Your account will be suspended. Click here to verify your identity: https://faceb00k.com/security")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `cutt ly shortened link`() {
        val result = analyze("Click here to verify your account and claim your prize: cutt.ly/promo999")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // URGENCY AMPLIFICATION
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `urgency words boost confidence for bank fraud`() {
        val base = analyze("Your account has been suspended due to suspicious activity.")
        val withUrgency = analyze("URGENT: Your account has been suspended due to suspicious activity. Act now!")
        assertTrue(base.isSuspicious)
        assertTrue(withUrgency.isSuspicious)
        assertTrue("Urgency should boost confidence", withUrgency.confidence >= base.confidence)
    }

    @Test
    fun `act now and hurry boost`() {
        val result = analyze("Hurry! Your bank account has been blocked. Act now to avoid losing your funds!")
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.3f)
    }

    @Test
    fun `expires today limited time boost`() {
        val result = analyze("Congratulations! You've won a prize. Claim it today only - limited time offer expires today.")
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.3f)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CONVERSATION ANALYSIS
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `conversation escalation - friendly then scam`() {
        val result = analyzeConversation(listOf(
            "Hi, how are you doing?",
            "I hope you're having a great day!",
            "By the way, I changed my number.",
            "I'm in trouble and I need you to send me money right away.",
            "Please wire $500 to this account number 123456789."
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `conversation with repeated urgency`() {
        val result = analyzeConversation(listOf(
            "Your account has been compromised. Act now!",
            "This is urgent! You must verify your identity immediately.",
            "Don't delay - your funds are at risk!"
        ))
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.4f)
    }

    @Test
    fun `conversation with multiple money requests`() {
        val result = analyzeConversation(listOf(
            "Your Chase account has a suspicious transaction.",
            "We need to verify your identity to secure your funds.",
            "Transfer your money to this safe account to protect it."
        ))
        assertTrue(result.isSuspicious)
    }

    @Test
    fun `normal conversation not flagged`() {
        val result = analyzeConversation(listOf(
            "Hey, how are you?",
            "I'm doing well, thanks!",
            "Want to grab lunch tomorrow?",
            "Sure, let's do Italian."
        ))
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // THREAT LEVEL VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `HIGH_ALERT for combined bank fraud with urgency`() {
        val result = analyze("URGENT: Your Wells Fargo account has been suspended. Provide your SSN and PIN immediately to avoid permanent closure!")
        assertTrue(result.isSuspicious)
        assertTrue("High-risk combined scam should score high", result.confidence > 0.5f)
    }

    @Test
    fun `WARNING level for moderate scam`() {
        val result = analyze("Your card has been compromised. Please update your banking details.")
        assertTrue(result.isSuspicious)
        assertTrue(result.confidence > 0.2f)
    }

    @Test
    fun `NONE for blank message`() {
        val result = analyze("")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
        assertEquals(0f, result.confidence)
    }

    @Test
    fun `NONE for whitespace only`() {
        val result = analyze("   \t  \n  ")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MULTI-CATEGORY DETECTION
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `message hitting multiple scam categories`() {
        val result = analyze(
            "URGENT: The IRS has filed a lawsuit against you. " +
            "Send $5,000 via Western Union immediately to avoid arrest. " +
            "Click here to verify your identity: bit.ly/irsverify"
        )
        assertTrue(result.isSuspicious)
        val categories = result.matchedPatterns.map { it.category }.toSet()
        assertTrue("Should detect government scam", categories.contains(ScamCategory.GOVERNMENT_SCAM))
        assertTrue("Should detect phishing", categories.contains(ScamCategory.PHISHING))
        assertTrue(result.confidence > 0.5f)
    }

    @Test
    fun `impersonation plus money request`() {
        val result = analyze(
            "Grandma it's me! I changed my number. " +
            "I'm in jail and I need you to buy Google Play gift cards and send me the codes."
        )
        assertTrue(result.isSuspicious)
        val categories = result.matchedPatterns.map { it.category }.toSet()
        assertTrue("Should detect impersonation", categories.contains(ScamCategory.IMPERSONATION))
        assertTrue("Should detect money request", categories.contains(ScamCategory.MONEY_REQUEST))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DMV / VISA / IMMIGRATION
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `DMV license suspension scam`() {
        val result = analyze("The DMV has issued a suspension of your license. Pay the fine to avoid arrest.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `visa revoked scam`() {
        val result = analyze("Your visa has been revoked due to a problem with your application. Contact us immediately.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `you have 72 hours to pay or respond`() {
        val result = analyze("You have 72 hours to pay the outstanding amount or you will be arrested.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `asset seizure warning`() {
        val result = analyze("A levy on your assets has been ordered. Seizure of your property will proceed unless you settle.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FALSE POSITIVES - Normal messages that should NOT trigger
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `false positive - simple greeting`() {
        val result = analyze("Hey, how are you?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - grocery errand`() {
        val result = analyze("Can you pick up milk on the way home?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - weather chat`() {
        val result = analyze("It's really cold today. Don't forget your jacket!")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - dinner plans`() {
        val result = analyze("What do you want for dinner tonight? I was thinking pasta.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - bank is closed today`() {
        val result = analyze("The bank is closed today because of the holiday.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - new phone number normal`() {
        val result = analyze("I just got a new phone number. The old one stopped working.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `false positive - doctor appointment`() {
        val result = analyze("Don't forget you have a doctor's appointment at 3pm tomorrow.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - family event`() {
        val result = analyze("We are meeting at noon for lunch. Are you coming?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - weekend plans`() {
        val result = analyze("Want to go to the park this weekend? The kids would love it.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - school pickup`() {
        val result = analyze("I'll pick up the kids from school today. You rest.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - sharing a recipe`() {
        val result = analyze("Here's that chicken soup recipe you asked for. Add salt to taste!")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - congratulations on real event`() {
        val result = analyze("Congratulations on your graduation! We are so proud of you!")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `false positive - good morning message`() {
        val result = analyze("Good morning! Hope you have a wonderful day today.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - photo sharing`() {
        val result = analyze("Look at this photo from our trip last summer. Such great memories!")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - simple thank you`() {
        val result = analyze("Thank you so much for helping me yesterday. I really appreciate it.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - movie recommendation`() {
        val result = analyze("Have you seen that new movie? It was really good, you should watch it.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - running late`() {
        val result = analyze("I'm running a bit late. Traffic is terrible today. Be there in 20 minutes.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - pet update`() {
        val result = analyze("The dog just had his vet checkup. Everything looks good!")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - love from family`() {
        val result = analyze("I love you so much! Have a great day at work today, sweetheart.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `false positive - picking up medication`() {
        val result = analyze("I'll stop by the pharmacy to pick up your medication on my way home.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - happy birthday`() {
        val result = analyze("Happy birthday! Wishing you all the best today and always.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `false positive - church plans`() {
        val result = analyze("Are you coming to church on Sunday? The service starts at 10am.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `empty conversation returns NONE`() {
        val result = analyzeConversation(emptyList())
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
        assertEquals(0f, result.confidence)
    }
}
