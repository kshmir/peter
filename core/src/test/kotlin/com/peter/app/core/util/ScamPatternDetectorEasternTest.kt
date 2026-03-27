package com.peter.app.core.util

import com.peter.app.core.util.ScamPatternDetector.ScamCategory
import com.peter.app.core.util.ScamPatternDetector.ThreatLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Extensive Eastern European + Turkish scam pattern detection tests.
 *
 * Covers: Polish (PL), Ukrainian (UK), Russian (RU), Turkish (TR)
 * with false-positive scenarios for each language.
 */
class ScamPatternDetectorEasternTest {

    private fun analyze(text: String) = ScamPatternDetector.analyze(text)

    // ═══════════════════════════════════════════════════════════════════════
    // POLISH (PL) — Bank Fraud
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `PL - bank account blocked`() {
        val result = analyze("Twoje konto zostalo zablokowane z powodu podejrzanej aktywnosci. Zaloguj sie natychmiast.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PL - mBank verification scam`() {
        val result = analyze("mBank: Wymagana weryfikacja konta w ciagu 24h z powodu podejrzanej aktywnosci.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PL - PKO BP card suspended`() {
        val result = analyze("PKO BP: Pani karta zostala zawieszona. Prosimy o potwierdzenie danych.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PL - ING Bank fraud alert`() {
        val result = analyze("ING Bank: Wykryto nieautoryzowane logowanie na Pana koncie. Wymagana weryfikacja.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PL - Santander card blocked`() {
        val result = analyze("Santander: Pani karta zostala zablokowana z powodu podejrzanych transakcji. Potwierdz dane.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PL - BLIK fraud alert`() {
        val result = analyze("Uwaga! Wykryto nieautoryzowana transakcje BLIK na Twoim koncie. Potwierdz operacje.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PL - Przelewy24 payment issue`() {
        val result = analyze("Przelewy24: Problem z Twoja platnoscia. Wymagana weryfikacja danych karty.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PL - request for PIN and card data`() {
        val result = analyze("Podaj swoje haslo i numer karty oraz kod CVV aby odblokowac konto.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PL - suspicious unauthorized transaction`() {
        val result = analyze("Podejrzana transakcja na kwote 3500 PLN wykryta na koncie. Jezeli to nie Ty, zadzwon natychmiast.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PL - card compromised warning`() {
        val result = analyze("Twoja karta zostala skompromitowana. Natychmiast zablokuj karte i podaj dane nowej.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `PL - avoid account blocking urgency`() {
        val result = analyze("Aby uniknac blokady konta, nalezy natychmiast potwierdzic swoje dane logowania.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // POLISH (PL) — Prize Scam
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `PL - lottery prize won`() {
        val result = analyze("Gratulacje! Wygrales 50 000 zlotych w naszym losowaniu. Odbierz nagrode teraz!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `PL - free voucher scam`() {
        val result = analyze("Otrzymales kupon za darmo do Biedronki o wartosci 500 zl. Odbierz klikajac tutaj.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `PL - you were selected winner`() {
        val result = analyze("Zostales wybrany sposrod tysiecy uczestnikow. Twoja nagroda czeka!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // POLISH (PL) — Phishing
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `PL - click link phishing`() {
        val result = analyze("Kliknij link ponizej aby zweryfikowac swoje konto bankowe.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `PL - verify account data`() {
        val result = analyze("Zweryfikuj swoje konto w ciagu 24 godzin lub zostanie ono zamkniete.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `PL - InPost package delivery phishing`() {
        val result = analyze("InPost: Paczka niedostarczona. Oplata wymagana, kliknij tutaj aby potwierdzic.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `PL - DHL delivery fee scam`() {
        val result = analyze("DHL: Paczka oczekuje na doplaty. Potwierdz oplate aby otrzymac przesylke.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `PL - account will be deleted`() {
        val result = analyze("Twoje konto zostanie usuniete w ciagu 48h jesli nie zaktualizujesz danych.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // POLISH (PL) — Money Request
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `PL - urgent money transfer BLIK`() {
        val result = analyze("Pilnie potrzebuje pieniedzy. Wyslij mi kod BLIK na 500 zl, blgam!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `PL - transfer to account number`() {
        val result = analyze("Przelej 2000 zl na konto 12 3456 7890. To bardzo pilne.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `PL - need financial help urgently`() {
        val result = analyze("Potrzebuje pomocy finansowej. Jak najszybciej przeslij mi pieniadze na rachunek.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // POLISH (PL) — Impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `PL - grandma impersonation changed number`() {
        val result = analyze("Babciu, to ja, zmienilam numer telefonu. Zapisz ten nowy kontakt.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `PL - mom I had an accident`() {
        val result = analyze("Mamo, mialem wypadek i jestem w szpitalu. Potrzebuje pilnie pieniedzy na leczenie.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `PL - its me your grandson`() {
        val result = analyze("To ja, twoj wnuk. Nie poznajesz mnie? Mam nowy numer, zapisz sobie.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // POLISH (PL) — Government Scam
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `PL - ZUS social security debt`() {
        val result = analyze("ZUS: Wykryto zaleglosc w skladkach. Ureguluj naleznosc w ciagu 7 dni lub grozi kara.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `PL - tax office penalty`() {
        val result = analyze("Urzad Skarbowy: Masz zaleglosc podatkowa w wysokosci 8500 PLN. Zaplac natychmiast.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `PL - police summons threat`() {
        val result = analyze("Policja: Otrzymales wezwanie do zaplaty mandatu. Grozi ci areszt w razie niezaplaty.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `PL - Profil Zaufany expired`() {
        val result = analyze("Twoj Profil Zaufany na ePUAP wygasl. Zaktualizuj go natychmiast aby uniknac blokady.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // POLISH (PL) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `PL FP - normal greeting`() {
        val result = analyze("Czesc, co u ciebie? Jak tam w pracy?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `PL FP - planning Sunday dinner`() {
        val result = analyze("W niedziele robimy obiad u babci. Przywieziesz ciasto?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `PL FP - asking about the weather`() {
        val result = analyze("Jaka pogoda dzisiaj? Bierzemy parasol czy nie?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `PL FP - normal shopping conversation`() {
        val result = analyze("Bylem w Biedronce i kupilem chleb, mleko i jajka. Potrzebujesz czegos jeszcze?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `PL FP - doctor appointment reminder`() {
        val result = analyze("Pamietaj ze jutro masz wizyte u lekarza o godzinie 10.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `PL FP - discussing a movie`() {
        val result = analyze("Widziales nowy film? Bardzo mi sie podobal, polecam ci go.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `PL FP - normal work conversation`() {
        val result = analyze("Jutro mam spotkanie o 9 rano. Mozesz przyjsc wczesniej?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `PL FP - birthday party planning`() {
        val result = analyze("Urodziny taty sa w sobote. Ja kupie prezent, a ty przynies napoje.")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // UKRAINIAN (UK) — Bank Fraud
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `UK - PrivatBank account blocked`() {
        val result = analyze("ПриватБанк: Ваш рахунок заблоковано через підозрілу активність. Підтвердіть дані.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UK - Monobank card suspended`() {
        val result = analyze("Монобанк: Вашу картку призупинено з міркувань безпеки. Пройдіть верифікацію.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UK - A-Bank verification required`() {
        val result = analyze("А-Банк: Виявлено несанкціонований доступ до вашого рахунку. Оновіть дані безпеки.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UK - request PIN and SMS code`() {
        val result = analyze("Для розблокування введіть пін-код та код з СМС який ви отримали.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UK - suspicious transaction detected`() {
        val result = analyze("Виявлено підозрілу операцію на суму 15000 грн. Зверніться до служби безпеки.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UK - card compromised warning`() {
        val result = analyze("Ваша картка скомпрометована. Негайно заблокуйте її та передайте нам дані нової.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UK - money at risk urgency`() {
        val result = analyze("Ваші кошти під загрозою! Для збереження коштів перекажіть їх на безпечний рахунок.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UK - Oschadbank fraud alert`() {
        val result = analyze("Ощадбанк: Ваш рахунок заблоковано. Для підтвердження перейдіть за посиланням.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `UK - avoid blocking transfer funds`() {
        val result = analyze("Для уникнення блокування рахунку терміново підтвердіть особисті дані.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // UKRAINIAN (UK) — Prize Scam
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `UK - lottery prize won`() {
        val result = analyze("Вітаємо! Ви виграли 100 000 гривень у нашому розіграші. Отримайте ваш приз!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `UK - you have been selected`() {
        val result = analyze("Вас обрано переможцем акції! Заберіть ваш подарунок протягом 24 годин.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `UK - free voucher coupon`() {
        val result = analyze("Отримайте ваучер на 5000 грн безкоштовно. Акція діє лише сьогодні!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // UKRAINIAN (UK) — Phishing
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `UK - click link phishing`() {
        val result = analyze("Натисніть на посилання нижче для підтвердження вашого рахунку.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `UK - verify account data`() {
        val result = analyze("Верифікуйте свій обліковий запис протягом 48 годин або його буде видалено.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `UK - Nova Poshta delivery phishing`() {
        val result = analyze("Нова Пошта: Ваша посилка не доставлена. Оплатіть доставку за посиланням.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `UK - Ukrposhta package fee`() {
        val result = analyze("Укрпошта: Ваше відправлення очікує. Доплатіть 150 грн для отримання.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // UKRAINIAN (UK) — Money Request
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `UK - urgent money transfer request`() {
        val result = analyze("Терміново надішли гроші на картку! Дуже потрібно, поясню потім.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `UK - transfer to card urgently`() {
        val result = analyze("Переведи 5000 грн на карту негайно. Це дуже важливо.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `UK - need financial help`() {
        val result = analyze("Потрібні гроші на операцію. Якнайшвидше скинь на рахунок.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // UKRAINIAN (UK) — Impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `UK - grandma impersonation new number`() {
        val result = analyze("Бабусю, це я, твоя онучка. Змінила номер, запиши новий.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `UK - mom I had a car accident`() {
        val result = analyze("Мамо, потрапив у аварію, зараз в лікарні. Потрібна допомога терміново.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `UK - its me your son`() {
        val result = analyze("Це я, твій син. Не впізнаєш? Пишу з нового телефону.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // UKRAINIAN (UK) — Government Scam
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `UK - tax service debt penalty`() {
        val result = analyze("Державна податкова служба: У вас заборгованість по податках. Сплатіть штраф негайно.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `UK - Diia digital signature expired`() {
        val result = analyze("Дія: Ваш електронний підпис закінчується. Оновіть його щоб уникнути блокування.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `UK - police summons threat`() {
        val result = analyze("Поліція: Вам загрожує арешт за несплату штрафів. Зверніться терміново.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `UK - pension fund verification`() {
        val result = analyze("Пенсійний фонд: Необхідне оновлення даних для продовження виплати пенсії.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // UKRAINIAN (UK) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `UK FP - normal greeting`() {
        val result = analyze("Привіт, як справи? Що нового?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `UK FP - weekend plans`() {
        val result = analyze("У неділю їдемо до бабусі на обід. Візьми пиріжки.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `UK FP - weather discussion`() {
        val result = analyze("Яка сьогодні погода? Треба брати парасольку?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `UK FP - grocery shopping`() {
        val result = analyze("Була в АТБ, купила хліб, молоко та сир. Щось ще треба?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `UK FP - doctor appointment`() {
        val result = analyze("Не забудь, завтра у тебе прийом у лікаря о десятій.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `UK FP - school pickup conversation`() {
        val result = analyze("Сьогодні я не можу забрати дітей зі школи. Зможеш ти?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `UK FP - discussing a recipe`() {
        val result = analyze("Для борщу потрібні буряк, картопля, капуста та морква.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `UK FP - normal work chat`() {
        val result = analyze("Завтра нарада о дев'ятій. Приходь раніше, будь ласка.")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RUSSIAN (RU) — Bank Fraud
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RU - Sberbank account blocked`() {
        val result = analyze("Сбербанк: Ваш счёт заблокирован из-за подозрительной активности. Подтвердите данные.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RU - Tinkoff card suspended`() {
        val result = analyze("Тинькофф: Ваша карта приостановлена. Пройдите верификацию для восстановления доступа.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RU - VTB fraud verification`() {
        val result = analyze("ВТБ: Обнаружен несанкционированный вход в ваш аккаунт. Срочно обновите данные безопасности.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RU - Alfa-Bank suspicious transaction`() {
        val result = analyze("Альфа-Банк: Подозрительная операция на 45000 руб. Подтвердите или заблокируйте карту.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RU - SBP fast payment fraud`() {
        val result = analyze("Ошибка в системе быстрых платежей СБП. Для возврата средств подтвердите перевод.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RU - request PIN and CVV`() {
        val result = analyze("Введите пин-код и номер карты с CVV для подтверждения операции.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RU - unauthorized transaction alert`() {
        val result = analyze("Обнаружена несанкционированная операция списания 28000 руб. с вашей карты.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RU - card compromised cloned`() {
        val result = analyze("Ваша карта скомпрометирована. Мошенники получили доступ к данным.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RU - savings at risk`() {
        val result = analyze("Ваши сбережения под угрозой! Переведите средства на безопасный счёт немедленно.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RU - bank security service call`() {
        val result = analyze("Служба безопасности банка. Перезвоните нам по номеру для подтверждения личности.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `RU - avoid loss of funds`() {
        val result = analyze("Для предотвращения потери средств срочно подтвердите данные вашей карты.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RUSSIAN (RU) — Prize Scam
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RU - lottery prize notification`() {
        val result = analyze("Поздравляем! Вы выиграли 500 000 рублей в розыгрыше! Заберите ваш приз.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `RU - you were selected as winner`() {
        val result = analyze("Вы были выбраны победителем нашей акции. Оформите получение награды.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `RU - free certificate voucher`() {
        val result = analyze("Вам начислен сертификат бесплатно на 10000 руб. Получите его прямо сейчас!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RUSSIAN (RU) — Phishing
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RU - click link phishing`() {
        val result = analyze("Нажмите по ссылке ниже для подтверждения вашего аккаунта.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `RU - Gosuslugi account verification`() {
        val result = analyze("Госуслуги: Ваш аккаунт заблокирован. Обновите данные чтобы восстановить доступ.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any {
            it.category == ScamCategory.PHISHING || it.category == ScamCategory.GOVERNMENT_SCAM
        })
    }

    @Test
    fun `RU - CDEK package delivery phishing`() {
        val result = analyze("СДЭК: Ваша посылка не доставлена. Оплатите доставку по ссылке.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `RU - Wildberries order problem`() {
        val result = analyze("Wildberries: Проблема с вашим заказом. Подтвердите данные для доставки.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `RU - account will be deleted`() {
        val result = analyze("Ваш аккаунт будет удалён через 24 часа. Подтвердите свои данные немедленно.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RUSSIAN (RU) — Money Request
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RU - urgent money transfer`() {
        val result = analyze("Срочно пришли деньги на карту! Объясню потом, очень надо.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `RU - transfer to card number`() {
        val result = analyze("Переведи 30000 руб на карту немедленно. Это вопрос жизни и смерти.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `RU - lend money until payday`() {
        val result = analyze("Одолжи до зарплаты 15 тысяч. Скинь на карту, верну через неделю.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `RU - need money urgently`() {
        val result = analyze("Нужны деньги срочно! Как можно скорее отправь на счёт.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RUSSIAN (RU) — Impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RU - grandma its your grandson`() {
        val result = analyze("Бабуль, это я, твой внучок. Сменил номер, запиши новый.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `RU - mom I got in an accident`() {
        val result = analyze("Мам, попал в аварию, я в больнице. Нужна помощь, пришли денег срочно.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `RU - its me your daughter`() {
        val result = analyze("Это я, твоя дочка. Не узнаёшь? У меня новый номер телефона.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `RU - boss impersonation urgent task`() {
        val result = analyze("Директор просил срочно перевести 200 000 руб. по этим реквизитам. Срочное дело.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RUSSIAN (RU) — Government Scam
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RU - FNS tax debt`() {
        val result = analyze("ФНС: У вас задолженность по налогам в размере 85000 руб. Оплатите штраф немедленно.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `RU - MVD police investigation`() {
        val result = analyze("МВД: На вас заведено уголовное дело. Срочно свяжитесь по указанному номеру.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `RU - court bailiff debt enforcement`() {
        val result = analyze("ФССП: Судебный пристав наложил арест на ваш счёт за задолженность.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `RU - threat of arrest`() {
        val result = analyze("Вам грозит арест за неуплату штрафов. Оплатите в течение суток.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `RU - Gosuslugi portal expired`() {
        val result = analyze("Госуслуги: Ваш аккаунт истекает. Обновите данные для продолжения.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `RU - pension fund recalculation`() {
        val result = analyze("Пенсионный фонд: Требуется обновление данных для перерасчёта пенсии.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `RU - Central Bank warning`() {
        val result = analyze("Центральный банк предупреждает: ваш счёт под угрозой блокировки.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RUSSIAN (RU) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `RU FP - normal greeting`() {
        val result = analyze("Привет, как дела? Что нового у тебя?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `RU FP - Sunday lunch plans`() {
        val result = analyze("В воскресенье едем к бабушке на обед. Привези пирожки.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RU FP - weather discussion`() {
        val result = analyze("Какая сегодня погода? Нужно ли брать зонтик?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RU FP - grocery shopping`() {
        val result = analyze("Зашёл в Пятёрочку, купил хлеб, молоко и яйца. Тебе что-нибудь нужно?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RU FP - doctor appointment reminder`() {
        val result = analyze("Напоминаю, завтра у тебя приём у врача в десять утра.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RU FP - discussing a movie`() {
        val result = analyze("Смотрел новый фильм? Очень хороший, рекомендую посмотреть.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RU FP - birthday planning`() {
        val result = analyze("День рождения мамы в субботу. Я куплю торт, а ты принеси напитки.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `RU FP - normal work conversation`() {
        val result = analyze("Завтра совещание в девять. Приходи пораньше, пожалуйста.")
        assertFalse(result.isSuspicious)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TURKISH (TR) — Bank Fraud
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `TR - Ziraat Bankasi account blocked`() {
        val result = analyze("Ziraat Bankası: Hesabınız bloke edilmiştir. Güvenlik doğrulaması yapmanız gerekmektedir.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TR - Is Bankasi verification scam`() {
        val result = analyze("İş Bankası: Hesabınızda şüpheli işlem tespit edildi. Onaylama için tıklayın.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TR - Garanti BBVA security update`() {
        val result = analyze("Garanti BBVA: Güvenlik güncellemeniz gerekiyor. Hesabınız askıya alınabilir.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TR - Akbank card suspended`() {
        val result = analyze("Akbank: Kartınız askıya alındı. Doğrulama için bilgilerinizi güncelleyin.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TR - Papara account blocked`() {
        val result = analyze("Papara: Hesabınız şüpheli işlem nedeniyle bloke edildi. Doğrulama yapın.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TR - request PIN and SMS code`() {
        val result = analyze("Hesabınızı kurtarmak için gönderin bize şifre ve sms kodu hemen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TR - unauthorized transaction detected`() {
        val result = analyze("Hesabınızda yetkisiz işlem tespit edildi. 15.000 TL tutarında çekim yapılmış.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TR - card cloned stolen warning`() {
        val result = analyze("Kartınız klonlandı! Hemen kartınızı iptal ettirin ve yeni kart talep edin.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TR - savings at risk`() {
        val result = analyze("Birikimleriniz tehlikede! Paranızı güvenli hesaba aktarın hemen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TR - avoid blocking transfer now`() {
        val result = analyze("Hesabınızın bloke edilmesini önlemek için kimlik bilgilerinizi doğrulayın.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TR - Yapi Kredi fraud alert`() {
        val result = analyze("Yapı Kredi: Güvenlik doğrulama gerekiyor. Hesabınız askıya alınabilir.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TURKISH (TR) — Prize Scam
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `TR - lottery prize notification`() {
        val result = analyze("Tebrikler! Çekilişimizde 250.000 TL kazandınız! Ödülünüzü hemen alın.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `TR - you have been selected`() {
        val result = analyze("Seçildiniz! Şanslı kişi siz oldunuz. Hediyenizi talep edin.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `TR - free gift coupon`() {
        val result = analyze("Hediye çeki ücretsiz kazandınız. 1000 TL değerinde, hemen alın!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TURKISH (TR) — Phishing
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `TR - click link phishing`() {
        val result = analyze("Hesabınızı doğrulamak için aşağıdaki linke tıklayın.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `TR - verify account data`() {
        val result = analyze("Hesabınızı 24 saat içinde doğrulayın yoksa hesabınız kapatılacak.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `TR - PTT package delivery phishing`() {
        val result = analyze("PTT: Kargonuz teslim edilemedi. Ek ücret ödemeniz gerekmektedir.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `TR - Trendyol order problem`() {
        val result = analyze("Trendyol: Siparişinizle ilgili sorun var. Onaylayın ve teslimatı alın.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `TR - Yurtici Kargo delivery scam`() {
        val result = analyze("Yurtiçi Kargo: Paketiniz teslim edilemedi. Ödeme yaparak teslim alabilirsiniz.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `TR - account will be deleted`() {
        val result = analyze("Hesabınız silinecek güvenlik nedeniyle. Bilgilerinizi güncelleyin.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TURKISH (TR) — Money Request
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `TR - urgent money transfer`() {
        val result = analyze("Acil para lazım! Hemen hesaba havale yap, sonra anlatırım.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `TR - transfer to IBAN`() {
        val result = analyze("Havale yap bu IBAN numarasina lütfen. Çok acil bir durum.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `TR - I need money lend me`() {
        val result = analyze("Paraya ihtiyacım var, borç ver lütfen. Maaşımı alınca öderim.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `TR - send money immediately`() {
        val result = analyze("Derhal 5000 TL gönder hesabıma. Hayati önem taşıyor.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TURKISH (TR) — Impersonation
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `TR - mom impersonation new number`() {
        val result = analyze("Anne, benim, numaramı değiştirdim. Bu yeni numaramı kaydet.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `TR - I had an accident in hospital`() {
        val result = analyze("Kaza geçirdim, hastanedeyim. Acil yardım lazım, para gönder lütfen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `TR - its me your son`() {
        val result = analyze("Baba, benim, senin oğlun. Tanımadın mı? Başka telefondan yazıyorum.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `TR - grandchild impersonation`() {
        val result = analyze("Anneciğim, benim, yeni numaram bu. Eskisini kaybettim, kaydet lütfen.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TURKISH (TR) — Government Scam
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `TR - e-Devlet verification expired`() {
        val result = analyze("e-Devlet: Hesabınızın süresi doldu. Doğrulayın yoksa erişiminiz bloke edilecek.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `TR - SGK social security debt`() {
        val result = analyze("SGK: Prim borcunuz bulunmaktadır. Ödeme yapmazsanız ceza uygulanacaktır.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `TR - tax authority debt penalty`() {
        val result = analyze("Vergi dairesi: Vergi borcunuz var. Ödenmezse haciz islemi baslatilacak.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `TR - police prosecution summons`() {
        val result = analyze("Savcılık: Hakkınızda soruşturma başlatıldı. İfade vermeniz gerekmektedir.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `TR - threat of arrest`() {
        val result = analyze("Ceza ödenmezse tutuklanacaksınız. 48 saat içinde ödeme yapın.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `TR - digital signature expired`() {
        val result = analyze("E-imza süreniz doldu. Güncelleyin yoksa e-Devlet erişiminiz bloke edilecek.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TURKISH (TR) — False Positives
    // ═══════════════════════════════════════════════════════════════════════

    @Test
    fun `TR FP - normal greeting`() {
        val result = analyze("Merhaba, nasılsın? İyi misin?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `TR FP - Sunday family dinner`() {
        val result = analyze("Pazar günü annemlerde yemek var. Tatlı getir lütfen.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `TR FP - weather discussion`() {
        val result = analyze("Bugün hava çok güzel. Pikniğe gidelim mi?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `TR FP - grocery shopping`() {
        val result = analyze("Marketten ekmek, süt ve peynir aldım. Başka bir şey lazım mı?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `TR FP - doctor appointment`() {
        val result = analyze("Yarın saat 10'da doktor randevun var, unutma.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `TR FP - discussing a TV show`() {
        val result = analyze("Dün gece diziyi izledin mi? Çok güzeldi, sana da tavsiye ederim.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `TR FP - school pickup`() {
        val result = analyze("Bugün çocukları okuldan alamıyorum. Sen alabilir misin?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `TR FP - birthday party`() {
        val result = analyze("Babanın doğum günü cumartesi. Ben pastayı alırım, sen içecekleri getir.")
        assertFalse(result.isSuspicious)
    }
}
