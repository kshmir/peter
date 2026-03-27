package com.peter.app.core.util

import com.peter.app.core.util.ScamPatternDetector.ScamCategory
import com.peter.app.core.util.ScamPatternDetector.ThreatLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Asian-language scam pattern detection tests.
 *
 * Covers: Chinese (ZH), Japanese (JA), Korean (KO), Vietnamese (VI), Thai (TH),
 * Indonesian (ID) — including local payment systems, government scams, impersonation,
 * phishing, prize scams, money requests, and false-positive scenarios.
 */
class ScamPatternDetectorAsianTest {

    private fun analyze(text: String) = ScamPatternDetector.analyze(text)

    // =====================================================================
    // CHINESE (ZH)
    // =====================================================================

    // ── BANK_FRAUD ──

    @Test
    fun `ZH - Alipay account frozen`() {
        val result = analyze("支付宝安全中心提醒：您的支付宝账户存在异常登录，已被临时冻结。请立即验证身份，否则资金将被永久锁定。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ZH - WeChat Pay risk alert`() {
        val result = analyze("【微信支付】检测到您的微信支付账户存在安全风险，请立即点击以下链接进行安全验证，避免资金损失。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ZH - Bank account abnormal activity`() {
        val result = analyze("您的银行卡尾号8856发生异常交易，账户已被暂停使用。请立即拨打客服电话核实。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ZH - UnionPay security warning`() {
        val result = analyze("银联安全警告：您的银联卡涉嫌异常交易，请立即登录验证，否则将被冻结处理。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ZH - ICBC account verification`() {
        val result = analyze("工商银行通知：您的账户存在风险操作，已被临时冻结。请尽快完成身份验证。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ZH - Request for verification code`() {
        val result = analyze("为确保安全，请立即发送您的验证码和支付密码到以下号码进行身份核实。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ── PRIZE_SCAM ──

    @Test
    fun `ZH - Prize winner congratulations`() {
        val result = analyze("恭喜您！您已被随机抽中为本期幸运用户，获得大奖现金88888元，请立即领取！")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `ZH - Red envelope cash claim`() {
        val result = analyze("您有一笔未领取的现金红包，金额5000元。请点击链接兑换奖金，24小时内过期。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ── PHISHING ──

    @Test
    fun `ZH - Urgent click link`() {
        val result = analyze("重要通知：您的账户安全受到威胁，请立即点击以下链接进行安全升级。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `ZH - Account expiring verify`() {
        val result = analyze("您的账号即将过期失效，请尽快点击链接完成验证，否则账户将被注销。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ── MONEY_REQUEST ──

    @Test
    fun `ZH - Urgent money transfer`() {
        val result = analyze("我现在急需用钱，能不能马上给我转账5000块到这个账户？")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `ZH - Advance fee deposit`() {
        val result = analyze("恭喜中奖！领取前需先垫付手续费800元到指定账户，收到后立即发放奖金。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ── IMPERSONATION ──

    @Test
    fun `ZH - Family emergency hospital`() {
        val result = analyze("妈，我出车祸了，现在在医院，急需3万块钱交手术费，赶紧转账给我！")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `ZH - Changed phone number`() {
        val result = analyze("我换了手机号，这是新号码，赶紧存一下。旧号码不用了。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ── GOVERNMENT_SCAM ──

    @Test
    fun `ZH - Police suspect summons`() {
        val result = analyze("这里是公安局，您涉嫌一起洗钱案件，已被立案调查。请配合将资金转入安全账户。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `ZH - Tax arrears penalty`() {
        val result = analyze("税务局通知：您有一笔社保欠费未缴，逾期将影响您的信用记录。请立即处理。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `ZH - Safe account transfer`() {
        val result = analyze("请立即将全部存款存入安全账户，转入后我们将全程监管您的资金。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ── FALSE POSITIVES ──

    @Test
    fun `ZH FP - Normal greeting`() {
        val result = analyze("你好，最近怎么样？好久不见了！")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `ZH FP - Dinner invitation`() {
        val result = analyze("今晚一起吃饭吧，我请客。新开了一家火锅店。")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `ZH FP - Weather conversation`() {
        val result = analyze("今天天气真好，我们去公园散散步吧。")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `ZH FP - Discussing recipe`() {
        val result = analyze("红烧肉的做法：五花肉切块，加酱油、料酒、冰糖，小火慢炖一小时。")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `ZH FP - Doctor appointment`() {
        val result = analyze("明天下午三点记得去医院复查，别忘了带医保卡。")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `ZH FP - Normal Alipay usage`() {
        val result = analyze("我用支付宝转给你了，午饭的钱。")
        assertFalse(result.isSuspicious)
    }

    // =====================================================================
    // JAPANESE (JA)
    // =====================================================================

    // ── BANK_FRAUD ──

    @Test
    fun `JA - PayPay account frozen`() {
        val result = analyze("【重要】お客様のPayPayアカウントが不正アクセスにより利用停止されました。本人確認が必要です。以下のリンクから手続きしてください。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `JA - LINE Pay security alert`() {
        val result = analyze("LINE Payよりお知らせ：お客様のアカウントにセキュリティ上の異常が検出されました。至急ご確認ください。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `JA - Mizuho bank account restriction`() {
        val result = analyze("みずほ銀行：お客様の口座に不正アクセスの疑いがあり、一時的に凍結されました。本人確認をお願いいたします。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `JA - MUFG account alert`() {
        val result = analyze("三菱UFJ銀行よりお知らせ：お客様の口座で不正な取引が確認されました。至急ご対応ください。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `JA - Request for OTP`() {
        val result = analyze("セキュリティ確認のため、ワンタイムパスワードを入力してください。お客様の安全のために必要です。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `JA - Unauthorized transaction detected`() {
        val result = analyze("不正利用が検知されました。お客様のカードで身に覚えのない取引が発生しています。至急ご確認ください。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ── PRIZE_SCAM ──

    @Test
    fun `JA - Lottery jackpot winner`() {
        val result = analyze("おめでとうございます！抽選の結果、あなたが当選されました。賞金300万円をお受け取りください。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `JA - Prize gift claim`() {
        val result = analyze("特別キャンペーン当選のお知らせ：賞金100万円の受け取り手続きをしてください。期限は本日中です。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ── PHISHING ──

    @Test
    fun `JA - Urgent login required`() {
        val result = analyze("至急ログインして本人確認を完了してください。24時間以内に対応がない場合、アカウントは閉鎖されます。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `JA - Account expiration verify`() {
        val result = analyze("お客様のアカウントの有効期限が切れます。確認手続きをお願いいたします。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ── MONEY_REQUEST ──

    @Test
    fun `JA - Urgent money request`() {
        val result = analyze("急いでお金を送金してほしい。今すぐ振り込みをお願いします、大変なことになっています。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `JA - Advance fee payment`() {
        val result = analyze("当選金をお受け取りになるには、手数料を先に振込していただく必要があります。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ── IMPERSONATION ──

    @Test
    fun `JA - Ore ore family accident`() {
        val result = analyze("お母さん、大変なことになった。事故を起こしてしまって、示談金が必要なんだ。至急お金を振り込んで。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `JA - Changed phone number`() {
        val result = analyze("携帯の番号を変えました。新しい番号を登録してください。前の番号は使えません。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ── GOVERNMENT_SCAM ──

    @Test
    fun `JA - Tax office unpaid penalty`() {
        val result = analyze("国税局よりお知らせ：税金の未納が確認されました。至急お支払いがない場合、差し押さえの手続きに入ります。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `JA - Police arrest warrant`() {
        val result = analyze("警察からの通知です。あなたに対して逮捕令状が出ています。至急出頭してください。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `JA - ATM refund scam`() {
        val result = analyze("年金機構からのお知らせ：還付金のお受け取り手続きが必要です。お近くのATMで手続きしてください。")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ── FALSE POSITIVES ──

    @Test
    fun `JA FP - Normal greeting`() {
        val result = analyze("こんにちは、お元気ですか？今度一緒にご飯でも行きましょう。")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `JA FP - Weekend plans`() {
        val result = analyze("週末は何をする予定ですか？天気が良ければ花見に行きたいです。")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `JA FP - Normal PayPay usage`() {
        val result = analyze("ランチ代、PayPayで送ったよ。確認してね。")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `JA FP - Recipe sharing`() {
        val result = analyze("お好み焼きの作り方：小麦粉、卵、キャベツを混ぜて、鉄板で焼いてください。")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `JA FP - Doctor appointment reminder`() {
        val result = analyze("明日の午後2時に病院の予約があるから忘れないでね。")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `JA FP - Grandchild school event`() {
        val result = analyze("来週の土曜日、孫の運動会があります。一緒に応援に行きましょう。")
        assertFalse(result.isSuspicious)
    }

    // =====================================================================
    // KOREAN (KO)
    // =====================================================================

    // ── BANK_FRAUD ──

    @Test
    fun `KO - KakaoPay account frozen`() {
        val result = analyze("카카오페이 긴급알림: 고객님의 계정에서 이상 거래가 감지되어 보안 인증이 필요합니다. 지금 바로 확인해주세요.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `KO - Toss account suspended`() {
        val result = analyze("토스 안내: 고객님의 계좌가 보안상의 이유로 동결되었습니다. 본인 인증 후 정상 이용 가능합니다.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `KO - Kookmin Bank account alert`() {
        val result = analyze("국민은행: 귀하의 계좌에서 이상 거래가 확인되었습니다. 즉시 본인 확인이 필요합니다.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `KO - Shinhan Bank restriction`() {
        val result = analyze("신한은행 알림: 고객님의 계좌가 부정 사용 감지로 제한되었습니다. 본인 확인을 완료해주세요.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `KO - Request for OTP security card`() {
        val result = analyze("보안 확인을 위해 비밀번호와 보안카드 번호를 입력해주세요. 미확인 시 계좌가 정지됩니다.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `KO - Suspicious transaction detected`() {
        val result = analyze("의심 거래가 감지되었습니다. 본인이 아닌 경우 즉시 고객센터에 연락해주세요.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ── PRIZE_SCAM ──

    @Test
    fun `KO - Lottery winner`() {
        val result = analyze("축하합니다! 고객님은 이번 추첨에서 당첨되셨습니다. 상금 500만원을 수령하시기 바랍니다.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `KO - Gift points claim`() {
        val result = analyze("고객님께 경품 상품이 지급되었습니다. 아래 링크에서 수령하세요. 유효기간: 오늘까지.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ── PHISHING ──

    @Test
    fun `KO - Urgent login required`() {
        val result = analyze("긴급: 귀하의 계정이 해킹 시도를 받았습니다. 지금 바로 로그인하여 비밀번호를 변경하세요.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `KO - Account expiration verify`() {
        val result = analyze("고객님의 계정이 만료 예정입니다. 확인 절차를 완료하지 않으면 계정이 폐쇄됩니다.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ── MONEY_REQUEST ──

    @Test
    fun `KO - Urgent money transfer`() {
        val result = analyze("급히 돈이 필요해. 지금 당장 100만원만 송금해줄 수 있어? 나중에 갚을게.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `KO - Advance fee deposit`() {
        val result = analyze("당첨금 수령을 위해 수수료 5만원을 먼저 입금해주셔야 합니다.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ── IMPERSONATION ──

    @Test
    fun `KO - Family emergency hospitalized`() {
        val result = analyze("엄마, 나 사고 났어. 지금 입원해 있는데 급히 돈이 필요해. 200만원만 보내줘.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `KO - Changed phone number`() {
        val result = analyze("엄마 나야, 전화번호 바꿨어. 새 번호 저장해줘. 옛날 번호는 안 돼.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ── GOVERNMENT_SCAM ──

    @Test
    fun `KO - Tax office unpaid penalty`() {
        val result = analyze("국세청 안내: 세금 미납이 확인되었습니다. 48시간 이내에 납부하지 않으면 재산 압류 절차가 진행됩니다.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `KO - Prosecution arrest warrant`() {
        val result = analyze("검찰청입니다. 귀하는 사기 사건의 피의자로 수사 중입니다. 즉시 출두하시기 바랍니다.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `KO - Safe account transfer`() {
        val result = analyze("자금 보호를 위해 안전 계좌로 이체해 주세요. 이것은 검찰의 공식 조치입니다.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ── FALSE POSITIVES ──

    @Test
    fun `KO FP - Normal greeting`() {
        val result = analyze("안녕하세요, 잘 지내셨어요? 이번 주말에 만날 수 있어요?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `KO FP - Lunch plans`() {
        val result = analyze("점심 뭐 먹을까? 김치찌개 어때? 맛있는 집 알아.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `KO FP - Normal KakaoPay usage`() {
        val result = analyze("카카오페이로 밥값 보냈어. 확인해봐.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `KO FP - Family dinner plan`() {
        val result = analyze("이번 추석에 할머니 댁에 모여서 같이 식사해요. 삼촌네도 온대.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `KO FP - Hospital checkup reminder`() {
        val result = analyze("내일 오후 3시에 건강검진 예약 있으니까 잊지 마세요.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `KO FP - Weather talk`() {
        val result = analyze("오늘 날씨 정말 좋다. 한강 공원에 산책 갈래?")
        assertFalse(result.isSuspicious)
    }

    // =====================================================================
    // VIETNAMESE (VI)
    // =====================================================================

    // ── BANK_FRAUD ──

    @Test
    fun `VI - MoMo wallet locked`() {
        val result = analyze("Tài khoản MoMo của bạn đã bị khóa do phát hiện giao dịch bất thường. Vui lòng xác minh ngay để tránh mất tiền.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `VI - ZaloPay restricted`() {
        val result = analyze("Tai khoan ZaloPay bi khoa do hoat dong bat thuong. Xac minh ngay.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `VI - Vietcombank frozen`() {
        val result = analyze("Vietcombank: Tài khoản của quý khách bị tạm ngưng do nghi ngờ giao dịch bất thường. Vui lòng xác minh danh tính.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `VI - VietinBank suspicious activity`() {
        val result = analyze("VietinBank: Phát hiện giao dịch bất thường trên tài khoản của bạn. Vui lòng liên hệ ngay.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `VI - Request for OTP and password`() {
        val result = analyze("Để bảo vệ tài khoản, vui lòng cung cấp mã OTP và mật khẩu của bạn cho nhân viên hỗ trợ.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `VI - Suspicious unauthorized transaction`() {
        val result = analyze("Cảnh báo: Giao dịch bất thường 15.000.000 VND từ tài khoản của bạn. Nếu không phải bạn, hãy liên hệ ngay.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ── PRIZE_SCAM ──

    @Test
    fun `VI - Congratulations prize winner`() {
        val result = analyze("Xin chúc mừng! Bạn đã trúng giải thưởng đặc biệt trị giá 50.000.000 VND. Nhận thưởng ngay!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `VI - Lucky draw claim reward`() {
        val result = analyze("Bạn đã được chọn trong chương trình rút thăm may mắn. Nhận phần thưởng 10 triệu đồng ngay hôm nay.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ── PHISHING ──

    @Test
    fun `VI - Urgent login click`() {
        val result = analyze("Khẩn cấp: Tài khoản của bạn sắp bị khóa. Đăng nhập ngay lập tức để xác minh thông tin.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `VI - Verify update account info`() {
        val result = analyze("Vui lòng xác minh thông tin tài khoản của bạn để tránh bị đóng. Cập nhật dữ liệu ngay.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ── MONEY_REQUEST ──

    @Test
    fun `VI - Urgent money needed`() {
        val result = analyze("Em cần gấp 5 triệu. Anh chuyển tiền cho em ngay được không? Em sẽ trả lại tuần sau.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `VI - Advance deposit fee`() {
        val result = analyze("Để nhận giải, bạn cần thanh toán lệ phí xử lý trước. Chuyển 500.000 VND vào tài khoản sau.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ── IMPERSONATION ──

    @Test
    fun `VI - Family accident hospital`() {
        val result = analyze("Mẹ ơi, con bị tai nạn, đang nhập viện. Con cần gấp 20 triệu để đóng viện phí. Chuyển ngay cho con mẹ nhé.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `VI - Changed phone number`() {
        val result = analyze("Mẹ ơi, số điện thoại con đổi rồi. Lưu lại số mới này nhé, số cũ hết dùng rồi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ── GOVERNMENT_SCAM ──

    @Test
    fun `VI - Police summons threat`() {
        val result = analyze("Công an thông báo: Bạn bị nghi phạm trong vụ án lừa đảo. Có lệnh triệu tập. Liên hệ ngay để giải quyết.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `VI - Tax office unpaid penalty`() {
        val result = analyze("Cơ quan thuế thông báo: Bạn có khoản nợ thuế chưa nộp. Nếu không xử lý trong 24 giờ, sẽ bị phạt nặng.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `VI - Safe protection account`() {
        val result = analyze("Để bảo vệ tài sản, hãy nộp tiền vào tài khoản an toàn. Chuyển ngay kẻo cơ quan điều tra đóng tài khoản.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ── FALSE POSITIVES ──

    @Test
    fun `VI FP - Normal greeting`() {
        val result = analyze("Xin chào, dạo này bạn khỏe không? Lâu rồi mình không gặp nhau.")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `VI FP - Family dinner`() {
        val result = analyze("Cuối tuần này về nhà ăn cơm với gia đình nhé. Mẹ nấu phở.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `VI FP - Normal MoMo transfer`() {
        val result = analyze("Mình chuyển tiền ăn trưa qua MoMo rồi nhé. Kiểm tra giúp mình.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `VI FP - Weather conversation`() {
        val result = analyze("Hôm nay trời đẹp quá. Đi cà phê không?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `VI FP - Hospital visit plan`() {
        val result = analyze("Chiều mai mình đi thăm bà ngoại ở bệnh viện nhé. Mua ít trái cây mang theo.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `VI FP - Recipe sharing`() {
        val result = analyze("Bánh mì thịt nướng: ướp thịt với sả, tỏi, nước mắm rồi nướng trên than hoa.")
        assertFalse(result.isSuspicious)
    }

    // =====================================================================
    // THAI (TH)
    // =====================================================================

    // ── BANK_FRAUD ──

    @Test
    fun `TH - PromptPay suspended`() {
        val result = analyze("แจ้งเตือน: บัญชี PromptPay ของท่านถูกระงับเนื่องจากตรวจพบกิจกรรมผิดปกติ กรุณายืนยันตัวตนทันที")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TH - TrueMoney wallet locked`() {
        val result = analyze("TrueMoney แจ้งเตือน: บัญชีของคุณถูกล็อคเนื่องจากผิดปกติ กรุณายืนยันตัวตนเพื่อปลดล็อค")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TH - KBank K PLUS alert`() {
        val result = analyze("KBank แจ้งเตือน: พบการใช้งาน K PLUS ผิดปกติ บัญชีถูกระงับชั่วคราว กรุณายืนยันตัวตน")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TH - SCB account frozen`() {
        val result = analyze("ไทยพาณิชย์: บัญชีของท่านถูกระงับเนื่องจากธุรกรรมน่าสงสัย กรุณาติดต่อทันที")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TH - Request for OTP PIN`() {
        val result = analyze("เพื่อความปลอดภัย กรุณากรอกรหัส OTP และรหัส PIN ที่ได้รับทาง SMS เพื่อยืนยันตัวตน")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `TH - Suspicious transaction detected`() {
        val result = analyze("ตรวจพบธุรกรรมผิดปกติจำนวน 50,000 บาท จากบัญชีของคุณ หากไม่ใช่คุณ โปรดแจ้งทันที")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ── PRIZE_SCAM ──

    @Test
    fun `TH - Lottery jackpot winner`() {
        val result = analyze("ยินดีด้วย! คุณถูกรางวัลสลากกินแบ่งรัฐบาล รางวัลที่ 1 จำนวน 6,000,000 บาท ติดต่อรับรางวัลทันที")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `TH - Prize cash claim`() {
        val result = analyze("คุณได้รับคัดเลือกให้รับเงินรางวัลพิเศษ 100,000 บาท กรุณาแลกรับของรางวัลภายในวันนี้")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ── PHISHING ──

    @Test
    fun `TH - Urgent click verify`() {
        val result = analyze("ด่วน! กรุณาคลิกลิงก์เพื่อยืนยันตัวตน บัญชีของคุณจะถูกปิดภายใน 24 ชั่วโมง")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `TH - Account expiring update`() {
        val result = analyze("บัญชีของคุณหมดอายุแล้ว กรุณาอัพเดทข้อมูลเพื่อยืนยันตัวตน มิฉะนั้นจะถูกปิดถาวร")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ── MONEY_REQUEST ──

    @Test
    fun `TH - Urgent money request`() {
        val result = analyze("ต้องการด่วนมาก ช่วยโอนเงิน 30,000 บาท ให้หน่อย เดี๋ยวคืนให้พรุ่งนี้")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `TH - Advance fee payment`() {
        val result = analyze("เพื่อรับรางวัล กรุณาจ่ายค่าธรรมเนียมก่อน 5,000 บาท โอนเข้าบัญชีนี้")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ── IMPERSONATION ──

    @Test
    fun `TH - Family emergency accident`() {
        val result = analyze("แม่คะ ลูกถูกรถชน เข้าโรงพยาบาลอยู่ ต้องการเงินด่วน 50,000 บาท โอนมาเดี๋ยวนี้")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `TH - Changed phone number`() {
        val result = analyze("แม่คะ หนูเปลี่ยนเบอร์ใหม่แล้วนะ บันทึกเบอร์นี้ไว้ด้วย เบอร์เดิมใช้ไม่ได้แล้ว")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ── GOVERNMENT_SCAM ──

    @Test
    fun `TH - Revenue department tax penalty`() {
        val result = analyze("กรมสรรพากร: ท่านมีภาษีค้างชำระ หากไม่ชำระภายใน 48 ชั่วโมง จะถูกดำเนินคดี")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `TH - Police arrest warrant`() {
        val result = analyze("ตำรวจแจ้งความ: มีหมายจับในชื่อของท่าน เกี่ยวกับคดีฟอกเงิน กรุณาติดต่อสอบสวนทันที")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `TH - Safe account transfer`() {
        val result = analyze("เพื่อปกป้องทรัพย์สิน ใช้บัญชีปลอดภัยนี้โอนเงินทั้งหมดของท่านทันที")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ── FALSE POSITIVES ──

    @Test
    fun `TH FP - Normal greeting`() {
        val result = analyze("สวัสดีครับ สบายดีไหม? นานแล้วไม่ได้เจอกัน")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `TH FP - Dinner invitation`() {
        val result = analyze("เย็นนี้ไปกินข้าวกันมั้ย มีร้านส้มตำเปิดใหม่ อร่อยมาก")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `TH FP - Normal PromptPay transfer`() {
        val result = analyze("โอนค่าข้าวเที่ยงให้แล้วนะ PromptPay เช็คด้วย")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `TH FP - Temple visit plan`() {
        val result = analyze("วันอาทิตย์นี้ไปทำบุญที่วัดกันนะ ตื่นเช้าหน่อย")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `TH FP - Hospital checkup`() {
        val result = analyze("พรุ่งนี้บ่ายสองมีนัดหมอที่โรงพยาบาล อย่าลืมนะ")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `TH FP - Recipe sharing`() {
        val result = analyze("วิธีทำต้มยำกุ้ง: ต้มน้ำใส่ข่า ตะไคร้ ใบมะกรูด พริก น้ำปลา มะนาว")
        assertFalse(result.isSuspicious)
    }

    // =====================================================================
    // INDONESIAN (ID)
    // =====================================================================

    // ── BANK_FRAUD ──

    @Test
    fun `ID - GoPay account blocked`() {
        val result = analyze("GoPay: Akun Anda telah diblokir karena aktivitas mencurigakan. Segera verifikasi identitas Anda untuk membuka blokir.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ID - OVO wallet frozen`() {
        val result = analyze("OVO: Akun Anda dibekukan karena terdeteksi transaksi tidak wajar. Verifikasi sekarang untuk mengaktifkan kembali.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ID - DANA wallet suspended`() {
        val result = analyze("DANA: Akun Anda telah ditangguhkan sementara karena aktivitas tidak normal. Segera lakukan verifikasi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ID - BCA account alert`() {
        val result = analyze("BCA: Rekening Anda dibekukan karena terdeteksi transaksi mencurigakan. Segera hubungi kami untuk verifikasi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ID - Mandiri suspicious activity`() {
        val result = analyze("Bank Mandiri: Aktivitas mencurigakan terdeteksi pada rekening Anda. Segera verifikasi untuk menghindari pemblokiran.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ID - Request for OTP and password`() {
        val result = analyze("Demi keamanan akun Anda, segera masukkan kode OTP dan kata sandi yang dikirim melalui SMS.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    @Test
    fun `ID - Suspicious unauthorized transaction`() {
        val result = analyze("Peringatan: Transaksi mencurigakan sebesar Rp 10.000.000 terdeteksi dari rekening Anda. Segera konfirmasi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.BANK_FRAUD })
    }

    // ── PRIZE_SCAM ──

    @Test
    fun `ID - Lucky draw winner`() {
        val result = analyze("Selamat! Anda terpilih sebagai pemenang undian berhadiah Rp 500.000.000. Klaim hadiah Anda sekarang!")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    @Test
    fun `ID - Prize voucher claim`() {
        val result = analyze("Anda memenangkan voucher belanja senilai Rp 5.000.000. Klaim hadiah uang tunai Anda sebelum kedaluwarsa.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PRIZE_SCAM })
    }

    // ── PHISHING ──

    @Test
    fun `ID - Urgent login access`() {
        val result = analyze("Darurat: Akun Anda akan ditutup dalam 24 jam. Segera login untuk memperbarui data Anda.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    @Test
    fun `ID - Account expiring verify`() {
        val result = analyze("Akun Anda akan kadaluarsa. Segera verifikasi data Anda melalui link berikut untuk menghindari penutupan.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.PHISHING })
    }

    // ── MONEY_REQUEST ──

    @Test
    fun `ID - Urgent money transfer`() {
        val result = analyze("Butuh segera uang 5 juta. Tolong transfer ke rekening ini sekarang. Nanti aku ganti.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    @Test
    fun `ID - Advance admin fee`() {
        val result = analyze("Untuk menerima hadiah, Anda perlu membayar biaya admin terlebih dahulu sebesar Rp 500.000.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.MONEY_REQUEST })
    }

    // ── IMPERSONATION ──

    @Test
    fun `ID - Family accident hospital`() {
        val result = analyze("Mama, aku kecelakaan. Sekarang masuk rumah sakit. Butuh uang segera 20 juta untuk biaya operasi.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    @Test
    fun `ID - Changed phone number save`() {
        val result = analyze("Ma, ini aku. Nomor HP ganti baru, simpan ya. Yang lama sudah tidak aktif.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.IMPERSONATION })
    }

    // ── GOVERNMENT_SCAM ──

    @Test
    fun `ID - Tax office penalty`() {
        val result = analyze("Dirjen Pajak: Anda memiliki tunggakan pajak yang belum dibayar. Segera lunasi dalam 48 jam untuk menghindari denda.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `ID - Police arrest warrant`() {
        val result = analyze("Polisi: Anda menjadi tersangka dalam kasus penipuan. Ada surat perintah penangkapan. Segera hubungi kami.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    @Test
    fun `ID - Safe account transfer`() {
        val result = analyze("Untuk melindungi dana Anda, gunakan rekening aman ini. Transfer seluruh saldo sekarang.")
        assertTrue(result.isSuspicious)
        assertTrue(result.matchedPatterns.any { it.category == ScamCategory.GOVERNMENT_SCAM })
    }

    // ── FALSE POSITIVES ──

    @Test
    fun `ID FP - Normal greeting`() {
        val result = analyze("Halo, apa kabar? Sudah lama tidak ketemu. Kapan bisa kumpul lagi?")
        assertFalse(result.isSuspicious)
        assertEquals(ThreatLevel.NONE, result.threatLevel)
    }

    @Test
    fun `ID FP - Lunch plans`() {
        val result = analyze("Makan siang dimana? Mau pesan nasi goreng atau bakso?")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `ID FP - Normal GoPay usage`() {
        val result = analyze("Sudah aku transfer lewat GoPay untuk makan siang tadi ya. Cek dulu.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `ID FP - Family gathering plan`() {
        val result = analyze("Hari Minggu kumpul di rumah nenek ya. Bawa kue dan minuman.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `ID FP - Hospital checkup`() {
        val result = analyze("Besok jam 10 ada jadwal kontrol di rumah sakit. Jangan lupa bawa kartu BPJS.")
        assertFalse(result.isSuspicious)
    }

    @Test
    fun `ID FP - Recipe sharing`() {
        val result = analyze("Resep rendang: daging sapi, santan, bumbu halus, serai, daun jeruk. Masak sampai kering.")
        assertFalse(result.isSuspicious)
    }
}
