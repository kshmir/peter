package com.peter.app.core.util

/**
 * Scam detection patterns for Asian languages:
 * Chinese (ZH), Japanese (JA), Korean (KO), Vietnamese (VI), Thai (TH), Indonesian (ID)
 *
 * CJK / Thai notes:
 *   - Chinese, Japanese, and Thai do not use spaces between words — patterns match
 *     character sequences directly (no \b word boundaries for native script).
 *   - Korean uses spaces but particles attach to words — patterns account for this.
 *   - Vietnamese uses Latin script with diacritics — word boundaries work normally.
 *   - Indonesian uses Latin script — word boundaries work normally.
 */
internal object ScamPatternsAsian {

    fun allRules(): List<ScamPatternDetector.PatternRule> = buildList {
        addAll(chineseRules())
        addAll(japaneseRules())
        addAll(koreanRules())
        addAll(vietnameseRules())
        addAll(thaiRules())
        addAll(indonesianRules())
    }

    // ──────────────────────────────────────────────────────────────────
    // CHINESE (ZH)
    // ──────────────────────────────────────────────────────────────────

    private fun chineseRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("(您的|你的)(账户|账号|银行卡).{0,15}(冻结|异常|风险|暂停|锁定|盗用)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ZH", "ALL", 0.4f,
            "ZH: Your account/card frozen/abnormal/locked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("支付宝.{0,20}(冻结|异常|风险|暂停|安全验证|限制)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ZH", "ALL", 0.4f,
            "ZH: Alipay account frozen/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("微信支付.{0,20}(冻结|异常|风险|暂停|限制|安全)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ZH", "ALL", 0.4f,
            "ZH: WeChat Pay frozen/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("银联.{0,15}(异常|风险|冻结|交易失败|安全警告)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ZH", "ALL", 0.35f,
            "ZH: UnionPay abnormal/risk alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(工商银行|建设银行|招商银行|中国银行|农业银行).{0,20}(冻结|异常|风险|暂停|验证)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ZH", "ALL", 0.4f,
            "ZH: Major Chinese bank account alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(输入|提供|发送).{0,10}(密码|验证码|支付密码|银行卡号|身份证号)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ZH", "ALL", 0.45f,
            "ZH: Request for password/verification code/ID number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(可疑|异常)(交易|转账|消费).{0,15}(确认|验证|核实)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ZH", "ALL", 0.35f,
            "ZH: Suspicious transaction needs verification",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("恭喜.{0,20}(中奖|获奖|被选中|获得大奖|幸运用户)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "ZH", "ALL", 0.4f,
            "ZH: Congratulations you won a prize",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(领取|兑换).{0,15}(奖金|奖品|红包|现金|大奖)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "ZH", "ALL", 0.35f,
            "ZH: Claim your prize/cash/red envelope",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(幸运|随机).{0,10}(抽中|选中|抽奖).{0,15}(万元|现金|大奖)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "ZH", "ALL", 0.35f,
            "ZH: Lucky draw won cash prize",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("(立即|马上|尽快|赶紧)(点击|打开|访问).{0,20}(链接|网址|网站)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "ZH", "ALL", 0.4f,
            "ZH: Urgently click/open this link",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(验证|更新|确认|完善).{0,10}(您的|你的).{0,10}(信息|资料|身份|账户)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "ZH", "ALL", 0.35f,
            "ZH: Verify/update your information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(账号|账户).{0,10}(过期|到期|失效|注销).{0,15}(点击|登录|验证)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "ZH", "ALL", 0.4f,
            "ZH: Account expiring, click to verify",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("安全(升级|更新|验证).{0,15}(点击|立即|马上|否则)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "ZH", "ALL", 0.35f,
            "ZH: Security upgrade required urgently",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("(急需|急用|马上需要).{0,15}(钱|转账|打款|汇款)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "ZH", "ALL", 0.35f,
            "ZH: Urgently need money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(转|汇|打).{0,5}(钱|款).{0,10}(到|给|至).{0,15}(账户|账号|卡号)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "ZH", "ALL", 0.35f,
            "ZH: Transfer money to this account",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(先|提前)(垫付|支付|转账).{0,15}(手续费|保证金|押金|税费)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "ZH", "ALL", 0.4f,
            "ZH: Pay advance fee/deposit/tax first",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("我(换|改)(了|过)(号码|手机号|电话号).{0,15}(存|记|保存)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "ZH", "ALL", 0.35f,
            "ZH: I changed my number, save it",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(我是|这是).{0,10}(你的|您的).{0,10}(儿子|女儿|孙子|孙女|亲人|家人)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "ZH", "ALL", 0.3f,
            "ZH: I am your son/daughter/grandchild",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(出事了|出了事|住院了|出车祸).{0,20}(急需|赶紧|马上|需要)(钱|帮忙|转账)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "ZH", "ALL", 0.4f,
            "ZH: Emergency accident/hospital, need money now",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(公安局|派出所|检察院|法院).{0,20}(涉嫌|嫌疑|立案|传唤|逮捕)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "ZH", "ALL", 0.4f,
            "ZH: Police/court says you are a suspect",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(税务|社保|医保).{0,15}(欠费|异常|违规|未缴|到期)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "ZH", "ALL", 0.35f,
            "ZH: Tax/social security/medical insurance arrears",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(安全账户|监管账户).{0,15}(转入|存入|汇入|打到)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "ZH", "ALL", 0.45f,
            "ZH: Transfer to safe/supervision account",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(投资|理财).{0,15}(保证|稳赚|零风险|高回报|日赚|月入)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "ZH", "ALL", 0.4f,
            "ZH: Investment guaranteed/zero risk/high returns",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(比特币|以太坊|虚拟货币|数字货币|加密货币).{0,20}(翻倍|暴涨|机会|内部)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "ZH", "ALL", 0.4f,
            "ZH: Crypto doubling/insider opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(日收益|月收益|年化).{0,10}(百分之|%).{0,5}[3-9]\\d", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "ZH", "ALL", 0.35f,
            "ZH: Unrealistic daily/monthly/annual returns",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("(您的|你的)(手机|电脑|设备).{0,15}(病毒|中毒|被黑|被入侵|安全风险)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "ZH", "ALL", 0.35f,
            "ZH: Your device has virus/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(客服|技术支持|官方).{0,15}(远程|协助|安装|下载).{0,10}(软件|APP|应用)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "ZH", "ALL", 0.35f,
            "ZH: Customer service remote install software",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(缘分|命中注定|一见钟情).{0,20}(认识你|遇到你|找到你)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "ZH", "ALL", 0.25f,
            "ZH: Fate/destiny brought us together",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(想你|爱你|好想你).{0,20}(寄|送|汇|转).{0,10}(礼物|钱|包裹|黄金)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "ZH", "ALL", 0.3f,
            "ZH: Miss/love you, sending gift/money/gold",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // JAPANESE (JA)
    // ──────────────────────────────────────────────────────────────────

    private fun japaneseRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("(お客様の|あなたの)(口座|アカウント|カード).{0,20}(凍結|停止|不正|制限|ロック)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "JA", "ALL", 0.4f,
            "JA: Your account/card frozen/locked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("PayPay.{0,20}(凍結|停止|不正|制限|利用.{0,5}停止|セキュリティ)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "JA", "ALL", 0.4f,
            "JA: PayPay account frozen/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("LINE\\s*Pay.{0,20}(凍結|停止|不正|制限|セキュリティ|異常)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "JA", "ALL", 0.4f,
            "JA: LINE Pay frozen/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(三菱UFJ|みずほ|三井住友|ゆうちょ|りそな).{0,20}(凍結|停止|不正|制限|確認)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "JA", "ALL", 0.4f,
            "JA: Major Japanese bank alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(暗証番号|パスワード|ワンタイムパスワード|認証コード).{0,15}(入力|送信|教えて|確認)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "JA", "ALL", 0.45f,
            "JA: Request for PIN/password/OTP",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("不正(利用|アクセス|取引|送金).{0,15}(検知|確認|発生)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "JA", "ALL", 0.4f,
            "JA: Unauthorized access/transaction detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(お振込|振込).{0,15}(取消|キャンセル|返金).{0,10}(手続|手数料|確認)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "JA", "ALL", 0.35f,
            "JA: Transfer cancellation/refund procedure",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("おめでとう.{0,20}(当選|当たり|受賞|選ばれ|獲得)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "JA", "ALL", 0.4f,
            "JA: Congratulations, you won",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(賞金|懸賞|景品|ギフト|プレゼント).{0,15}(受け取|獲得|当選|受領)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "JA", "ALL", 0.35f,
            "JA: Claim your prize/gift",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(抽選|くじ|宝くじ).{0,15}(当選|当たり|当せん).{0,15}(万円|百万|千万)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "JA", "ALL", 0.4f,
            "JA: Lottery/draw won millions of yen",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("(至急|早急|直ちに|今すぐ)(クリック|タップ|アクセス|確認|ログイン)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "JA", "ALL", 0.4f,
            "JA: Urgently click/access/log in",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(本人確認|身元確認|情報更新).{0,15}(お願い|ください|必要|手続)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "JA", "ALL", 0.35f,
            "JA: Identity/information verification required",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(アカウント|口座).{0,10}(有効期限|期限切れ|失効|閉鎖).{0,10}(確認|更新|手続)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "JA", "ALL", 0.4f,
            "JA: Account expiring, verify now",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("セキュリティ(強化|更新|確認|対策).{0,15}(こちら|以下|リンク|URL)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "JA", "ALL", 0.35f,
            "JA: Security update, click link",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("(急ぎ|急いで|至急).{0,15}(お金|送金|振込|振り込)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "JA", "ALL", 0.35f,
            "JA: Urgently need money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(振込|送金|入金).{0,10}(お願い|してください|頼む|ください)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "JA", "ALL", 0.3f,
            "JA: Please make a transfer/deposit",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(手数料|保証金|頭金|前払).{0,15}(先に|まず|事前に).{0,10}(振込|支払|送金)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "JA", "ALL", 0.4f,
            "JA: Pay fee/deposit in advance",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("(番号|電話番号|携帯).{0,10}(変え|変わ|替え).{0,10}(ました|たの|たよ|登録して)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "JA", "ALL", 0.35f,
            "JA: I changed my phone number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(お母さん|お父さん|おじいちゃん|おばあちゃん).{0,15}(助けて|お金|大変|事故|入院)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "JA", "ALL", 0.4f,
            "JA: Family member emergency/accident/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(事故|入院|トラブル|逮捕).{0,20}(示談|お金|至急|助けて|払わないと)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "JA", "ALL", 0.4f,
            "JA: Accident/arrest, need settlement money",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(税務署|国税局|市役所|年金機構).{0,20}(未納|滞納|還付|差し押さえ|罰金)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "JA", "ALL", 0.4f,
            "JA: Tax office/city hall unpaid/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(警察|検察|裁判所).{0,20}(逮捕|出頭|令状|捜査|容疑)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "JA", "ALL", 0.4f,
            "JA: Police/prosecutor arrest/warrant threat",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(還付金|給付金|補助金).{0,15}(手続|受け取|申請|ATM)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "JA", "ALL", 0.4f,
            "JA: Refund/subsidy claim via ATM",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(投資|資産運用).{0,15}(保証|確実|ノーリスク|高利回り|元本保証)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "JA", "ALL", 0.4f,
            "JA: Investment guaranteed/no risk/high return",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ビットコイン|仮想通貨|暗号資産|イーサリアム).{0,20}(倍|急騰|チャンス|限定|内部情報)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "JA", "ALL", 0.4f,
            "JA: Crypto opportunity/insider info",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(月利|日利|年利).{0,10}[1-9]\\d.{0,3}(パーセント|%|％)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "JA", "ALL", 0.35f,
            "JA: Unrealistic monthly/daily interest rate",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("(お使いの|あなたの)(端末|スマホ|パソコン|PC).{0,15}(ウイルス|感染|不正アクセス|危険|ハッキング)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "JA", "ALL", 0.35f,
            "JA: Your device has virus/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(サポート|カスタマー|公式).{0,15}(遠隔|リモート).{0,10}(操作|インストール|アプリ)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "JA", "ALL", 0.35f,
            "JA: Support remote access/install app",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(運命|出会い|一目惚れ).{0,20}(あなた|素敵|特別)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "JA", "ALL", 0.25f,
            "JA: Fate/love at first sight, you are special",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(会いたい|愛してる|好きです).{0,20}(送金|プレゼント|贈り物|お金|ギフト)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "JA", "ALL", 0.3f,
            "JA: Miss/love you, sending gift/money",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // KOREAN (KO)
    // ──────────────────────────────────────────────────────────────────

    private fun koreanRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("(귀하의|고객님의|본인의)\\s*(계좌|카드|통장).{0,20}(동결|정지|제한|이상|도용)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "KO", "ALL", 0.4f,
            "KO: Your account/card frozen/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("카카오페이.{0,20}(동결|정지|제한|이상|보안|인증)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "KO", "ALL", 0.4f,
            "KO: KakaoPay frozen/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("토스.{0,20}(동결|정지|제한|이상|보안|인증|차단)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "KO", "ALL", 0.4f,
            "KO: Toss frozen/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(국민은행|신한은행|하나은행|우리은행|삼성페이|농협).{0,20}(동결|정지|제한|이상|확인)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "KO", "ALL", 0.4f,
            "KO: Major Korean bank/Samsung Pay alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(비밀번호|인증번호|보안카드|OTP).{0,15}(입력|전송|알려|보내)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "KO", "ALL", 0.45f,
            "KO: Request for password/OTP/security card",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(의심|이상)\\s*(거래|출금|이체|결제).{0,15}(감지|발생|확인)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "KO", "ALL", 0.4f,
            "KO: Suspicious transaction detected",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(부정|불법)\\s*(사용|접속|결제|출금).{0,15}(확인|감지|발생)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "KO", "ALL", 0.4f,
            "KO: Unauthorized use/access detected",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("축하.{0,20}(당첨|선정|수상|추첨|경품)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "KO", "ALL", 0.4f,
            "KO: Congratulations, you won",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(상금|경품|상품|선물|포인트).{0,15}(수령|받으|지급|당첨)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "KO", "ALL", 0.35f,
            "KO: Claim your prize/gift/points",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(복권|로또|추첨).{0,15}(당첨|1등|대박).{0,15}(만원|억원|백만)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "KO", "ALL", 0.4f,
            "KO: Lottery/lotto jackpot winner",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("(즉시|긴급|지금\\s*바로|빨리).{0,15}(클릭|접속|확인|로그인)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "KO", "ALL", 0.4f,
            "KO: Urgently click/access/login",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(본인\\s*확인|신원\\s*확인|정보\\s*갱신|정보\\s*업데이트).{0,15}(필요|바랍니다|해주세요)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "KO", "ALL", 0.35f,
            "KO: Identity/information verification required",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(계정|계좌).{0,10}(만료|폐쇄|정지|비활성).{0,15}(확인|갱신|인증)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "KO", "ALL", 0.4f,
            "KO: Account expiring/closing, verify now",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("(급히|급하게|빨리).{0,15}(돈|송금|이체|입금)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "KO", "ALL", 0.35f,
            "KO: Urgently need money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(송금|이체|입금).{0,10}(부탁|해줘|해주세요|바랍니다)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "KO", "ALL", 0.3f,
            "KO: Please transfer/deposit money",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(수수료|보증금|선입금|계약금).{0,15}(먼저|선|사전).{0,10}(보내|입금|이체|납부)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "KO", "ALL", 0.4f,
            "KO: Pay fee/deposit in advance",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("(번호|전화번호|핸드폰).{0,10}(바꿨|변경|바뀌).{0,10}(저장|등록|기억)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "KO", "ALL", 0.35f,
            "KO: I changed my phone number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(엄마|아빠|할머니|할아버지).{0,15}(도와줘|돈|급해|사고|입원)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "KO", "ALL", 0.4f,
            "KO: Family member emergency/accident/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(사고|입원|큰일).{0,20}(급히|당장|빨리|지금).{0,10}(돈|송금|이체|도움)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "KO", "ALL", 0.4f,
            "KO: Accident/hospitalized, need money now",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(국세청|세무서|시청).{0,20}(미납|체납|환급|과태료|벌금)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "KO", "ALL", 0.4f,
            "KO: Tax office unpaid/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(경찰|검찰|법원).{0,20}(체포|소환|수사|영장|피의자)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "KO", "ALL", 0.4f,
            "KO: Police/prosecutor arrest/warrant threat",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(안전\\s*계좌|보호\\s*계좌).{0,15}(이체|송금|입금|옮겨)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "KO", "ALL", 0.45f,
            "KO: Transfer to safe/protection account",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(투자|재테크).{0,15}(보장|확실|무위험|고수익|원금\\s*보장)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "KO", "ALL", 0.4f,
            "KO: Investment guaranteed/no risk/high return",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(비트코인|가상화폐|암호화폐|이더리움|코인).{0,20}(배|급등|기회|내부|정보)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "KO", "ALL", 0.4f,
            "KO: Crypto doubling/insider opportunity",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("(고객님의|귀하의)\\s*(기기|휴대폰|컴퓨터).{0,15}(바이러스|해킹|감염|위험|악성)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "KO", "ALL", 0.35f,
            "KO: Your device has virus/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(고객센터|상담원|기술지원).{0,15}(원격|리모트).{0,10}(제어|설치|접속|앱)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "KO", "ALL", 0.35f,
            "KO: Support remote access/install app",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(운명|인연|첫눈에).{0,20}(당신|특별|소중)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "KO", "ALL", 0.25f,
            "KO: Fate/destiny, you are special",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(보고싶|사랑해|좋아해).{0,20}(선물|돈|송금|보내줄|택배)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "KO", "ALL", 0.3f,
            "KO: Miss/love you, sending gift/money",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // VIETNAMESE (VI)
    // ──────────────────────────────────────────────────────────────────

    private fun vietnameseRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(t[aà]i kho[aả]n|th[eẻ]).{0,20}(b[iị] kh[oó]a|t[aạ]m ng[uừ]ng|b[aấ]t th[uư][oờ]ng|đ[oó]ng b[aă]ng|rủi ro)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "VI", "ALL", 0.4f,
            "VI: Account/card locked/frozen/abnormal",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bMoMo.{0,20}(kh[oó]a|t[aạ]m ng[uừ]ng|b[aấ]t th[uư][oờ]ng|h[aạ]n ch[eế]|x[aá]c minh)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "VI", "ALL", 0.4f,
            "VI: MoMo wallet locked/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bZaloPay.{0,20}(kh[oó]a|t[aạ]m ng[uừ]ng|b[aấ]t th[uư][oờ]ng|h[aạ]n ch[eế]|x[aá]c minh)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "VI", "ALL", 0.4f,
            "VI: ZaloPay wallet locked/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(Vietcombank|VietinBank|BIDV|Techcombank|Agribank|Sacombank).{0,20}(kh[oó]a|t[aạ]m ng[uừ]ng|b[aấ]t th[uư][oờ]ng|x[aá]c minh)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "VI", "ALL", 0.4f,
            "VI: Major Vietnamese bank alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(nh[aậ]p|cung c[aấ]p|g[uử]i).{0,15}(m[aậ]t kh[aẩ]u|m[aã] OTP|m[aã] x[aá]c nh[aậ]n|s[oố] th[eẻ]|m[aã] PIN)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "VI", "ALL", 0.45f,
            "VI: Request for password/OTP/PIN/card number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("giao d[iị]ch.{0,15}(b[aấ]t th[uư][oờ]ng|đ[aá]ng ng[oờ]|kh[oô]ng h[oợ]p l[eệ]|tr[aá]i ph[eé]p)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "VI", "ALL", 0.4f,
            "VI: Suspicious/unauthorized transaction",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\bxin ch[uú]c m[uừ]ng.{0,20}(tr[uú]ng|gi[aả]i|th[uắ]ng|nh[aậ]n đ[uư][oợ]c)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "VI", "ALL", 0.4f,
            "VI: Congratulations you won",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(nh[aậ]n|l[iĩ]nh|đ[oổ]i).{0,15}(gi[aả]i th[uư][oở]ng|ph[aầ]n th[uư][oở]ng|ti[eề]n th[uư][oở]ng|qu[aà] t[aặ]ng)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "VI", "ALL", 0.35f,
            "VI: Claim your prize/gift/reward",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(quay s[oố]|x[oổ] s[oố]|r[uú]t th[aă]m).{0,15}(tr[uú]ng|gi[aả]i nh[aấ]t|đ[aặ]c bi[eệ]t)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "VI", "ALL", 0.35f,
            "VI: Lottery/lucky draw winner",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ngay l[aậ]p t[uứ]c|kh[aẩ]n c[aấ]p|g[aấ]p).{0,15}(nh[aấ]p|b[aấ]m|truy c[aậ]p|đ[aă]ng nh[aậ]p)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "VI", "ALL", 0.4f,
            "VI: Urgently click/access/log in",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(x[aá]c minh|c[aậ]p nh[aậ]t|x[aá]c nh[aậ]n).{0,15}(th[oô]ng tin|d[uữ] li[eệ]u|t[aà]i kho[aả]n|danh t[ií]nh)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "VI", "ALL", 0.35f,
            "VI: Verify/update your information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(t[aà]i kho[aả]n).{0,10}(h[eế]t h[aạ]n|s[aắ]p kh[oó]a|b[iị] h[uủ]y|v[oô] hi[eệ]u).{0,15}(x[aá]c minh|đ[aă]ng nh[aậ]p|c[aậ]p nh[aậ]t)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "VI", "ALL", 0.4f,
            "VI: Account expiring, verify now",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bb[aả]o m[aậ]t.{0,15}(n[aâ]ng c[aấ]p|c[aậ]p nh[aậ]t|x[aá]c minh).{0,15}(link|đ[uư][oờ]ng d[aẫ]n|li[eê]n k[eế]t)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "VI", "ALL", 0.35f,
            "VI: Security upgrade, click link",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(c[aầ]n g[aấ]p|kh[aẩ]n c[aấ]p|g[aấ]p l[aắ]m).{0,15}(ti[eề]n|chuy[eể]n kho[aả]n|chuy[eể]n ti[eề]n)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "VI", "ALL", 0.35f,
            "VI: Urgently need money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(chuy[eể]n|g[uử]i).{0,10}(ti[eề]n|kho[aả]n).{0,15}(v[aà]o|cho|đ[eế]n).{0,15}(t[aà]i kho[aả]n|s[oố] t[aà]i kho[aả]n)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "VI", "ALL", 0.35f,
            "VI: Transfer money to this account",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ph[ií]|l[eệ] ph[ií]|ti[eề]n c[oọ]c|đ[aặ]t c[oọ]c).{0,15}(tr[uư][oớ]c|thanh to[aá]n tr[uư][oớ]c|chuy[eể]n tr[uư][oớ]c)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "VI", "ALL", 0.4f,
            "VI: Pay fee/deposit in advance",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(s[oố] đi[eệ]n tho[aạ]i|s[oố]).{0,10}(đ[oổ]i|thay đ[oổ]i|m[oớ]i).{0,10}(l[uư]u|ghi|nh[oớ]|l[uư]u l[aạ]i)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "VI", "ALL", 0.35f,
            "VI: I changed my phone number, save it",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(con|ch[aá]u|b[oố]|m[eẹ]).{0,10}(đ[aâ]y|n[eè]).{0,15}(c[uứ]u|gi[uú]p|c[aầ]n g[aấ]p|b[iị] tai n[aạ]n|nh[aậ]p vi[eệ]n)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "VI", "ALL", 0.4f,
            "VI: Family member emergency/accident/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(tai n[aạ]n|nh[aậ]p vi[eệ]n|b[iị] b[aắ]t|g[aấ]p chuy[eệ]n).{0,20}(c[aầ]n ti[eề]n|c[aầ]n g[aấ]p|chuy[eể]n ngay|gi[uú]p)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "VI", "ALL", 0.4f,
            "VI: Accident/arrest, need money now",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(thu[eế]|c[oơ] quan thu[eế]).{0,20}(n[oợ]|ch[uư]a n[oộ]p|ph[aạ]t|vi ph[aạ]m|tr[uố]n)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "VI", "ALL", 0.4f,
            "VI: Tax office unpaid/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(c[oô]ng an|vi[eệ]n ki[eể]m s[aá]t|t[oò]a [aá]n).{0,20}(tri[eệ]u t[aậ]p|b[aắ]t|l[eệ]nh|đi[eề]u tra|nghi ph[aạ]m)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "VI", "ALL", 0.4f,
            "VI: Police/prosecutor arrest/summons threat",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(t[aà]i kho[aả]n an to[aà]n|t[aà]i kho[aả]n b[aả]o v[eệ]).{0,15}(chuy[eể]n|g[uử]i|n[oộ]p)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "VI", "ALL", 0.45f,
            "VI: Transfer to safe/protection account",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(đ[aầ]u t[uư]|t[aà]i ch[ií]nh).{0,15}(cam k[eế]t|đ[aả]m b[aả]o|kh[oô]ng r[uủ]i ro|l[oợ]i nhu[aậ]n cao)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "VI", "ALL", 0.4f,
            "VI: Investment guaranteed/no risk/high returns",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bitcoin|ti[eề]n [aả]o|ti[eề]n m[aã] h[oó]a|crypto).{0,20}(g[aấ]p đ[oô]i|t[aă]ng|c[oơ] h[oộ]i|n[oộ]i b[oộ])", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "VI", "ALL", 0.4f,
            "VI: Crypto doubling/insider opportunity",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(đi[eệ]n tho[aạ]i|m[aá]y t[ií]nh|thi[eế]t b[iị]).{0,15}(virus|nhi[eễ]m|b[iị] hack|m[aã] đ[oộ]c|nguy hi[eể]m)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "VI", "ALL", 0.35f,
            "VI: Your device has virus/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(h[oỗ] tr[oợ]|k[iỹ] thu[aậ]t).{0,15}(t[uừ] xa|đi[eề]u khi[eể]n|c[aà]i đ[aặ]t).{0,10}([uứ]ng d[uụ]ng|ph[aầ]n m[eề]m|app)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "VI", "ALL", 0.35f,
            "VI: Support remote install software",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(duy[eê]n s[oố]|đ[iị]nh m[eệ]nh|t[iì]nh c[oờ]).{0,20}(g[aặ]p|quen|bi[eế]t)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "VI", "ALL", 0.25f,
            "VI: Fate/destiny brought us together",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(nh[oớ]|y[eê]u|th[uư][oơ]ng).{0,20}(g[uử]i|t[aặ]ng|qu[aà]|ti[eề]n|v[aà]ng)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "VI", "ALL", 0.3f,
            "VI: Miss/love you, sending gift/money/gold",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // THAI (TH)
    // ──────────────────────────────────────────────────────────────────

    private fun thaiRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("(บัญชี|บัตร).{0,20}(ถูกระงับ|ถูกล็อค|ผิดปกติ|ถูกอายัด|มีความเสี่ยง|ถูกบล็อก)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TH", "ALL", 0.4f,
            "TH: Account/card suspended/locked/abnormal",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("PromptPay.{0,20}(ระงับ|ล็อค|ผิดปกติ|จำกัด|ยืนยัน)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TH", "ALL", 0.4f,
            "TH: PromptPay suspended/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(K\\s*PLUS|KBank|กสิกร).{0,20}(ระงับ|ล็อค|ผิดปกติ|จำกัด|ยืนยัน)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TH", "ALL", 0.4f,
            "TH: KBank/K PLUS suspended/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(SCB|ไทยพาณิชย์|กรุงเทพ|Bangkok Bank|TrueMoney|ทรูมันนี่).{0,20}(ระงับ|ล็อค|ผิดปกติ|ยืนยัน)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TH", "ALL", 0.4f,
            "TH: Major Thai bank/TrueMoney alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(กรอก|ส่ง|แจ้ง).{0,10}(รหัสผ่าน|รหัส OTP|รหัส PIN|เลขบัตร|เลขบัญชี)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TH", "ALL", 0.45f,
            "TH: Request for password/OTP/PIN/card number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ธุรกรรม|การโอน|การชำระ).{0,15}(ผิดปกติ|น่าสงสัย|ไม่ได้รับอนุญาต)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "TH", "ALL", 0.4f,
            "TH: Suspicious/unauthorized transaction",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("ยินดีด้วย.{0,20}(ได้รับ|ชนะ|ถูกรางวัล|ได้รางวัล|คัดเลือก)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "TH", "ALL", 0.4f,
            "TH: Congratulations you won",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(รับ|แลก|เคลม).{0,15}(รางวัล|เงินรางวัล|ของรางวัล|เงินสด)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "TH", "ALL", 0.35f,
            "TH: Claim your prize/cash/reward",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(สลากกินแบ่ง|ล็อตเตอรี่|จับรางวัล).{0,15}(ถูก|ชนะ|รางวัลที่\\s*1|แจ็คพ็อต)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "TH", "ALL", 0.4f,
            "TH: Lottery/jackpot winner",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("(ด่วน|เร่งด่วน|ทันที|รีบ).{0,15}(คลิก|กด|เข้า|ล็อกอิน|ยืนยัน)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "TH", "ALL", 0.4f,
            "TH: Urgently click/access/log in",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ยืนยันตัวตน|อัพเดทข้อมูล|ยืนยันข้อมูล).{0,15}(กรุณา|โปรด|จำเป็น)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "TH", "ALL", 0.35f,
            "TH: Verify identity/update info required",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(บัญชี|แอคเคาท์).{0,10}(หมดอายุ|ถูกปิด|ระงับ|ใช้ไม่ได้).{0,15}(ยืนยัน|อัพเดท|คลิก)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "TH", "ALL", 0.4f,
            "TH: Account expiring/closing, verify now",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ความปลอดภัย|ระบบรักษาความปลอดภัย).{0,15}(อัพเกรด|อัพเดท|ยืนยัน).{0,10}(ลิงก์|ลิ้งค์|เว็บ)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "TH", "ALL", 0.35f,
            "TH: Security update, click link",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("(ต้องการด่วน|เร่งด่วน|รีบ).{0,15}(เงิน|โอน|โอนเงิน)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "TH", "ALL", 0.35f,
            "TH: Urgently need money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(โอน|ส่ง).{0,10}(เงิน).{0,15}(ไปที่|เข้า|บัญชี|เลขที่)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "TH", "ALL", 0.35f,
            "TH: Transfer money to this account",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ค่าธรรมเนียม|เงินมัดจำ|เงินประกัน|ค่าดำเนินการ).{0,15}(ก่อน|ล่วงหน้า|จ่ายก่อน|โอนก่อน)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "TH", "ALL", 0.4f,
            "TH: Pay fee/deposit in advance",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("(เบอร์|เบอร์โทร|หมายเลข).{0,10}(เปลี่ยน|ใหม่|เปลี่ยนแล้ว).{0,10}(บันทึก|เซฟ|จด)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "TH", "ALL", 0.35f,
            "TH: I changed my phone number, save it",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(แม่|พ่อ|ลูก|หลาน).{0,15}(ช่วย|ด่วน|เงิน|อุบัติเหตุ|โรงพยาบาล)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "TH", "ALL", 0.4f,
            "TH: Family member emergency/accident/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(อุบัติเหตุ|เข้าโรงพยาบาล|ถูกจับ|มีเรื่อง).{0,20}(ด่วน|ต้องการเงิน|รีบ|โอน|ช่วย)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "TH", "ALL", 0.4f,
            "TH: Accident/arrest, need money now",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(สรรพากร|กรมสรรพากร|สำนักงานเขต).{0,20}(ค้างชำระ|ค้างจ่าย|ค่าปรับ|หนี้ภาษี)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "TH", "ALL", 0.4f,
            "TH: Revenue department unpaid tax/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ตำรวจ|อัยการ|ศาล).{0,20}(จับ|หมายเรียก|หมายจับ|สอบสวน|ผู้ต้องสงสัย)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "TH", "ALL", 0.4f,
            "TH: Police/court arrest/warrant threat",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(บัญชีปลอดภัย|บัญชีคุ้มครอง).{0,15}(โอน|ฝาก|ส่ง)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "TH", "ALL", 0.45f,
            "TH: Transfer to safe/protection account",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(ลงทุน|การลงทุน).{0,15}(การันตี|ไม่มีความเสี่ยง|ผลตอบแทนสูง|รับรอง|มั่นคง)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "TH", "ALL", 0.4f,
            "TH: Investment guaranteed/no risk/high return",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(บิทคอยน์|คริปโต|เหรียญดิจิทัล|สกุลเงินดิจิทัล).{0,20}(เท่าตัว|พุ่ง|โอกาส|ข้อมูลวงใน)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "TH", "ALL", 0.4f,
            "TH: Crypto doubling/insider opportunity",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("(โทรศัพท์|คอมพิวเตอร์|อุปกรณ์).{0,15}(ไวรัส|ติดไวรัส|ถูกแฮก|มัลแวร์|อันตราย)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "TH", "ALL", 0.35f,
            "TH: Your device has virus/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(ฝ่ายช่วยเหลือ|ฝ่ายเทคนิค|เจ้าหน้าที่).{0,15}(รีโมท|ควบคุมระยะไกล|ติดตั้ง).{0,10}(แอป|ซอฟต์แวร์|โปรแกรม)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "TH", "ALL", 0.35f,
            "TH: Support remote install software",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("(พรหมลิขิต|โชคชะตา|ดวงชะตา).{0,20}(เจอ|พบ|รู้จัก)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "TH", "ALL", 0.25f,
            "TH: Fate/destiny brought us together",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("(คิดถึง|รัก|ห่วง).{0,20}(ส่ง|โอน|ของขวัญ|เงิน|ทอง)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "TH", "ALL", 0.3f,
            "TH: Miss/love you, sending gift/money/gold",
        ))
    }

    // ──────────────────────────────────────────────────────────────────
    // INDONESIAN (ID)
    // ──────────────────────────────────────────────────────────────────

    private fun indonesianRules(): List<ScamPatternDetector.PatternRule> = buildList {

        // ── BANK_FRAUD ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(akun|rekening|kartu)\\s*.{0,20}(diblokir|dibekukan|ditangguhkan|tidak normal|dicurigai|terkunci)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ID", "ALL", 0.4f,
            "ID: Account/card blocked/frozen/suspicious",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\bGoPay.{0,20}(diblokir|dibekukan|ditangguhkan|dibatasi|verifikasi)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ID", "ALL", 0.4f,
            "ID: GoPay blocked/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(OVO|DANA|ShopeePay).{0,20}(diblokir|dibekukan|ditangguhkan|dibatasi|verifikasi)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ID", "ALL", 0.4f,
            "ID: OVO/DANA/ShopeePay blocked/restricted",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(BCA|Mandiri|BNI|BRI|CIMB Niaga|Bank Jago).{0,20}(diblokir|dibekukan|ditangguhkan|tidak normal|verifikasi)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ID", "ALL", 0.4f,
            "ID: Major Indonesian bank alert",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(masukkan|berikan|kirimkan)\\s*.{0,15}(kata sandi|password|kode OTP|PIN|nomor kartu|CVV)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ID", "ALL", 0.45f,
            "ID: Request for password/OTP/PIN/card number",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\btransaksi.{0,15}(mencurigakan|tidak sah|tidak dikenal|ilegal|tidak wajar)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ID", "ALL", 0.4f,
            "ID: Suspicious/unauthorized transaction",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(aktivitas|akses)\\s*(mencurigakan|tidak sah|ilegal).{0,15}(terdeteksi|ditemukan)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.BANK_FRAUD, "ID", "ALL", 0.4f,
            "ID: Suspicious activity/access detected",
        ))

        // ── PRIZE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\bselamat.{0,20}(menang|memenangkan|terpilih|mendapatkan|beruntung)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "ID", "ALL", 0.4f,
            "ID: Congratulations you won",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(klaim|ambil|tukarkan|dapatkan)\\s*.{0,15}(hadiah|hadiah uang|voucher|uang tunai|reward)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "ID", "ALL", 0.35f,
            "ID: Claim your prize/cash/voucher",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(undian|lotre|lucky draw).{0,15}(menang|pemenang|juara|grand prize|jackpot)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PRIZE_SCAM, "ID", "ALL", 0.4f,
            "ID: Lottery/lucky draw winner",
        ))

        // ── PHISHING ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(segera|darurat|sekarang juga|cepat).{0,15}(klik|tekan|buka|akses|login|masuk)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "ID", "ALL", 0.4f,
            "ID: Urgently click/access/log in",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(verifikasi|perbarui|konfirmasi|lengkapi)\\s*.{0,15}(data|informasi|akun|identitas)\\s*(anda|kamu)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "ID", "ALL", 0.35f,
            "ID: Verify/update your information",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(akun|rekening).{0,10}(kadaluarsa|ditutup|dinonaktifkan|kedaluwarsa).{0,15}(verifikasi|perbarui|klik)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "ID", "ALL", 0.4f,
            "ID: Account expiring/closing, verify now",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(keamanan|sistem keamanan).{0,15}(peningkatan|pembaruan|verifikasi).{0,10}(link|tautan|URL)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.PHISHING, "ID", "ALL", 0.35f,
            "ID: Security update, click link",
        ))

        // ── MONEY_REQUEST ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(butuh segera|darurat|mendesak).{0,15}(uang|transfer|kirim uang)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "ID", "ALL", 0.35f,
            "ID: Urgently need money/transfer",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(transfer|kirim)\\s*.{0,10}(uang|dana).{0,15}(ke|rekening|nomor rekening)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "ID", "ALL", 0.35f,
            "ID: Transfer money to this account",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(biaya|uang muka|deposit|jaminan|biaya admin).{0,15}(terlebih dahulu|duluan|di muka|bayar dulu)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.MONEY_REQUEST, "ID", "ALL", 0.4f,
            "ID: Pay fee/deposit in advance",
        ))

        // ── IMPERSONATION ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(nomor|nomor HP|nomor telepon).{0,10}(ganti|baru|berubah).{0,10}(simpan|catat|save)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "ID", "ALL", 0.35f,
            "ID: I changed my phone number, save it",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(ibu|ayah|anak|mama|papa).{0,15}(tolong|uang|darurat|kecelakaan|rumah sakit)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "ID", "ALL", 0.4f,
            "ID: Family member emergency/accident/hospital",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kecelakaan|masuk rumah sakit|ditangkap|masalah besar).{0,20}(butuh uang|segera|darurat|transfer|tolong)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.IMPERSONATION, "ID", "ALL", 0.4f,
            "ID: Accident/arrest, need money now",
        ))

        // ── GOVERNMENT_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kantor pajak|dirjen pajak|ditjen pajak).{0,20}(tunggakan|belum bayar|denda|pelanggaran)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "ID", "ALL", 0.4f,
            "ID: Tax office unpaid/penalty",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(polisi|kejaksaan|pengadilan).{0,20}(tangkap|panggilan|surat perintah|penyelidikan|tersangka)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "ID", "ALL", 0.4f,
            "ID: Police/prosecutor arrest/warrant threat",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(rekening aman|rekening perlindungan).{0,15}(transfer|kirim|pindahkan)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.GOVERNMENT_SCAM, "ID", "ALL", 0.45f,
            "ID: Transfer to safe/protection account",
        ))

        // ── CRYPTO_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(investasi|penanaman modal).{0,15}(dijamin|tanpa risiko|keuntungan tinggi|pasti untung|aman)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "ID", "ALL", 0.4f,
            "ID: Investment guaranteed/no risk/high return",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(bitcoin|kripto|crypto|mata uang digital|aset digital).{0,20}(lipat ganda|melonjak|peluang|orang dalam|info rahasia)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "ID", "ALL", 0.4f,
            "ID: Crypto doubling/insider opportunity",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(keuntungan|return|profit)\\s*.{0,10}(harian|bulanan|tahunan).{0,10}[1-9]\\d.{0,3}(%|persen)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.CRYPTO_SCAM, "ID", "ALL", 0.35f,
            "ID: Unrealistic daily/monthly returns",
        ))

        // ── TECH_SUPPORT ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(HP|ponsel|komputer|perangkat)\\s*(anda|kamu).{0,15}(virus|terinfeksi|diretas|malware|berbahaya)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "ID", "ALL", 0.35f,
            "ID: Your device has virus/hacked",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(layanan pelanggan|customer service|dukungan teknis).{0,15}(remote|jarak jauh|instal).{0,10}(aplikasi|software|app)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.TECH_SUPPORT, "ID", "ALL", 0.35f,
            "ID: Support remote install software",
        ))

        // ── ROMANCE_SCAM ──

        add(ScamPatternDetector.PatternRule(
            Regex("\\b(takdir|jodoh|nasib).{0,20}(bertemu|kenal|menemukan)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "ID", "ALL", 0.25f,
            "ID: Fate/destiny brought us together",
        ))
        add(ScamPatternDetector.PatternRule(
            Regex("\\b(kangen|rindu|cinta|sayang).{0,20}(kirim|hadiah|uang|emas|paket)", RegexOption.IGNORE_CASE),
            ScamPatternDetector.ScamCategory.ROMANCE_SCAM, "ID", "ALL", 0.3f,
            "ID: Miss/love you, sending gift/money/gold",
        ))
    }
}
