pub mod brand;
pub mod homoglyph;
pub mod keywords;
pub mod platform;
use crate::url;

fn score_push(score: &mut u8, reasons: &mut Vec<String>, amount: u8, reason: String) {
    *score = score.saturating_add(amount);
    reasons.push(reason);
}

pub fn analyse(url: &str) -> (u8, Vec<String>) {
    let parts = url::parse_url(url);
    let mut score: u8 = 0;
    let mut reasons = Vec::new();

    if url::looks_like_ip(&parts.host) {
        score_push(&mut score, &mut reasons, 25, "ip_address_hostname".to_string());
    }

    let subdomains = url::count_subdomains(&parts.host);
    if subdomains >= 3 {
        score_push(
            &mut score,
            &mut reasons,
            10,
            format!("many_subdomains:{}", subdomains),
        );
    }

    let hyphens = url::count_hyphens(&parts.host);
    if hyphens >= 3 {
        score_push(
            &mut score,
            &mut reasons,
            10,
            format!("many_hyphens:{}", hyphens),
        );
    }

    if parts.host.len() > 30 {
        score_push(
            &mut score,
            &mut reasons,
            10,
            format!("long_hostname:{}", parts.host.len()),
        );
    }

    if url::is_safe_domain(&parts.host) {
        score = score.saturating_sub(20);
        reasons.push(format!("safe_domain:{}", parts.host));
    }

    if url::is_indian_trusted_domain(&parts.host) {
        score = score.saturating_sub(10);
        reasons.push(format!("trusted_indian_domain:{}", parts.host));
    }

    let brand_result = brand::check(&parts.original);
    score = score.saturating_add(brand_result.score);
    reasons.extend(brand_result.reasons.clone());

    let (s, r) = platform::check(&parts.host);
    score = score.saturating_add(s);
    reasons.extend(r);

    let combined = url::normalize_segments(&parts.host, &parts.path_and_query);
    let (s, r) = keywords::check(&combined);
    score = score.saturating_add(s);
    reasons.extend(r);

    let (s, r) = homoglyph::check(&parts.original);
    score = score.saturating_add(s);
    reasons.extend(r);

    let context = url::analyze_context(
        &parts.host,
        &parts.path_and_query,
        &reasons,
        &brand_result.matches,
    );
    score = url::apply_contextual_multiplier(score, &context);

    (score, reasons)
}

#[cfg(test)]
mod tests {
    use super::analyse;
    use crate::scorer::score_to_verdict;
    use crate::types::Verdict;

    fn setup_brand_rules() {
        std::env::set_var("GARUDA_BRANDS_PATH", "../../lists/brands.json");
    }

    #[test]
    fn safe_domain_stays_clean() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://google.com");
        let verdict = score_to_verdict(score, reasons);
        assert!(matches!(verdict.verdict, Verdict::Clean));
    }

    #[test]
    fn free_platform_brand_impersonation_is_blocked() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://google-account-verify.vercel.app/login");
        assert!(reasons.iter().any(|reason| reason.contains("suspicious_hosting:vercel.app")));
        let verdict = score_to_verdict(score, reasons);
        assert!(matches!(verdict.verdict, Verdict::Block));
    }

    #[test]
    fn mixed_script_domain_is_flagged() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://rnicrosoft.com");
        let verdict = score_to_verdict(score, reasons);
        assert!(score >= 25 || matches!(verdict.verdict, Verdict::Suspicious | Verdict::Caution | Verdict::Block));
    }

    #[test]
    fn firebase_phishing_is_blocked() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://sbi-kyc-update.firebaseapp.com/login");
        assert!(reasons.iter().any(|reason| reason.contains("suspicious_hosting:firebaseapp.com")));
        let verdict = score_to_verdict(score, reasons);
        assert!(matches!(verdict.verdict, Verdict::Caution | Verdict::Block));
    }

    #[test]
    fn trusted_indian_domain_is_not_penalized() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://uidai.gov.in");
        assert!(reasons.iter().any(|reason| reason.contains("trusted_indian_domain:uidai.gov.in")));
        let verdict = score_to_verdict(score, reasons);
        assert!(matches!(verdict.verdict, Verdict::Clean));
    }

    #[test]
    fn homoglyph_l_i_substitution_detected() {
        setup_brand_rules();
        let (score, _reasons) = analyse("https://paypaI.com");
        assert!(score >= 50, "paypaI (l/I substitution) should be detected, got score {}", score);
    }

    #[test]
    fn homoglyph_capital_O_zero_detected() {
        setup_brand_rules();
        let (score, _reasons) = analyse("https://goog1e.com");
        assert!(score >= 50, "goog1e (1/i substitution) should be detected, got score {}", score);
    }

    #[test]
    fn brand_containment_with_hosting_multiplies_risk() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://phonepe-kyc-auth.pages.dev");
        assert!(score >= 80,
            "phonepe + kyc on pages.dev should be high risk due to contextual multiplier, got score {}", score);
        assert!(reasons.iter().any(|r| r.contains("brand_impersonation:phonepe")));
        assert!(reasons.iter().any(|r| r.contains("suspicious_hosting:pages.dev")));
    }

    #[test]
    fn wallet_recovery_is_highly_suspicious() {
        setup_brand_rules();
        let (score, _reasons) = analyse("https://wallet-recovery-seed.netlify.app");
        assert!(score >= 60,
            "wallet + recovery + seed on netlify should trigger high score due to crypto keyword multiplier, got {}", score);
    }

    #[test]
    fn bank_login_on_free_hosting_is_high_severity() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://axisbank-secure-netbanking.web.app/login");
        assert!(score >= 80,
            "bank brand + netbanking + login on web.app should be very high due to multipliers, got {}", score);
        assert!(reasons.iter().any(|r| r.contains("brand_impersonation")));
    }

    #[test]
    fn income_tax_refund_scam_detected() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://income-tax-refund.netlify.app/verify");
        assert!(score >= 50,
            "refund + verify on hosting should be suspicious, got {}", score);
        assert!(reasons.iter().any(|r| r.contains("suspicious_keyword:refund")));
    }

    #[test]
    fn paypal_kyc_on_firebase_multiplied() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://paypal-kyc-verification.firebaseapp.com");
        assert!(score >= 80,
            "paypal + kyc on firebase should trigger maximum multiplier, got {}", score);
        assert!(reasons.iter().any(|r| r.contains("brand_impersonation")));
        assert!(reasons.iter().any(|r| r.contains("suspicious_keyword:kyc")));
    }

    #[test]
    fn hosting_suffix_does_not_trigger_unrelated_brand() {
        setup_brand_rules();
        let (_score, reasons) = analyse("https://kotak-netbanking-login.netlify.app");
        assert!(
            reasons.iter().all(|r| {
                !(r == "brand_impersonation:netflix"
                    || r == "brand_impersonation:zoom"
                    || r == "brand_impersonation:apple")
            }),
            "hosting or TLD labels should not map to unrelated brands: {:?}",
            reasons
        );
    }

    #[test]
    fn github_typo_gets_high_confidence_brand_reason() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://githuub.com");
        assert!(
            reasons.iter().any(|r| r == "brand_impersonation:github"),
            "expected github brand reason, got {:?}",
            reasons
        );
        assert!(score >= 50, "known-brand typo should not stay clean, got {}", score);
    }

    #[test]
    fn gitlab_impersonation_is_not_misattributed() {
        setup_brand_rules();
        let (_score, reasons) = analyse("https://gitlab-account-security.pages.dev");
        assert!(
            reasons.iter().any(|r| r == "brand_impersonation:gitlab"),
            "expected gitlab brand reason, got {:?}",
            reasons
        );
        assert!(
            reasons.iter().all(|r| r != "brand_impersonation:github"),
            "gitlab should not be mapped to github: {:?}",
            reasons
        );
    }

    #[test]
    fn government_verify_is_critical() {
        setup_brand_rules();
        let (score, reasons) = analyse("https://aadhaar-verify.pages.dev/login");
        assert!(score >= 80, "government verify should be critical, got {}", score);
        assert!(reasons.iter().any(|r| r == "brand_impersonation:aadhaar"));
    }

    #[test]
    fn typo_domains_block_without_keywords() {
        setup_brand_rules();
        let (score, _reasons) = analyse("https://rnicrosoft.com");
        assert!(score >= 80, "rnicrosoft should be high-risk typo, got {}", score);
        let (score, _reasons) = analyse("https://arnazon.in");
        assert!(score >= 80, "arnazon should be high-risk typo, got {}", score);
        let (score, _reasons) = analyse("https://linkedln.com");
        assert!(score >= 80, "linkedln should be high-risk typo, got {}", score);
    }
}
