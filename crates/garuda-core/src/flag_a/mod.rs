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

    let (s, r) = brand::check(&parts.original);
    score = score.saturating_add(s);
    reasons.extend(r);

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

    (score, reasons)
}

#[cfg(test)]
mod tests {
    use super::analyse;
    use crate::scorer::score_to_verdict;
    use crate::types::Verdict;

    #[test]
    fn safe_domain_stays_clean() {
        let (score, reasons) = analyse("https://google.com");
        let verdict = score_to_verdict(score, reasons);
        assert!(matches!(verdict.verdict, Verdict::Clean));
    }

    #[test]
    fn free_platform_brand_impersonation_is_blocked() {
        let (score, reasons) = analyse("https://google-account-verify.vercel.app/login");
        let verdict = score_to_verdict(score, reasons);
        assert!(matches!(verdict.verdict, Verdict::Block));
    }

    #[test]
    fn mixed_script_domain_is_flagged() {
        let (score, reasons) = analyse("https://rnicrosoft.com");
        let verdict = score_to_verdict(score, reasons);
        assert!(score >= 40 || matches!(verdict.verdict, Verdict::Caution | Verdict::Block));
    }
}
