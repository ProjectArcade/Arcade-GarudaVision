use crate::brand_rules::{self, BrandCategory, BrandRule};
use garuda_lists::{platform_list, safe_list};
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone)]
pub enum MatchType {
    Exact,
    Normalized,
    Homoglyph,
    Alias,
    TypoDistance,
}

#[derive(Debug, Clone)]
pub struct BrandMatch {
    pub brand: String,
    pub domain: String,
    pub category: BrandCategory,
    pub risk: u8,
    pub confidence: f32,
    pub match_type: MatchType,
}

#[derive(Debug, Clone)]
pub struct UrlParts {
    pub original: String,
    pub normalized: String,
    pub host: String,
    pub path_and_query: String,
}

pub fn parse_url(input: &str) -> UrlParts {
    let original = input.trim().to_string();
    let normalized = original.nfkc().collect::<String>().to_lowercase();
    let without_scheme = normalized
        .strip_prefix("https://")
        .or_else(|| normalized.strip_prefix("http://"))
        .unwrap_or(&normalized);
    let (authority, path_and_query) = match without_scheme.split_once('/') {
        Some((authority, rest)) => (authority, format!("/{}", rest)),
        None => (without_scheme, String::new()),
    };
    let without_credentials = authority.rsplit_once('@').map(|(_, tail)| tail).unwrap_or(authority);
    let without_www = without_credentials.strip_prefix("www.").unwrap_or(without_credentials);

    let host = match without_www.split_once('/') {
        Some((host, _)) => host,
        None => without_www,
    };

    let host = host
        .split(['?', '#'])
        .next()
        .unwrap_or(host)
        .split(':')
        .next()
        .unwrap_or(host)
        .trim_end_matches('.')
        .to_string();

    UrlParts {
        original,
        normalized,
        host,
        path_and_query,
    }
}

pub fn is_domain_or_subdomain(host: &str, domain: &str) -> bool {
    let host = host.trim().to_lowercase();
    let domain = domain.trim().to_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

pub fn is_safe_domain(host: &str) -> bool {
    safe_list::is_safe(host)
}

pub fn is_free_platform(host: &str) -> bool {
    platform_list::is_free_platform(host)
}

pub fn is_indian_domain(host: &str) -> bool {
    let host = host.trim().to_lowercase();
    host.ends_with(".in")
        || host.ends_with(".co.in")
        || host.ends_with(".org.in")
        || host.ends_with(".net.in")
        || host.ends_with(".gov.in")
        || host.ends_with(".nic.in")
        || host.ends_with(".ac.in")
        || host.ends_with(".edu.in")
        || host.ends_with(".res.in")
}

pub fn is_indian_trusted_domain(host: &str) -> bool {
    let host = host.trim().to_lowercase();
    host.ends_with(".gov.in")
        || host.ends_with(".nic.in")
        || host.ends_with(".ac.in")
        || host.ends_with(".edu.in")
        || host.ends_with(".res.in")
}

pub fn find_brand_matches(host: &str) -> Vec<BrandMatch> {
    let rules = brand_rules::get_rules();
    if rules.rules.is_empty() {
        return Vec::new();
    }

    let host = host.to_lowercase();
    let tokens = tokenize_host(&host);
    let mut matches = Vec::new();

    for rule in rules.rules.iter() {
        if is_domain_or_subdomain(&host, &rule.domain) {
            continue;
        }

        if let Some(matched) = match_rule_tokens(&host, &tokens, rule) {
            if matched.confidence >= 0.78 {
                matches.push(matched);
            }
        }
    }

    matches
}

fn match_rule_tokens(host: &str, tokens: &[String], rule: &BrandRule) -> Option<BrandMatch> {
    let canonical = rule.canonical.to_lowercase();
    let alias_values: Vec<String> = rule.aliases.iter().map(|alias| alias.to_lowercase()).collect();
    let canonical_norm = normalize_token(&canonical);
    let alias_norms: Vec<String> = alias_values.iter().map(|alias| normalize_token(alias)).collect();

    for token in tokens {
        if is_noise_token(token, host) {
            continue;
        }

        if token == &canonical {
            return Some(build_match(rule, MatchType::Exact, 1.0));
        }

        if alias_values.iter().any(|alias| alias == token) {
            return Some(build_match(rule, MatchType::Alias, 0.95));
        }

        if token.len() >= 4 {
            let token_norm = normalize_token(token);
            if token_norm == canonical_norm && token != &canonical {
                return Some(build_match(rule, MatchType::Normalized, 0.92));
            }

            if alias_norms.iter().any(|alias| alias == &token_norm) {
                return Some(build_match(rule, MatchType::Normalized, 0.9));
            }

            let (homoglyph, changed) = normalize_homoglyphs_with_flags(token);
            if changed {
                if homoglyph == canonical || alias_values.iter().any(|alias| alias == &homoglyph) {
                    return Some(build_match(rule, MatchType::Homoglyph, 0.85));
                }
            }
        }

        if token.len() >= 5 {
            let token_norm = normalize_token(token);
            if let Some(distance) = strict_levenshtein_match(&token_norm, &canonical_norm) {
                let confidence = if distance == 1 { 0.82 } else { 0.75 };
                return Some(build_match(rule, MatchType::TypoDistance, confidence));
            }
        }
    }

    None
}

fn build_match(rule: &BrandRule, match_type: MatchType, confidence: f32) -> BrandMatch {
    BrandMatch {
        brand: rule.canonical.to_string(),
        domain: rule.domain.to_string(),
        category: rule.category.clone(),
        risk: rule.risk,
        confidence,
        match_type,
    }
}

fn tokenize_host(host: &str) -> Vec<String> {
    host.split(['.', '-', '_'])
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect()
}

fn normalize_token(token: &str) -> String {
    token
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

fn is_noise_token(token: &str, host: &str) -> bool {
    const NOISE: &[&str] = &[
        "com", "org", "net", "in", "co", "io", "ai", "app", "dev", "gov", "edu", "nic",
        "ac", "res", "www", "vercel", "pages", "netlify", "web", "firebaseapp",
        "onrender", "herokuapp", "appspot",
    ];

    if NOISE.contains(&token) {
        return true;
    }

    is_platform_label(token, host)
}

fn is_platform_label(token: &str, host: &str) -> bool {
    let platform_labels = [
        ("vercel", "vercel.app"),
        ("pages", "pages.dev"),
        ("netlify", "netlify.app"),
        ("firebaseapp", "firebaseapp.com"),
        ("web", "web.app"),
        ("github", "github.io"),
        ("onrender", "onrender.com"),
        ("herokuapp", "herokuapp.com"),
        ("appspot", "appspot.com"),
    ];

    platform_labels
        .iter()
        .any(|(label, domain)| token == *label && is_domain_or_subdomain(host, domain))
}

fn strict_levenshtein_match(token: &str, brand: &str) -> Option<usize> {
    if brand.len() < 5 || token.len() < 5 {
        return None;
    }

    let len_diff = token.len().abs_diff(brand.len());
    if len_diff > 2 {
        return None;
    }

    let distance = levenshtein_distance(token, brand);
    if distance == 0 || distance > 2 {
        return None;
    }

    Some(distance)
}

fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.len();
    let len2 = s2.len();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut prev_row: Vec<usize> = (0..=len2).collect();
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();

    for (i, &c1) in s1_chars.iter().enumerate() {
        let mut curr_row = vec![i + 1];

        for (j, &c2) in s2_chars.iter().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            let del = prev_row[j + 1] + 1;
            let ins = curr_row[j] + 1;
            let sub = prev_row[j] + cost;
            curr_row.push(del.min(ins).min(sub));
        }

        prev_row = curr_row;
    }

    prev_row[len2]
}

pub fn looks_like_ip(host: &str) -> bool {
    let host = host.trim();
    host.parse::<std::net::Ipv4Addr>().is_ok()
        || host.parse::<std::net::Ipv6Addr>().is_ok()
        || host.chars().all(|c| c.is_ascii_digit() || c == '.') && host.contains('.')
}

pub fn has_punycode(host: &str) -> bool {
    host.contains("xn--")
}

pub fn has_mixed_script(value: &str) -> bool {
    let mut has_ascii = false;
    let mut has_non_ascii = false;

    for ch in value.chars() {
        if ch.is_ascii_alphabetic() {
            has_ascii = true;
        } else if ch.is_alphabetic() {
            has_non_ascii = true;
        }

        if has_ascii && has_non_ascii {
            return true;
        }
    }

    false
}

pub fn count_subdomains(host: &str) -> usize {
    let labels: Vec<&str> = host
        .split('.')
        .filter(|label| !label.is_empty())
        .collect();

    labels.len().saturating_sub(2)
}

pub fn count_hyphens(value: &str) -> usize {
    value.chars().filter(|ch| *ch == '-').count()
}

pub fn normalize_segments(host: &str, path_and_query: &str) -> String {
    format!("{}{}", host.to_lowercase(), path_and_query.to_lowercase())
}

pub fn suspicious_keywords() -> &'static [&'static str] {
    &[
        "login",
        "auth",
        "verify",
        "verification",
        "password",
        "account",
        "confirm",
        "secure",
        "update",
        "banking",
        "signin",
        "sign-in",
        "credential",
        "authenticate",
        "otp",
        "kyc",
        "refund",
        "payment",
        "wallet",
        "recovery",
        "seed",
        "billing",
        "support",
        "premium",
        "upgrade",
        "business",
        "bluebadge",
        "aadhaar",
        "aadhar",
        "pan",
        "ifsc",
        "netbanking",
        "upi",
    ]
}

pub fn keyword_hits(value: &str) -> Vec<&'static str> {
    let value = value.to_lowercase();
    suspicious_keywords()
        .iter()
        .copied()
        .filter(|keyword| value.contains(keyword))
        .collect()
}

pub fn normalize_homoglyphs(value: &str) -> String {
    normalize_homoglyphs_with_flags(value).0
}

pub fn normalize_homoglyphs_with_flags(value: &str) -> (String, bool) {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    let mut changed = false;

    while index < chars.len() {
        if index + 1 < chars.len() {
            match (chars[index], chars[index + 1]) {
                ('r', 'n') => {
                    out.push('m');
                    changed = true;
                    index += 2;
                    continue;
                }
                ('v', 'v') => {
                    out.push('w');
                    changed = true;
                    index += 2;
                    continue;
                }
                _ => {}
            }
        }

        let ch = chars[index];
        let mapped = match ch {
            'I' | 'l' | 'L' | '1' | '|' => 'l',
            'O' | '0' => 'o',
            'S' | '5' => 's',
            'Z' | '2' => 'z',
            'B' | '8' => 'b',
            'G' | '9' => 'g',
            'T' | '7' => 't',
            'E' | '3' => 'e',
            '@' => 'a',
            other => other,
        };

        if mapped != ch {
            changed = true;
        }

        if mapped.is_ascii_alphabetic() {
            out.push(mapped.to_ascii_lowercase());
        } else {
            out.push(mapped);
        }

        index += 1;
    }

    (out, changed)
}

#[derive(Debug, Clone)]
pub struct SuspiciousContext {
    pub has_brand: bool,
    pub has_financial_keyword: bool,
    pub has_auth_keyword: bool,
    pub has_crypto_keyword: bool,
    pub has_free_hosting: bool,
    pub brand_name: Option<String>,
    pub brand_categories: Vec<BrandCategory>,
    pub brand_risk: Option<u8>,
}

pub fn analyze_context(
    host: &str,
    path_query: &str,
    reasons: &[String],
    brand_matches: &[BrandMatch],
) -> SuspiciousContext {
    let combined = format!("{}{}", host.to_lowercase(), path_query.to_lowercase());
    
    let financial_keywords = &[
        "bank", "payment", "wallet", "refund", "kyc", "pan", "ifsc", "netbanking",
        "billing", "upi",
    ];
    let auth_keywords = &[
        "login", "verify", "password", "auth", "account", "confirm", "otp", "signin",
    ];
    let crypto_keywords = &["seed", "phrase", "recovery", "private", "key", "mnemonic"];

    let has_brand = !brand_matches.is_empty()
        || reasons.iter().any(|r| r.contains("brand_impersonation"));
    let has_financial_keyword = financial_keywords.iter().any(|kw| combined.contains(kw));
    let has_auth_keyword = auth_keywords.iter().any(|kw| combined.contains(kw));
    let has_crypto_keyword = crypto_keywords.iter().any(|kw| combined.contains(kw));
    let has_free_hosting = reasons.iter().any(|r| r.contains("free_platform") || r.contains("suspicious_hosting"));

    let brand_name = brand_matches
        .first()
        .map(|item| item.brand.clone())
        .or_else(|| {
            reasons
                .iter()
                .find(|r| r.contains("brand_impersonation"))
                .and_then(|r| r.split(':').nth(1).map(|s| s.to_string()))
        });

    let brand_categories = brand_matches.iter().map(|item| item.category.clone()).collect();
    let brand_risk = brand_matches.iter().map(|item| item.risk).max();

    SuspiciousContext {
        has_brand,
        has_financial_keyword,
        has_auth_keyword,
        has_crypto_keyword,
        has_free_hosting,
        brand_name,
        brand_categories,
        brand_risk,
    }
}

pub fn apply_contextual_multiplier(base_score: u8, context: &SuspiciousContext) -> u8 {
    let mut bonus = 0.0;

    if context.has_brand && context.has_free_hosting {
        bonus += 0.9;
    }

    if context.has_brand && context.has_financial_keyword {
        bonus += 0.7;
    }

    if context.has_free_hosting && context.has_auth_keyword {
        bonus += 0.6;
    }

    if context.has_financial_keyword && context.has_auth_keyword {
        bonus += 0.4;
    }

    if context.has_crypto_keyword && context.has_auth_keyword {
        bonus += 0.8;
    }

    if context.brand_categories.contains(&BrandCategory::Government) && context.has_auth_keyword {
        bonus += 1.0;
    }

    if context.brand_categories.contains(&BrandCategory::Bank) && context.has_auth_keyword {
        bonus += 0.8;
    }

    if context.brand_categories.contains(&BrandCategory::Crypto) && context.has_crypto_keyword {
        bonus += 0.9;
    }

    if let Some(risk) = context.brand_risk {
        bonus += (risk as f32 / 100.0) * 0.2;
    }

    let adjusted = (base_score as f32 * (1.0 + bonus)).round() as u8;
    adjusted.min(100)
}
