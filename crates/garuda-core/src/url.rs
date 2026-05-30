use crate::brand_rules::{self, BrandCategory, BrandRule};
use garuda_lists::{platform_list, safe_list};
use std::collections::HashSet;
use unicode_normalization::UnicodeNormalization;

/// Dangerous URI schemes that should be immediately blocked.
const DANGEROUS_SCHEMES: &[&str] = &[
    "javascript:",
    "data:",
    "blob:",
    "vbscript:",
    "ftp:",
];

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
    pub matched_token: String,
}

#[derive(Debug, Clone)]
pub struct UrlParts {
    pub original: String,
    pub normalized: String,
    pub scheme: String,
    pub host: String,
    pub path_and_query: String,
    pub has_userinfo: bool,
}

/// Returns true if the URL uses a dangerous scheme (data:, javascript:, blob:, etc.)
pub fn is_dangerous_scheme(url: &str) -> bool {
    let lower = url.trim().to_lowercase();
    DANGEROUS_SCHEMES.iter().any(|s| lower.starts_with(s))
}

pub fn parse_url(input: &str) -> UrlParts {
    let original = input.trim().to_string();
    
    // Strip internal tab and newline characters that browsers ignore
    let stripped: String = original
        .chars()
        .filter(|&c| c != '\t' && c != '\r' && c != '\n')
        .collect();

    // Percent-decode before normalization so %XX-encoded characters are resolved
    let decoded = percent_decode(&stripped);
    
    // Normalize backslashes to forward slashes in pre-query/pre-fragment parts (mimicking WHATWG browser normalizations)
    let slashes_normalized = normalize_slashes(&decoded);
    
    let normalized = slashes_normalized.nfkc().collect::<String>().to_lowercase();

    // Extract scheme
    let scheme = if let Some(idx) = normalized.find("://") {
        normalized[..idx].to_string()
    } else if let Some(idx) = normalized.find(':') {
        normalized[..idx].to_string()
    } else {
        String::new()
    };

    let without_scheme = normalized
        .strip_prefix("https://")
        .or_else(|| normalized.strip_prefix("http://"))
        .unwrap_or(&normalized);
    let (authority, path_and_query) = {
        let mut auth = without_scheme;
        let mut rest = String::new();
        if let Some(idx) = without_scheme.find(['/', '?', '#']) {
            auth = &without_scheme[..idx];
            rest = without_scheme[idx..].to_string();
        }
        (auth, rest)
    };
    let has_userinfo = authority.contains('@');
    let without_credentials = authority.rsplit_once('@').map(|(_, tail)| tail).unwrap_or(authority);
    let without_www = without_credentials.strip_prefix("www.").unwrap_or(without_credentials);

    let host = without_www
        .split(':')
        .next()
        .unwrap_or(without_www)
        .trim_end_matches('.')
        .to_string();

    UrlParts {
        original,
        normalized,
        scheme,
        host,
        path_and_query,
        has_userinfo,
    }
}

/// Decode percent-encoded characters (%XX) in a URL string.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                hex_val(bytes[i + 1]),
                hex_val(bytes[i + 2]),
            ) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

/// Helper to normalize backslashes to forward slashes in pre-query/pre-fragment parts of the URL.
fn normalize_slashes(url: &str) -> String {
    let mut parts = url.splitn(2, |c| c == '?' || c == '#');
    let pre_query = parts.next().unwrap_or("");
    let rest = parts.next();
    
    let pre_query_normalized = pre_query.replace('\\', "/");
    
    if let Some(r) = rest {
        let delimiter = if url.contains('?') && url.contains('#') {
            if url.find('?').unwrap() < url.find('#').unwrap() { '?' } else { '#' }
        } else if url.contains('?') {
            '?'
        } else {
            '#'
        };
        format!("{}{}{}", pre_query_normalized, delimiter, r)
    } else {
        pre_query_normalized
    }
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn is_domain_or_subdomain(host: &str, domain: &str) -> bool {
    let host = host.trim().to_lowercase();
    let domain = domain.trim().to_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

pub fn is_brand_owned_gtld(host: &str) -> bool {
    let host = host.trim().to_lowercase();
    host == "google" || host.ends_with(".google")
        || host == "apple" || host.ends_with(".apple")
        || host == "amazon" || host.ends_with(".amazon")
        || host == "microsoft" || host.ends_with(".microsoft")
}

pub fn is_brand_owned_gtld_for_brand(host: &str, brand: &str) -> bool {
    let host = host.trim().to_lowercase();
    let brand = brand.trim().to_lowercase();
    if (host == "google" || host.ends_with(".google")) && brand == "google" {
        return true;
    }
    if (host == "apple" || host.ends_with(".apple")) && brand == "apple" {
        return true;
    }
    if (host == "amazon" || host.ends_with(".amazon")) && brand == "amazon" {
        return true;
    }
    if (host == "microsoft" || host.ends_with(".microsoft")) && brand == "microsoft" {
        return true;
    }
    false
}

pub fn is_safe_domain(host: &str) -> bool {
    is_brand_owned_gtld(host) || safe_list::is_safe(host)
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
        if is_brand_owned_gtld_for_brand(&host, &rule.canonical) {
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

pub fn is_generic_keyword(token: &str) -> bool {
    const GENERIC_KEYWORDS: &[&str] = &[
        "recovery", "seed", "mnemonic", "wallet", "private", "otp", "kyc", "aadhaar", "aadhar", "pan",
        "login", "verify", "verification", "account", "auth", "payment", "banking", "netbanking", "refund",
        "billing", "support", "confirm", "secure", "update", "signin", "authenticate", "credential",
        "security", "portal", "check", "upgrade", "premium", "business", "bluebadge",
    ];
    GENERIC_KEYWORDS.contains(&token)
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
            return Some(build_match(rule, MatchType::Exact, 1.0, token.clone()));
        }

        if alias_values.iter().any(|alias| alias == token) {
            return Some(build_match(rule, MatchType::Alias, 0.95, token.clone()));
        }

        if token.len() >= 4 {
            let token_norm = normalize_token(token);
            if token_norm == canonical_norm && token != &canonical {
                return Some(build_match(rule, MatchType::Normalized, 0.92, token.clone()));
            }

            if alias_norms.iter().any(|alias| alias == &token_norm) {
                return Some(build_match(rule, MatchType::Normalized, 0.9, token.clone()));
            }

            let (homoglyph, changed) = normalize_homoglyphs_with_flags(token);
            if changed {
                if homoglyph == canonical || alias_values.iter().any(|alias| alias == &homoglyph) {
                    return Some(build_match(rule, MatchType::Homoglyph, 0.85, token.clone()));
                }
            }
        }

        if token.len() >= 5 {
            let token_norm = normalize_token(token);
            if let Some(distance) = strict_levenshtein_match(&token_norm, &canonical_norm) {
                let confidence = if distance == 1 { 0.82 } else { 0.80 };
                return Some(build_match(rule, MatchType::TypoDistance, confidence, token.clone()));
            }
        }
    }

    None
}

fn build_match(rule: &BrandRule, match_type: MatchType, confidence: f32, matched_token: String) -> BrandMatch {
    BrandMatch {
        brand: rule.canonical.to_string(),
        domain: rule.domain.to_string(),
        category: rule.category.clone(),
        risk: rule.risk,
        confidence,
        match_type,
        matched_token,
    }
}

fn tokenize_host(host: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    
    // 1. Add full labels split only by dot (normalized to strip hyphens/underscores)
    for label in host.split('.') {
        if !label.is_empty() {
            tokens.push(normalize_token(label));
            tokens.push(label.to_lowercase());
        }
    }
    
    // 2. Add sub-tokens split by hyphen, underscore, and dot
    for part in host.split(['.', '-', '_']) {
        if !part.is_empty() {
            tokens.extend(split_compound_token(part));
        }
    }
    
    // Deduplicate and remove empty
    tokens.retain(|t| !t.is_empty());
    tokens.sort();
    tokens.dedup();
    tokens
}

pub fn tokenize_for_keywords(value: &str) -> Vec<String> {
    value
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .flat_map(|token| split_compound_token(token))
        .collect()
}

fn normalize_token(token: &str) -> String {
    token
        .chars()
        .filter(|ch| ch.is_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

fn split_compound_token(token: &str) -> Vec<String> {
    let normalized = normalize_token(token);
    if !normalized.is_ascii() || normalized.len() < 8 {
        return vec![normalized];
    }

    let dictionary: HashSet<&'static str> = COMPOUND_WORDS.iter().copied().collect();
    let bytes = normalized.as_bytes();
    let len = bytes.len();
    let mut prev: Vec<Option<usize>> = vec![None; len + 1];
    prev[0] = Some(0);

    for i in 1..=len {
        for j in (0..i).rev() {
            if prev[j].is_some() {
                let slice = &normalized[j..i];
                if dictionary.contains(slice) {
                    prev[i] = Some(j);
                    break;
                }
            }
        }
    }

    if prev[len].is_none() {
        return vec![normalized];
    }

    let mut parts = Vec::new();
    let mut index = len;
    while index > 0 {
        let start = prev[index].unwrap_or(0);
        let part = normalized[start..index].to_string();
        parts.push(part);
        index = start;
    }
    parts.reverse();

    if parts.len() < 2 {
        return vec![normalized];
    }

    parts
}

const COMPOUND_WORDS: &[&str] = &[
    "account",
    "verify",
    "verification",
    "security",
    "check",
    "wallet",
    "connect",
    "signin",
    "login",
    "auth",
    "authentication",
    "portal",
    "support",
    "update",
    "recover",
    "recovery",
    "seed",
    "otp",
    "kyc",
    "bank",
    "payment",
    "billing",
    "paypal",
    "microsoft",
    "office365",
    "microsoftonline",
    "outlook",
    "appleid",
    "icloud",
    "gmail",
    "gdrive",
    "workspace",
    "aws",
    "primevideo",
    "linkedinpremium",
    "walletconnect",
    "githubauth",
];

fn is_noise_token(token: &str, host: &str) -> bool {
    const NOISE: &[&str] = &[
        "com", "org", "net", "in", "co", "io", "ai", "app", "dev", "gov", "edu", "nic",
        "ac", "res", "www", "vercel", "pages", "netlify", "web", "firebaseapp",
        "onrender", "herokuapp", "appspot", "cloud", "click", "me", "us", "to", "la",
        "it", "by", "do", "so", "my", "is", "ru", "cn", "xyz", "info", "mobi", "ga", "tv", "fm",
    ];

    if NOISE.contains(&token) {
        return true;
    }

    // Check if the token matches the TLD extension of the host (the last label)
    if let Some(tld) = host.split('.').last() {
        if token == tld {
            return true;
        }
    }
    
    // Check for double TLDs (e.g., .co.uk, .co.in, .gov.in)
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 3 {
        let tld = labels[labels.len() - 1];
        let sub_tld = labels[labels.len() - 2];
        if (token == tld || token == sub_tld) && (tld == "uk" || tld == "in" || tld == "jp" || tld == "kr" || tld == "br" || tld == "ru" || tld == "tr" || tld == "za" || tld == "cn" || tld == "id" || tld == "pk" || tld == "bd" || tld == "ae") {
            return true;
        }
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

    // For short brand names (length 5), restrict Levenshtein distance to 1
    // to prevent loose matching errors on generic keywords (e.g. click matching slack)
    if brand.len() == 5 && distance > 1 {
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
            // Cyrillic Lookalikes
            'а' | 'А' | 'α' | 'Α' => 'a',
            'е' | 'Е' | 'ε' | 'Ε' => 'e',
            'о' | 'О' | 'ο' | 'Ο' => 'o',
            'р' | 'Р' | 'ρ' | 'Ρ' => 'p',
            'с' | 'С' => 'c',
            'у' | 'У' | 'υ' | 'Υ' => 'y',
            'х' | 'Х' | 'χ' | 'Χ' => 'x',
            'і' | 'І' | 'ι' | 'Ι' => 'l',
            'ѕ' | 'Ѕ' => 's',
            'ј' | 'Ј' => 'j',
            'н' | 'Н' | 'η' | 'Η' => 'h',
            'м' | 'М' | 'μ' | 'Μ' => 'm',
            'к' | 'К' | 'κ' | 'Κ' => 'k',
            'т' | 'Т' | 'τ' | 'Τ' => 't',
            'в' | 'В' | 'ν' | 'Ν' => 'v',
            'з' | 'З' => 'z',
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
    pub has_wallet_keyword: bool,
    pub has_recovery_keyword: bool,
    pub has_login_keyword: bool,
    pub has_verify_keyword: bool,
    pub has_otp_keyword: bool,
}

pub fn analyze_context(
    host: &str,
    path_query: &str,
    reasons: &[String],
    brand_matches: &[BrandMatch],
) -> SuspiciousContext {
    let path = match path_query.split_once('?') {
        Some((p, _)) => p,
        None => path_query,
    };
    let combined = format!("{}{}", host.to_lowercase(), path.to_lowercase());
    
    let financial_keywords = &[
        "bank", "payment", "wallet", "refund", "kyc", "pan", "ifsc", "netbanking",
        "billing", "upi",
    ];
    let auth_keywords = &[
        "login", "verify", "password", "auth", "account", "confirm", "otp", "signin",
    ];
    let crypto_keywords = &["seed", "phrase", "recovery", "private", "key", "mnemonic"];
    let wallet_keywords = &["wallet", "walletconnect"];
    let recovery_keywords = &["recovery", "seed", "mnemonic", "phrase"];
    let login_keywords = &["login", "signin", "authentication", "auth"];
    let verify_keywords = &["verify", "verification", "confirm"];
    let otp_keywords = &["otp", "one-time", "onetime"];

    let has_brand = brand_matches.iter().any(|m| {
        !(matches!(m.match_type, MatchType::TypoDistance) && is_generic_keyword(&m.matched_token))
    }) || (reasons.iter().any(|r| r.contains("brand_impersonation")) && !brand_matches.iter().any(|m| {
        matches!(m.match_type, MatchType::TypoDistance) && is_generic_keyword(&m.matched_token)
    }));

    let has_financial_keyword = financial_keywords.iter().any(|kw| combined.contains(kw));
    let has_auth_keyword = auth_keywords.iter().any(|kw| combined.contains(kw));
    let has_crypto_keyword = crypto_keywords.iter().any(|kw| combined.contains(kw));
    let has_wallet_keyword = wallet_keywords.iter().any(|kw| combined.contains(kw));
    let has_recovery_keyword = recovery_keywords.iter().any(|kw| combined.contains(kw));
    let has_login_keyword = login_keywords.iter().any(|kw| combined.contains(kw));
    let has_verify_keyword = verify_keywords.iter().any(|kw| combined.contains(kw));
    let has_otp_keyword = otp_keywords.iter().any(|kw| combined.contains(kw));
    let has_free_hosting = reasons.iter().any(|r| r.contains("free_platform") || r.contains("suspicious_hosting"));

    let brand_name = brand_matches
        .iter()
        .find(|m| !(matches!(m.match_type, MatchType::TypoDistance) && is_generic_keyword(&m.matched_token)))
        .map(|item| item.brand.clone())
        .or_else(|| {
            reasons
                .iter()
                .find(|r| r.contains("brand_impersonation"))
                .and_then(|r| r.split(':').nth(1).map(|s| s.to_string()))
        });

    let brand_categories = brand_matches
        .iter()
        .filter(|m| !(matches!(m.match_type, MatchType::TypoDistance) && is_generic_keyword(&m.matched_token)))
        .map(|item| item.category.clone())
        .collect();

    let brand_risk = brand_matches
        .iter()
        .filter(|m| !(matches!(m.match_type, MatchType::TypoDistance) && is_generic_keyword(&m.matched_token)))
        .map(|item| item.risk)
        .max();

    SuspiciousContext {
        has_brand,
        has_financial_keyword,
        has_auth_keyword,
        has_crypto_keyword,
        has_free_hosting,
        brand_name,
        brand_categories,
        brand_risk,
        has_wallet_keyword,
        has_recovery_keyword,
        has_login_keyword,
        has_verify_keyword,
        has_otp_keyword,
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

    if context.has_wallet_keyword && context.has_recovery_keyword {
        bonus += 0.7;
    }

    if context.has_brand && context.has_login_keyword {
        bonus += 0.5;
    }

    if context.has_brand && context.has_verify_keyword {
        bonus += 0.4;
    }

    if context.brand_categories.contains(&BrandCategory::Bank)
        && context.has_login_keyword
        && context.has_otp_keyword
    {
        bonus += 0.9;
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

    bonus = bonus.min(1.8);
    let adjusted = (base_score as f32 * (1.0 + bonus)).round() as u8;
    adjusted.min(100)
}
