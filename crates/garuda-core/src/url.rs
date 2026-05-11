use garuda_lists::{brand_list, platform_list, safe_list};
use unicode_normalization::UnicodeNormalization;

const BRAND_RULES: &[(&str, &str)] = &[
    ("google", "google.com"),
    ("microsoft", "microsoft.com"),
    ("paypal", "paypal.com"),
    ("amazon", "amazon.com"),
    ("apple", "apple.com"),
    ("facebook", "facebook.com"),
    ("instagram", "instagram.com"),
    ("twitter", "twitter.com"),
    ("netflix", "netflix.com"),
    ("sbi", "sbi.co.in"),
    ("hdfc", "hdfcbank.com"),
    ("paytm", "paytm.com"),
    ("icici", "icicibank.com"),
    ("airtel", "airtel.in"),
    ("jio", "jio.com"),
];

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

pub fn brand_candidates(host: &str) -> Vec<&'static str> {
    let host = host.to_lowercase();
    let squashed = squash_common_typos(&host);
    let mut candidates = brand_list::brands()
        .filter(|brand| host.contains(brand) || squashed.contains(brand))
        .collect::<Vec<_>>();
    
    for brand in brand_list::brands() {
        if !candidates.contains(&brand) && is_brand_typo(&host, brand) {
            candidates.push(brand);
        }
    }
    
    candidates
}

fn is_brand_typo(test_str: &str, brand: &str) -> bool {
    let distance = levenshtein_distance(test_str, brand);
    let max_allowed = (brand.len() as f32 * 0.3).ceil() as usize;
    distance <= max_allowed && distance > 0
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

fn squash_common_typos(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;

    while index < chars.len() {
        if index + 1 < chars.len() {
            match (chars[index], chars[index + 1]) {
                ('r', 'n') => {
                    out.push('m');
                    index += 2;
                    continue;
                }
                ('v', 'v') => {
                    out.push('w');
                    index += 2;
                    continue;
                }
                ('c', 'l') => {
                    out.push('d');
                    index += 2;
                    continue;
                }
                _ => {}
            }
        }

        match chars[index] {
            '0' => out.push('o'),
            '1' => out.push('l'),
            '3' => out.push('e'),
            '5' => out.push('s'),
            '7' => out.push('t'),
            ch => out.push(ch),
        }

        index += 1;
    }

    out
}

pub fn brand_legit_domain(brand: &str) -> Option<&'static str> {
    BRAND_RULES.iter().find_map(|(known_brand, legit)| {
        if known_brand.eq_ignore_ascii_case(brand) {
            Some(*legit)
        } else {
            None
        }
    })
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
        "auth",
        "credential",
        "authenticate",
        "kyc",
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
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;

    while index < chars.len() {
        match chars[index] {
            'I' | 'l' | 'L' | '1' | '|' => out.push('l'),
            'O' | '0' => out.push('o'),
            'S' | '5' => out.push('s'),
            'Z' | '2' => out.push('z'),
            'B' | '8' => out.push('b'),
            'G' | '9' => out.push('g'),
            'T' | '7' => out.push('t'),
            'E' | '3' => out.push('e'),
            'a' | '@' => out.push('a'),
            ch => out.push(ch),
        }
        index += 1;
    }

    out
}

#[derive(Debug, Clone)]
pub struct SuspiciousContext {
    pub has_brand: bool,
    pub has_financial_keyword: bool,
    pub has_auth_keyword: bool,
    pub has_crypto_keyword: bool,
    pub has_free_hosting: bool,
    pub brand_name: Option<String>,
}

pub fn analyze_context(host: &str, path_query: &str, reasons: &[String]) -> SuspiciousContext {
    let combined = format!("{}{}", host.to_lowercase(), path_query.to_lowercase());
    
    let financial_keywords = &["bank", "payment", "wallet", "refund", "kyc", "pan", "ifsc"];
    let auth_keywords = &["login", "verify", "password", "auth", "account", "confirm"];
    let crypto_keywords = &["seed", "phrase", "recovery", "private", "key", "mnemonic"];

    let has_brand = reasons.iter().any(|r| r.contains("brand_") || r.contains("impersonation"));
    let has_financial_keyword = financial_keywords.iter().any(|kw| combined.contains(kw));
    let has_auth_keyword = auth_keywords.iter().any(|kw| combined.contains(kw));
    let has_crypto_keyword = crypto_keywords.iter().any(|kw| combined.contains(kw));
    let has_free_hosting = reasons.iter().any(|r| r.contains("free_platform") || r.contains("suspicious_hosting"));

    let brand_name = reasons
        .iter()
        .find(|r| r.contains("brand_"))
        .and_then(|r| r.split(':').nth(1).map(|s| s.to_string()));

    SuspiciousContext {
        has_brand,
        has_financial_keyword,
        has_auth_keyword,
        has_crypto_keyword,
        has_free_hosting,
        brand_name,
    }
}

pub fn apply_contextual_multiplier(base_score: u8, context: &SuspiciousContext) -> u8 {
    let mut multiplier = 1.0;

    if context.has_brand && context.has_free_hosting {
        multiplier *= 2.5;
    }

    if context.has_brand && context.has_financial_keyword {
        multiplier *= 2.0;
    }

    if context.has_free_hosting && context.has_auth_keyword {
        multiplier *= 1.8;
    }

    if context.has_financial_keyword && context.has_auth_keyword {
        multiplier *= 1.5;
    }

    if context.has_crypto_keyword && context.has_auth_keyword {
        multiplier *= 2.2;
    }

    let adjusted = (base_score as f64 * multiplier) as u8;
    adjusted.min(100)
}
