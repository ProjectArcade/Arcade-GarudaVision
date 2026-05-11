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

pub fn brand_candidates(host: &str) -> Vec<&'static str> {
    let host = host.to_lowercase();
    let squashed = squash_common_typos(&host);
    brand_list::brands()
        .filter(|brand| host.contains(brand) || squashed.contains(brand))
        .collect()
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
