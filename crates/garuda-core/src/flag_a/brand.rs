use crate::url;

pub fn check(url: &str) -> (u8, Vec<String>) {
    let parts = url::parse_url(url);
    
    for brand in url::brand_candidates(&parts.host) {
        let legit_domain = url::brand_legit_domain(brand);
        let is_legit = legit_domain
            .map(|domain| url::is_domain_or_subdomain(&parts.host, domain))
            .unwrap_or(false);

        if !is_legit {
            let points = if legit_domain.is_some() { 40 } else { 20 };
            return (points, vec![format!("brand_impersonation:{}", brand)]);
        }
    }

    let host_normalized = url::normalize_homoglyphs(&parts.host);
    for brand in url::brand_candidates(&host_normalized) {
        if contains_brand_as_word(&host_normalized, brand) {
            let legit_domain = url::brand_legit_domain(brand);
            let is_legit = legit_domain
                .map(|domain| url::is_domain_or_subdomain(&host_normalized, domain))
                .unwrap_or(false);
            
            if !is_legit {
                return (50, vec![format!("brand_impersonation:{}", brand)]);
            }
        }
    }

    (0, vec![])
}

fn contains_brand_as_word(host: &str, brand: &str) -> bool {
    let separators = ['-', '.', '_'];
    if host.contains(brand) {
        let brand_len = brand.len();
        for (i, _) in host.match_indices(brand) {
            let before_ok = i == 0 || separators.contains(&host.chars().nth(i - 1).unwrap_or('a'));
            let after_ok = (i + brand_len >= host.len())
                || separators.contains(&host.chars().nth(i + brand_len).unwrap_or('a'));
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}
