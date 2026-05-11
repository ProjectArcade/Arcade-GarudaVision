use crate::url;

pub fn check(url: &str) -> (u8, Vec<String>) {
    let parts = url::parse_url(url);

    for brand in url::brand_candidates(&parts.host) {
        let legit_domain = url::brand_legit_domain(brand);
        let is_legit = legit_domain
            .map(|domain| url::is_domain_or_subdomain(&parts.host, domain))
            .unwrap_or(false);

        if !is_legit {
            let points = if legit_domain.is_some() { 35 } else { 20 };
            return (points, vec![format!("brand_mismatch:{}", brand)]);
        }
    }

    (0, vec![])
}
