use crate::bloom::BloomFilter;
use crate::segments::{self, DomainCategory};
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::OnceLock;

struct EngineData {
    bloom: BloomFilter,
    exact: FxHashSet<String>,
    categories: FxHashMap<String, DomainCategory>,
}

static ENGINE: OnceLock<EngineData> = OnceLock::new();

fn get_engine() -> &'static EngineData {
    ENGINE.get_or_init(|| {
        let segs = segments::all_segments();
        let mut all_domains: Vec<(String, DomainCategory)> = Vec::new();

        for (cat, content) in &segs {
            for line in segments::parse_lines(content) {
                let domain = line.to_lowercase();
                all_domains.push((domain, *cat));
            }
        }

        // Size bloom filter: 10 bits per element, 7 hash functions (optimal for <1% FPR)
        let n = all_domains.len().max(1);
        let num_bits = n * 10;
        let mut bloom = BloomFilter::new(num_bits, 7);
        let mut exact = FxHashSet::default();
        let mut categories = FxHashMap::default();

        for (domain, cat) in &all_domains {
            bloom.insert(domain);
            exact.insert(domain.clone());
            categories.insert(domain.clone(), *cat);
        }

        EngineData {
            bloom,
            exact,
            categories,
        }
    })
}

/// Check if the given host (or any parent domain) is a known safe domain.
/// Uses Bloom filter for fast rejection, then exact hash set lookup,
/// then binary-search suffix matching for subdomain support.
pub fn is_known_domain(host: &str) -> bool {
    let engine = get_engine();
    let host = host.trim().to_lowercase();

    // Fast path: Bloom filter rejects most non-matching domains in O(1)
    if !engine.bloom.maybe_contains(&host) {
        // Check if any parent domain is in the bloom filter
        return check_parent_domains(&host, engine);
    }

    // Bloom says maybe: verify with exact hash set
    if engine.exact.contains(&host) {
        return true;
    }

    // Check parent domains (e.g., mail.google.com -> google.com)
    check_parent_domains(&host, engine)
}

fn check_parent_domains(host: &str, engine: &EngineData) -> bool {
    // Walk up the domain labels
    let mut remaining = host;
    while let Some(dot_pos) = remaining.find('.') {
        remaining = &remaining[dot_pos + 1..];
        if remaining.is_empty() {
            break;
        }
        if engine.bloom.maybe_contains(remaining) && engine.exact.contains(remaining) {
            if crate::platform_list::is_free_platform(remaining) {
                continue;
            }
            return true;
        }
    }
    false
}

/// Get the category for a domain (or its closest parent domain in the list).
pub fn domain_category(host: &str) -> Option<DomainCategory> {
    let engine = get_engine();
    let host = host.trim().to_lowercase();

    if let Some(cat) = engine.categories.get(&host) {
        return Some(*cat);
    }

    // Walk up parent domains
    let mut remaining = host.as_str();
    while let Some(dot_pos) = remaining.find('.') {
        remaining = &remaining[dot_pos + 1..];
        if remaining.is_empty() {
            break;
        }
        if let Some(cat) = engine.categories.get(remaining) {
            if crate::platform_list::is_free_platform(remaining) {
                continue;
            }
            return Some(*cat);
        }
    }

    None
}

/// Check if a domain belongs to a specific category.
pub fn is_known_in_category(host: &str, category: DomainCategory) -> bool {
    domain_category(host).map(|c| c == category).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_domains() {
        assert!(is_known_domain("google.com"));
        assert!(is_known_domain("sub.google.com"));
        assert!(is_known_domain("chase.com"));
        assert!(is_known_domain("sub.chase.com"));

        assert!(!is_known_domain("unknown-non-existent-domain.xyz"));
    }

    #[test]
    fn test_categories() {
        assert_eq!(domain_category("chase.com"), Some(DomainCategory::Finance));
        assert_eq!(domain_category("sub.chase.com"), Some(DomainCategory::Finance));
        assert_eq!(domain_category("google.com"), Some(DomainCategory::Tech));
        assert_eq!(domain_category("unknown-domain.xyz"), None);

        assert!(is_known_in_category("chase.com", DomainCategory::Finance));
        assert!(!is_known_in_category("chase.com", DomainCategory::Government));
    }
}
