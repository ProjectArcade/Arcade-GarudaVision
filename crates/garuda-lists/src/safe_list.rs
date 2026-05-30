use crate::engine;

/// Check if a domain (or any parent domain) is a known safe domain.
/// Uses the high-performance Bloom filter + FxHashSet engine for O(1) lookups.
pub fn is_safe(domain: &str) -> bool {
    engine::is_known_domain(domain)
}
