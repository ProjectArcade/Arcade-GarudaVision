fn entries() -> impl Iterator<Item = &'static str> {
    include_str!("../../../lists/platforms.txt")
        .lines()
        .map(|line| {
            line.split('#')
                .next()
                .unwrap_or("")
                .trim()
        })
        .filter(|line| !line.is_empty())
}

pub fn platforms() -> impl Iterator<Item = &'static str> {
    entries()
}

/// Check if a domain is a free hosting platform.
/// Checks the dedicated platforms.txt list.
pub fn is_free_platform(domain: &str) -> bool {
    let domain = domain.trim().to_lowercase();
    // Check the dedicated platforms list (these are hosting platforms specifically)
    if entries().any(|line| domain == line || domain.ends_with(&format!(".{line}"))) {
        return true;
    }
    false
}
