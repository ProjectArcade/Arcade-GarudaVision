fn entries() -> impl Iterator<Item = &'static str> {
    include_str!("../../../lists/platforms.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
}

pub fn platforms() -> impl Iterator<Item = &'static str> {
    entries()
}

pub fn is_free_platform(domain: &str) -> bool {
    let domain = domain.trim().to_lowercase();
    entries().any(|line| domain == line || domain.ends_with(&format!(".{line}")))
}
