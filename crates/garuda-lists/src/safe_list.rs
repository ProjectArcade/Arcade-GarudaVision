fn entries() -> impl Iterator<Item = &'static str> {
    include_str!("../../../lists/safe_top10k.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
}

pub fn safe_domains() -> impl Iterator<Item = &'static str> {
    entries()
}

pub fn is_safe(domain: &str) -> bool {
    let domain = domain.trim().to_lowercase();
    entries().any(|line| domain == line || domain.ends_with(&format!(".{line}")))
}
