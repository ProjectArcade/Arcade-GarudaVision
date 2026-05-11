fn entries() -> impl Iterator<Item = &'static str> {
    include_str!("../../../lists/brands.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
}

pub fn brands() -> impl Iterator<Item = &'static str> {
    entries()
}

pub fn is_brand(word: &str) -> bool {
    let word = word.trim();
    entries().any(|line| line.eq_ignore_ascii_case(word))
}
