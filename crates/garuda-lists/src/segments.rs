#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainCategory {
    Finance,
    Government,
    Tech,
    Media,
    Commerce,
}

pub fn all_segments() -> Vec<(DomainCategory, &'static str)> {
    vec![
        (DomainCategory::Finance, include_str!("../../../lists/segments/finance.txt")),
        (DomainCategory::Government, include_str!("../../../lists/segments/government.txt")),
        (DomainCategory::Tech, include_str!("../../../lists/segments/tech.txt")),
        (DomainCategory::Media, include_str!("../../../lists/segments/media.txt")),
        (DomainCategory::Commerce, include_str!("../../../lists/segments/commerce.txt")),
    ]
}

pub fn parse_lines<'a>(content: &'a str) -> impl Iterator<Item = String> + 'a {
    content
        .lines()
        .map(|line| {
            line.split('#')
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        })
        .filter(|line| !line.is_empty())
}
