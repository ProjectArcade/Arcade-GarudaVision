use crate::url;

pub fn check(url: &str) -> (u8, Vec<String>) {
    let mut keyword_score: u8 = 0;
    let mut reasons = Vec::new();
    for kw in url::keyword_hits(url) {
        if !reasons.iter().any(|reason| reason == &format!("keyword:{}", kw)) {
            keyword_score = keyword_score.saturating_add(15);
            reasons.push(format!("keyword:{}", kw));
        }
    }
    let final_score = keyword_score.min(30);
    (final_score, reasons)
}
