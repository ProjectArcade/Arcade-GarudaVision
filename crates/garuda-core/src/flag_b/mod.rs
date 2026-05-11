pub mod dom;
pub mod form;
pub mod favicon;


pub fn analyse(html: &str, domain: &str) -> (u8, Vec<String>) {
    let mut score: u8 = 0;
    let mut reasons = Vec::new();

    let (s, r) = dom::check(html, domain);
    score = score.saturating_add(s);
    reasons.extend(r);

    let (s, r) = form::check(html, domain);
    score = score.saturating_add(s);
    reasons.extend(r);

    let (s, r) = favicon::check(html, domain);
    score = score.saturating_add(s);
    reasons.extend(r);

    (score, reasons)
}
