use crate::url;

pub fn check(url: &str) -> (u8, Vec<String>) {
    let normalized = url::normalize_homoglyphs(url);
    
    if normalized != url.to_lowercase() {
        return (40, vec!["homoglyph_detected".to_string()]);
    }

    if url::has_punycode(url) || url::has_mixed_script(url) {
        return (40, vec!["homoglyph_detected".to_string()]);
    }

    (0, vec![])
}
