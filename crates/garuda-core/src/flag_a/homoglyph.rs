use crate::url;

pub fn check(url: &str) -> (u8, Vec<String>) {
    if url::has_punycode(url) || url::has_mixed_script(url) {
        return (40, vec!["homoglyph_detected".to_string()]);
    }

    (0, vec![])
}
