use crate::url;

pub fn check(url: &str) -> (u8, Vec<String>) {
    let parts = url::parse_url(url);
    if url::is_free_platform(&parts.host) {
        return (30, vec![format!("free_platform:{}", parts.host)]);
    }

    (0, vec![])
}
