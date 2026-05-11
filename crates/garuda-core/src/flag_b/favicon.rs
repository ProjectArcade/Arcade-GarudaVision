pub fn check(html: &str, domain: &str) -> (u8, Vec<String>) {
    let html_lower = html.to_lowercase();
    if !html_lower.contains("rel=\"icon\"")
        && !html_lower.contains("rel='icon'")
        && !html_lower.contains("shortcut icon")
    {
        return (0, vec![]);
    }

    let mut search = html_lower.as_str();
    while let Some(idx) = search.find("href=") {
        let after = &search[idx + "href=".len()..];
        let after = after.trim_start();
        let (value, rest) = if let Some(rest) = after.strip_prefix('"') {
            match rest.split_once('"') {
                Some((value, tail)) => (value, tail),
                None => (rest, ""),
            }
        } else if let Some(rest) = after.strip_prefix('\'') {
            match rest.split_once('\'') {
                Some((value, tail)) => (value, tail),
                None => (rest, ""),
            }
        } else {
            match after.split_once(|ch: char| ch.is_whitespace() || ch == '>') {
                Some((value, tail)) => (value, tail),
                None => (after, ""),
            }
        };

        let value = value.trim();
        if (value.starts_with("http://") || value.starts_with("https://")) && !value.contains(domain) {
            return (10, vec![format!("external_favicon:{}", value)]);
        }

        search = rest;
    }

    (0, vec![])
}
