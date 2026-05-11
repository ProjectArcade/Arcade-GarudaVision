const BRAND_ASSETS: &[&str] = &["accounts.google.com", "microsoft.com", "paypal.com", "amazon.com"];

pub fn check(html: &str, domain: &str) -> (u8, Vec<String>) {
    let html_lower = html.to_lowercase();
    let has_password = html_lower.contains("type=\"password\"")
        || html_lower.contains("type='password'")
        || html_lower.contains("autocomplete=\"current-password\"")
        || html_lower.contains("autocomplete='current-password'")
        || html_lower.contains("autocomplete=\"new-password\"")
        || html_lower.contains("autocomplete='new-password'");

    if has_password && form_action_mismatch(&html_lower, domain) {
        return (30, vec!["credential_form_mismatch".to_string()]);
    }

    (0, vec![])
}

fn form_action_mismatch(html: &str, domain: &str) -> bool {
    let mut search = html;

    while let Some(idx) = search.find("action=") {
        let after = &search[idx + "action=".len()..];
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
            return true;
        }

        search = rest;
    }

    false
        if html_lower.contains(asset) {
            return (30, vec![format!("brand_asset_impersonation:{}", asset)]);
        }
    }
    (0, vec![])
}
