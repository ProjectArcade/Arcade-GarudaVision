pub fn check(html: &str, domain: &str) -> (u8, Vec<String>) {
    let html_lower = html.to_lowercase();
    let has_password = html_lower.contains("type=\"password\"") || html_lower.contains("type='password'");
    let form_points_elsewhere = html_lower.contains("action=") && !html_lower.contains(domain);
    if has_password && form_points_elsewhere {
        return (30, vec!["credential_form_mismatch".to_string()]);
    }
    (0, vec![])
}
