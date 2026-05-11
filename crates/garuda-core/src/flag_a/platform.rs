use crate::url;

pub fn check(url: &str) -> (u8, Vec<String>) {
    let parts = url::parse_url(url);
    for platform in url::is_free_platform(&parts.host).then_some(parts.host.as_str()) {
        return (30, vec![format!("free_platform:{}", platform)]);
    }

    if url::is_free_platform(&parts.host) {
        return (30, vec![format!("free_platform:{}", parts.host)]);
    }

    for platform in ["vercel.app", "netlify.app", "github.io", "pages.dev", "glitch.me", "replit.dev", "render.com", "fly.dev"] {
        if url::is_domain_or_subdomain(&parts.host, platform) {
            return (30, vec![format!("free_platform:{}", platform)]);
        }
    }

    (0, vec![])
}
