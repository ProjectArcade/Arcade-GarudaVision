use crate::url;

pub fn check(url: &str) -> (u8, Vec<String>) {
    let parts = url::parse_url(url);
    if let Some(platform) = matched_platform(&parts.host) {
        return (45, vec![format!("suspicious_hosting:{}", platform)]);
    }

    (0, vec![])
}

fn matched_platform(host: &str) -> Option<&'static str> {
    const PLATFORMS: &[&str] = &[
        "vercel.app",
        "netlify.app",
        "github.io",
        "pages.dev",
        "glitch.me",
        "replit.dev",
        "render.com",
        "fly.dev",
        "firebaseapp.com",
        "web.app",
        "appspot.com",
    ];

    PLATFORMS
        .iter()
        .copied()
        .find(|platform| url::is_domain_or_subdomain(host, platform))
}
