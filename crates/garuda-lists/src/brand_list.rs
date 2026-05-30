fn entries() -> Vec<String> {
    let mut brands = Vec::new();
    for line in include_str!("../../../lists/brands.txt").lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let content = line.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }

        let parts: Vec<&str> = content.split('|').map(|s| s.trim()).collect();
        if parts.is_empty() {
            continue;
        }

        let canonical = parts[0];
        if !canonical.is_empty() {
            brands.push(canonical.to_lowercase());
        }

        if parts.len() > 2 {
            for alias in parts[2].split(',') {
                let alias = alias.trim();
                if !alias.is_empty() {
                    brands.push(alias.to_lowercase());
                }
            }
        }
    }

    brands.sort();
    brands.dedup();
    brands
}

pub fn brands() -> impl Iterator<Item = String> {
    entries().into_iter()
}

pub fn is_brand(word: &str) -> bool {
    let word = word.trim().to_lowercase();
    entries().iter().any(|b| b == &word)
}
