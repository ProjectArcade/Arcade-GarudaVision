use crate::url::{self, BrandMatch, MatchType};

pub struct BrandCheckResult {
    pub score: u8,
    pub reasons: Vec<String>,
    pub matches: Vec<BrandMatch>,
}

pub fn check(url: &str) -> BrandCheckResult {
    let parts = url::parse_url(url);
    let matches = url::find_brand_matches(&parts.host);
    if matches.is_empty() {
        return BrandCheckResult {
            score: 0,
            reasons: Vec::new(),
            matches,
        };
    }

    let mut reasons = Vec::new();
    let mut highest = 0u8;
    let mut primary = None;

    for brand_match in matches.iter() {
        let score = match_score(brand_match);
        if score > highest {
            highest = score;
            primary = Some(brand_match);
        }
    }

    if let Some(primary) = primary {
        reasons.push(format!("brand_impersonation:{}", primary.brand));
    }

    BrandCheckResult {
        score: highest,
        reasons,
        matches,
    }
}

fn match_score(brand_match: &BrandMatch) -> u8 {
    let base: u8 = match brand_match.match_type {
        MatchType::Exact => 45,
        MatchType::Alias => 45,
        MatchType::Normalized => 50,
        MatchType::Homoglyph => 60,
        MatchType::TypoDistance => 65,
    };

    let risk_boost = ((brand_match.risk as f32) * 0.3).round() as u8;
    base.saturating_add(risk_boost).min(90)
}
