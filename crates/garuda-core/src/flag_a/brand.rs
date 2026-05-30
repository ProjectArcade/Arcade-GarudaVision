use crate::brand_rules;
use crate::url::{self, BrandMatch, MatchType};

pub struct BrandCheckResult {
    pub score: u8,
    pub reasons: Vec<String>,
    pub matches: Vec<BrandMatch>,
}

pub fn check(url: &str) -> BrandCheckResult {
    let parts = url::parse_url(url);
    let mut matches = url::find_brand_matches(&parts.host);
    let mut is_path_match = false;

    // If no host matches found, check the path/query for brand names
    if matches.is_empty() && !parts.path_and_query.is_empty() {
        let tokens = url::tokenize_for_keywords(&parts.path_and_query);
        let rules = brand_rules::get_rules();
        for rule in rules.rules.iter() {
            if url::is_domain_or_subdomain(&parts.host, &rule.domain) {
                continue;
            }
            let canonical_lower = rule.canonical.to_lowercase();
            let alias_lowers: Vec<String> =
                rule.aliases.iter().map(|a| a.to_lowercase()).collect();
            
            let mut matched_token = false;
            let mut is_alias = false;
            for token in &tokens {
                let token_lower = token.to_lowercase();
                if token_lower == canonical_lower {
                    matched_token = true;
                    break;
                } else if alias_lowers.iter().any(|a| *a == token_lower) {
                    matched_token = true;
                    is_alias = true;
                    break;
                }
            }

            if matched_token {
                let match_type = if is_alias {
                    MatchType::Alias
                } else {
                    MatchType::Exact
                };
                matches.push(BrandMatch {
                    brand: rule.canonical.clone(),
                    domain: rule.domain.clone(),
                    category: rule.category.clone(),
                    risk: rule.risk,
                    confidence: 0.7,
                    match_type,
                });
                is_path_match = true;
            }
        }
    }

    if matches.is_empty() {
        return BrandCheckResult {
            score: 0,
            reasons: Vec::new(),
            matches,
        };
    }

    let mut reasons = Vec::new();
    let mut highest = 0u8;
    let mut primary: Option<&BrandMatch> = None;

    for brand_match in matches.iter() {
        let mut score = match_score(brand_match);
        if is_path_match {
            score = ((score as f32) * 0.7).round() as u8;
        }
        
        let is_better = match primary {
            None => true,
            Some(prim) => {
                let prim_prio = match_type_priority(&prim.match_type);
                let curr_prio = match_type_priority(&brand_match.match_type);
                if curr_prio != prim_prio {
                    curr_prio > prim_prio
                } else {
                    score > highest
                }
            }
        };

        if is_better {
            highest = score;
            primary = Some(brand_match);
        }
    }

    if let Some(prim) = primary {
        reasons.push(format!("brand_impersonation:{}", prim.brand));
    }

    BrandCheckResult {
        score: highest,
        reasons,
        matches,
    }
}

fn match_type_priority(t: &MatchType) -> u8 {
    match t {
        MatchType::Exact => 5,
        MatchType::Alias => 4,
        MatchType::Normalized => 3,
        MatchType::Homoglyph => 2,
        MatchType::TypoDistance => 1,
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
