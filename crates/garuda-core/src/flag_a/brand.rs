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

    // If no host matches found, check the path (excluding query) for brand names
    let path = match parts.path_and_query.split_once('?') {
        Some((p, _)) => p,
        None => &parts.path_and_query,
    };
    if matches.is_empty() && !path.is_empty() {
        let tokens = url::tokenize_for_keywords(path);
        let rules = brand_rules::get_rules();
        for rule in rules.rules.iter() {
            if url::is_domain_or_subdomain(&parts.host, &rule.domain) {
                continue;
            }
            let canonical_lower = rule.canonical.to_lowercase();
            let alias_lowers: Vec<String> =
                rule.aliases.iter().map(|a| a.to_lowercase()).collect();
            
            let mut matched_token = false;
            let mut matched_token_str = String::new();
            let mut is_alias = false;
            for token in &tokens {
                let token_lower = token.to_lowercase();
                if token_lower == canonical_lower {
                    matched_token = true;
                    matched_token_str = token.clone();
                    break;
                } else if alias_lowers.iter().any(|a| *a == token_lower) {
                    matched_token = true;
                    matched_token_str = token.clone();
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
                    matched_token: matched_token_str,
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
    // If it's a TypoDistance match on a generic keyword (e.g. verify -> veriff),
    // cap the base score and risk boost so that it flags as Caution, but does NOT block.
    if matches!(brand_match.match_type, MatchType::TypoDistance) && url::is_generic_keyword(&brand_match.matched_token) {
        let base = 30u8;
        let risk_boost = ((brand_match.risk as f32) * 0.2).round() as u8;
        return base.saturating_add(risk_boost);
    }

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
