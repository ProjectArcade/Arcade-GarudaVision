use crate::url;

pub fn check(url: &str) -> (u8, Vec<String>) {
    let url_lower = url.to_lowercase();
    let tokens = url::tokenize_for_keywords(&url_lower);
    let mut score: u8 = 0;
    let mut reasons = Vec::new();

    let critical_keywords = &[
        ("recovery", 35u8),
        ("seed", 35),
        ("mnemonic", 35),
        ("wallet", 32),
        ("private", 30),
        ("otp", 30),
        ("kyc", 30),
        ("aadhaar", 30),
        ("aadhar", 30),
        ("pan", 28),
    ];
    
    let high_keywords = &[
        ("login", 22u8),
        ("verify", 22),
        ("verification", 22),
        ("account", 20),
        ("auth", 20),
        ("payment", 20),
        ("banking", 20),
        ("netbanking", 20),
        ("refund", 20),
        ("billing", 18),
        ("support", 18),
    ];
    
    let medium_keywords = &[
        ("confirm", 12u8),
        ("secure", 12),
        ("update", 12),
        ("signin", 12),
        ("authenticate", 12),
        ("credential", 12),
        ("security", 12),
        ("portal", 12),
        ("check", 12),
        ("upgrade", 12),
        ("premium", 12),
        ("business", 12),
        ("bluebadge", 12),
    ];

    for (kw, points) in critical_keywords {
        if (if kw.len() >= 5 { url_lower.contains(kw) } else { false } || tokens.iter().any(|token| token == kw))
            && !reasons.iter().any(|r| r == &format!("suspicious_keyword:{}", kw))
        {
            score = score.saturating_add(*points);
            reasons.push(format!("suspicious_keyword:{}", kw));
        }
    }

    for (kw, points) in high_keywords {
        if (if kw.len() >= 5 { url_lower.contains(kw) } else { false } || tokens.iter().any(|token| token == kw))
            && !reasons.iter().any(|r| r == &format!("suspicious_keyword:{}", kw))
        {
            score = score.saturating_add(*points);
            reasons.push(format!("suspicious_keyword:{}", kw));
        }
    }

    for (kw, points) in medium_keywords {
        if (if kw.len() >= 5 { url_lower.contains(kw) } else { false } || tokens.iter().any(|token| token == kw))
            && !reasons.iter().any(|r| r == &format!("suspicious_keyword:{}", kw))
        {
            score = score.saturating_add(*points);
            reasons.push(format!("suspicious_keyword:{}", kw));
        }
    }

    score = score.min(50);
    (score, reasons)
}

pub fn check_query(query: &str) -> (u8, Vec<String>) {
    let query_lower = query.to_lowercase();
    // If the query looks like a standard OAuth flow (contains redirect_uri=, client_id=, scope=, iss=, state=),
    // we should completely ignore it, to avoid SSO false positives on any domain!
    if query_lower.contains("client_id=")
        || query_lower.contains("redirect_uri=")
        || query_lower.contains("scope=")
        || query_lower.contains("state=")
        || query_lower.contains("response_type=")
        || query_lower.contains("code=")
        || query_lower.contains("iss=")
    {
        return (0, Vec::new());
    }

    let tokens = url::tokenize_for_keywords(&query_lower);
    let mut score: u8 = 0;
    let mut reasons = Vec::new();

    let critical_keywords = &[
        ("recovery", 8u8),
        ("seed", 8),
        ("mnemonic", 8),
        ("wallet", 8),
        ("private", 6),
        ("otp", 6),
        ("kyc", 6),
        ("aadhaar", 6),
        ("aadhar", 6),
        ("pan", 6),
    ];
    
    let high_keywords = &[
        ("login", 5u8),
        ("verify", 5),
        ("verification", 5),
        ("account", 4),
        ("auth", 4),
        ("payment", 4),
        ("banking", 4),
        ("netbanking", 4),
        ("refund", 4),
        ("billing", 4),
        ("support", 4),
    ];
    
    let medium_keywords = &[
        ("confirm", 2u8),
        ("secure", 2),
        ("update", 2),
        ("signin", 2),
        ("authenticate", 2),
        ("credential", 2),
        ("security", 2),
        ("portal", 2),
        ("check", 2),
        ("upgrade", 2),
        ("premium", 2),
        ("business", 2),
        ("bluebadge", 2),
    ];

    for (kw, points) in critical_keywords {
        if (if kw.len() >= 5 { query_lower.contains(kw) } else { false } || tokens.iter().any(|token| token == kw))
            && !reasons.iter().any(|r| r == &format!("suspicious_keyword:{}", kw))
        {
            score = score.saturating_add(*points);
            reasons.push(format!("suspicious_keyword:{}", kw));
        }
    }

    for (kw, points) in high_keywords {
        if (if kw.len() >= 5 { query_lower.contains(kw) } else { false } || tokens.iter().any(|token| token == kw))
            && !reasons.iter().any(|r| r == &format!("suspicious_keyword:{}", kw))
        {
            score = score.saturating_add(*points);
            reasons.push(format!("suspicious_keyword:{}", kw));
        }
    }

    for (kw, points) in medium_keywords {
        if (if kw.len() >= 5 { query_lower.contains(kw) } else { false } || tokens.iter().any(|token| token == kw))
            && !reasons.iter().any(|r| r == &format!("suspicious_keyword:{}", kw))
        {
            score = score.saturating_add(*points);
            reasons.push(format!("suspicious_keyword:{}", kw));
        }
    }

    score = score.min(15);
    (score, reasons)
}
