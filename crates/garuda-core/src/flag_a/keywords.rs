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
        if (url_lower.contains(kw) || tokens.iter().any(|token| token == kw))
            && !reasons.iter().any(|r| r == &format!("suspicious_keyword:{}", kw))
        {
            score = score.saturating_add(*points);
            reasons.push(format!("suspicious_keyword:{}", kw));
        }
    }

    if score < 20 {
        for (kw, points) in high_keywords {
            if (url_lower.contains(kw) || tokens.iter().any(|token| token == kw))
                && !reasons.iter().any(|r| r == &format!("suspicious_keyword:{}", kw))
            {
                score = score.saturating_add(*points);
                reasons.push(format!("suspicious_keyword:{}", kw));
            }
        }
    }

    if score < 30 {
        for (kw, points) in medium_keywords {
            if (url_lower.contains(kw) || tokens.iter().any(|token| token == kw))
                && !reasons.iter().any(|r| r == &format!("suspicious_keyword:{}", kw))
            {
                score = score.saturating_add(*points);
                reasons.push(format!("suspicious_keyword:{}", kw));
            }
        }
    }

    score = score.min(50);
    (score, reasons)
}
