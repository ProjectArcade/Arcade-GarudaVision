pub fn check(url: &str) -> (u8, Vec<String>) {
    let url_lower = url.to_lowercase();
    let mut score: u8 = 0;
    let mut reasons = Vec::new();

    let critical_keywords = &[
        ("kyc", 35u8),
        ("aadhaar", 35),
        ("aadhar", 35),
        ("pan", 30),
        ("wallet", 30),
        ("recovery", 28),
        ("seed", 28),
        ("phrase", 25),
        ("private", 25),
    ];
    
    let high_keywords = &[
        ("login", 20u8),
        ("verify", 20),
        ("password", 20),
        ("account", 18),
        ("auth", 18),
        ("payment", 18),
        ("banking", 18),
        ("otp", 18),
        ("upi", 18),
        ("refund", 18),
    ];
    
    let medium_keywords = &[
        ("confirm", 10u8),
        ("secure", 10),
        ("update", 10),
        ("signin", 10),
        ("authenticate", 10),
        ("credential", 10),
    ];

    for (kw, points) in critical_keywords {
        if url_lower.contains(kw) && !reasons.iter().any(|r| r == &format!("keyword:{}", kw)) {
            score = score.saturating_add(*points);
            reasons.push(format!("keyword:{}", kw));
        }
    }

    if score < 20 {
        for (kw, points) in high_keywords {
            if url_lower.contains(kw) && !reasons.iter().any(|r| r == &format!("keyword:{}", kw)) {
                score = score.saturating_add(*points);
                reasons.push(format!("keyword:{}", kw));
            }
        }
    }

    if score < 30 {
        for (kw, points) in medium_keywords {
            if url_lower.contains(kw) && !reasons.iter().any(|r| r == &format!("keyword:{}", kw)) {
                score = score.saturating_add(*points);
                reasons.push(format!("keyword:{}", kw));
            }
        }
    }

    score = score.min(40);
    (score, reasons)
}
