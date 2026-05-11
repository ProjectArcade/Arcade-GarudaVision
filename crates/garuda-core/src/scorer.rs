use crate::types::{Verdict, UrlVerdict};

pub fn score_to_verdict(score: u8, reasons: Vec<String>) -> UrlVerdict {
    let verdict = match score {
        0..=24 => Verdict::Clean,
        25..=49 => Verdict::Suspicious,
        50..=79 => Verdict::Caution,
        _ => Verdict::Block,
    };
    UrlVerdict { verdict, score, reasons }
}
