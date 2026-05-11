use crate::types::{Verdict, UrlVerdict};

pub fn score_to_verdict(score: u8, reasons: Vec<String>) -> UrlVerdict {
    let verdict = match score {
        0..=39  => Verdict::Clean,
        40..=69 => Verdict::Caution,
        _       => Verdict::Block,
    };
    UrlVerdict { verdict, score, reasons }
}
