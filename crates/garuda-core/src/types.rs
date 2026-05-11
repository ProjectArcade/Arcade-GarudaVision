#[derive(Debug)]
pub enum Verdict {
    Clean,
    Caution,
    Block,
}

#[derive(Debug)]
pub struct UrlVerdict {
    pub verdict: Verdict,
    pub score: u8,
    pub reasons: Vec<String>,
}
