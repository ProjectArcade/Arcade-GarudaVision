use garuda_core::{flag_a, scorer};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] != "check" {
        println!("Usage: garuda-cli check <url>");
        return;
    }
    let url = &args[2];
    let (score, reasons) = flag_a::analyse(url);
    let verdict = scorer::score_to_verdict(score, reasons);
    println!("URL     : {}", url);
    println!("Score   : {}", verdict.score);
    println!("Verdict : {:?}", verdict.verdict);
    println!("Reasons : {:?}", verdict.reasons);
}
