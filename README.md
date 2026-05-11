# GarudaVision

GarudaVision is a lightweight phishing detection engine written in Rust that detects typo-squatting, homoglyph attacks, hosted phishing kits, enterprise impersonation, banking scams, crypto wallet phishing, and suspicious authentication portals using deterministic layered heuristics.

The engine focuses on:

* high detection quality
* low false positives
* explainable scoring
* dynamic rule intelligence
* real-world phishing infrastructure patterns

---

# Features

* Layered phishing detection pipeline
* Brand impersonation detection
* Homoglyph normalization
* Typo-domain analysis
* Enterprise SSO and OAuth phishing detection
* Banking and fintech phishing heuristics
* Crypto wallet scam detection
* Government portal impersonation detection
* Suspicious keyword intelligence
* Hosted phishing kit detection
* Dynamic JSON-based intelligence loading
* Hot reload + remote updater support
* Explainable scoring and verdicts
* Regression testing suite

---

# Detection Capabilities

GarudaVision detects:

## Typo Squatting

Examples:

```text
paypa1.com
rnicrosoft.com
linkedln.com
g00gle.com
```

## Hosted Phishing Kits

Examples:

```text
paypal-login.vercel.app
secure-sbi-login.pages.dev
google-drive-share.web.app
```

## Enterprise Phishing

Examples:

```text
office365-verification-center.com
login.microsoftonline-support.com
githubauth-security-check.com
```

## Banking / Fintech Phishing

Examples:

```text
hdfc-kyc-update.pages.dev
axisbank-otp-auth.firebaseapp.com
paytm-wallet-security.vercel.app
```

## Crypto Wallet Scams

Examples:

```text
metamask-wallet-recovery.net
walletconnect-metamask.net
trustwallet-dapps-connect.org
```

---

# Architecture

GarudaVision uses deterministic layered heuristics instead of unrestricted fuzzy matching.

Pipeline:

```text
normalize
→ tokenize
→ alias extraction
→ homoglyph normalization
→ typo analysis
→ contextual scoring
→ verdict generation
```

Core components:

```text
src/
├── analyzer/
├── detectors/
├── intelligence/
├── models/
└── tests/
```

---

# Dynamic Intelligence System

Brand intelligence is stored externally in JSON files.

Example:

```json
{
  "canonical": "google",
  "domain": "google.com",
  "aliases": ["gmail", "gdrive", "workspace"],
  "category": "tech",
  "risk": 90
}
```

Supported intelligence files:

```text
lists/
├── brands.json
├── keywords.json
├── hosting.json
├── homoglyphs.json
├── typo_aliases.json
└── metadata.json
```

Rules can be:

* updated without recompiling
* hot reloaded
* remotely fetched from GitHub raw URLs

---

# Build

## Requirements

* Rust stable
* Cargo

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Clone repository:

```bash
git clone https://github.com/ProjectArcade/Arcade-GarudaVision.git
cd Arcade-GarudaVision
```

Build project:

```bash
cargo build --release
```

Run tests:

```bash
cargo test -p garuda-core
```

---

# Running the CLI

Basic usage:

```bash
cargo run -p garuda-cli -- check "https://www.rnicrosoft.com/en-in"
```

Example output:

```text
URL     : https://www.rnicrosoft.com/en-in
Score   : 100
Verdict : Block
Reasons : [
  "brand_impersonation:microsoft",
  "homoglyph_detected"
]
```

---

# Dynamic Brand Intelligence

Use external intelligence files:

```bash
export GARUDA_BRANDS_PATH=lists/brands.json
```

Enable hot reload:

```bash
export GARUDA_BRANDS_HOT_RELOAD=true
```

Configure remote updater:

```bash
export GARUDA_BRANDS_URL="https://raw.githubusercontent.com/<repo>/main/lists/brands.json"
export GARUDA_BRANDS_UPDATE_INTERVAL_SECS=3600
export GARUDA_BRANDS_CACHE_PATH=lists/cache/brands.json
```

---

# Regression Testing

Run the regression suite:

```bash
cargo test -p garuda-core
```

Manual phishing validation:

```bash
cargo run -p garuda-cli -- check "https://paypa1.com/login"
cargo run -p garuda-cli -- check "https://secure-sbi-login.vercel.app"
cargo run -p garuda-cli -- check "https://metamask-wallet-recovery.net"
cargo run -p garuda-cli -- check "https://githubauth-security-check.com"
```

Legitimate sanity checks:

```bash
cargo run -p garuda-cli -- check "https://github.com"
cargo run -p garuda-cli -- check "https://workspace.google.com"
cargo run -p garuda-cli -- check "https://aws.amazon.com"
```

---

# Verdict Thresholds

| Score | Verdict    |
| ----- | ---------- |
| 0-24  | Clean      |
| 25-49 | Suspicious |
| 50-79 | Caution    |
| 80+   | Block      |

---


# License

GNU GENERAL PUBLIC LICENSE
