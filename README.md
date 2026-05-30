# GarudaVision

## 1. Introduction
**GarudaVision** is a lightweight, high-performance phishing detection engine written in Rust. It utilizes deterministic layered heuristics to identify typosquatting, homoglyph attacks, hosted phishing kits, enterprise SSO/OAuth spoofing, banking scams, and crypto wallet phishing in real time.

---

## 2. Why GarudaVision is Needed
Traditional phishing detection relies heavily on reactive blacklists (e.g., Google Safe Browsing), which fail to stop newly registered zero-day phishing domains. Modern attackers spin up ephemeral phishing sites on free hosting services (Vercel, Netlify, Github Pages) that last only a few hours. GarudaVision solves this by proactively evaluating structural and contextual signals inside URLs to assign real-time risk scores without relying on pre-existing blacklists.

---

## 3. How It Identifies Phishing and Risky Sites
GarudaVision processes incoming URLs through a layered analysis pipeline:
1. **URI Scheme Validation**: Immediately flags dangerous protocols (`javascript:`, `data:`, `blob:`, etc.).
2. **Structural Checks**: Analyzes hostname length, hyphen count, subdomains count, and presence of IP addresses as hostnames.
3. **Punycode & Homoglyph Normalization**: Detects visual character substitutions (e.g., replacing `l` with `I`, `0` with `O`, or using Cyrillic lookalikes like `раураі.сом` for `paypal.com`).
4. **Brand Impersonation Detection**: Performs fuzzy, levenshtein-distance, and token-based checks against high-value target brands (e.g. `githuub.com` vs `github.com`).
5. **Suspicious Keyword Identification**: Targets critical phishing keywords (`login`, `verify`, `otp`, `secure`, `recovery`, `seed`).
6. **Contextual Risk Multipliers**: Amplifies scores when risky combinations occur together, such as brand containment combined with free hosting (e.g., `paypal-kyc-verify.vercel.app`).

---

## 4. Why It is Efficient at Scale (Handling Billions of Internet Sites)
To check billions of domains globally without slowing down network requests or suffering from memory bloat, GarudaVision implements a multi-tier whitelisting engine:
* **Bloom Filter Rejection**: Utilizes a highly compact Bloom Filter (using `FxHasher` and double hashing) sized dynamically based on a whitelist of over 10,000 top global domains (derived from OpenDNS Top 10k). This rejects clean, legitimate traffic in $O(1)$ time with negligible CPU and memory overhead (requiring only ~13 KB of L1 cache-friendly space).
* **Exact Hash Matching**: Legitimate domains that trigger the Bloom filter are validated against a high-speed `FxHashSet` to eliminate False Positives.
* **Fast Subdomain Walking**: Parent domain verification (e.g. checking `mail.google.com` $\rightarrow$ `google.com`) is performed through label parsing instead of slow binary searches or prefix comparisons, achieving verification in nanoseconds.

---

## 5. Architecture of GarudaVision
The codebase is structured as a modular workspace:
* **[garuda-lists](Arcade-GarudaVision/crates/garuda-lists)**: Manages Bloom filters, whitelists, and category classifications (`finance`, `government`, `tech`, `media`, `commerce`).
* **[garuda-core](Arcade-GarudaVision/crates/garuda-core)**: Contains the central analyzer, tokenization pipeline, homoglyph maps, brand rules, and scoring modules.
* **[garuda-cli](Arcade-GarudaVision/crates/garuda-cli)**: Provides a command-line interface for manual analysis and validation.
* **[garuda-ffi](Arcade-GarudaVision/crates/garuda-ffi)**: Exposes C-compatible bindings for integration with other languages.

```text
Incoming URL 
  → Normalize & Decode (NFKC, Percent Decode)
  → Whitelist Query (O(1) Bloom Filter + Exact Hash Match)
  → Heuristics Pipeline (Structure, Brand, Homoglyph, Keywords)
  → Contextual Multiplier 
  → Score (0 - 100) & Verdict Generation (Clean, Suspicious, Caution, Block)
```

---

## 6. Build and Test

### Requirements
- Rust Stable
- Cargo

### Build the Project
```bash
cargo build --release
```

### Run Tests
```bash
cargo test
```

### Run CLI Validation Example
```bash
cargo run -p garuda-cli -- check "https://www.rnicrosoft.com/login"
```

---

## 7. License
This project is licensed under the **GNU General Public License**.
