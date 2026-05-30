#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# GarudaVision — 50 Test Cases
# Run: bash garuda_test_cases.sh  (from workspace root)
# Expected verdicts annotated per case
# ══════════════════════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════"
echo " GarudaVision Test Suite — 50 Cases"
echo "════════════════════════════════════════════════════════"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 1: CLEAN / WHITELISTED DOMAINS (Expected: Clean)
# Should be rejected at Bloom Filter / Exact Hash — score ~0
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-1] Clean / Whitelisted Domains — Expected: CLEAN\n"

# TC-01: Global tech giant — must be whitelisted
cargo run -p garuda-cli -- check "https://www.google.com"

# TC-02: India's national identity portal — whitelisted gov
cargo run -p garuda-cli -- check "https://uidai.gov.in"

# TC-03: HTTPS banking — legitimate subdomain walk
cargo run -p garuda-cli -- check "https://netbanking.hdfcbank.com"

# TC-04: India tax portal
cargo run -p garuda-cli -- check "https://www.incometax.gov.in"

# TC-05: GitHub main domain
cargo run -p garuda-cli -- check "https://github.com"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 2: TYPOSQUATTING — Levenshtein Distance Hits (Expected: Block)
# Single/double character swaps on high-value brands
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-2] Typosquatting — Expected: BLOCK\n"

# TC-06: Original from spec — rn→m swap on microsoft
cargo run -p garuda-cli -- check "https://www.rnicrosoft.com/en-in"

# TC-07: Double-letter typo — paypal
cargo run -p garuda-cli -- check "https://www.paypall.com/signin"

# TC-08: Character swap — google
cargo run -p garuda-cli -- check "https://www.gooogle.com"

# TC-09: Missing letter — amazon
cargo run -p garuda-cli -- check "https://www.amazn.com/login"

# TC-10: Extra hyphen insertion — github
cargo run -p garuda-cli -- check "https://git-hub.com/login"

# TC-11: Letter swap — facebook
cargo run -p garuda-cli -- check "https://www.faceb00k.com"

# TC-12: TLD swap on Apple
cargo run -p garuda-cli -- check "https://www.apple.net/id/login"

# TC-13: Prefix typo — twitter/X
cargo run -p garuda-cli -- check "https://twiiter.com/login"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 3: HOMOGLYPH / PUNYCODE ATTACKS (Expected: Block)
# Visual character substitution using Unicode / Cyrillic / IDN
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-3] Homoglyph / Punycode — Expected: BLOCK\n"

# TC-14: Cyrillic 'а' replacing ASCII 'a' in paypal
cargo run -p garuda-cli -- check "https://www.pаypal.com/signin"

# TC-15: Punycode encoded phishing domain (paypal with Cyrillic p)
cargo run -p garuda-cli -- check "https://www.xn--aypal-uye.com"

# TC-16: Zero replacing O — google
cargo run -p garuda-cli -- check "https://www.g00gle.com/accounts/login"

# TC-17: Capital I replacing lowercase l — paypal
cargo run -p garuda-cli -- check "https://www.paypaI.com/verify"

# TC-18: Cyrillic full domain lookalike — microsoft
cargo run -p garuda-cli -- check "https://www.microsоft.com/login"

# TC-19: Unicode rn → m confusion — coinbase
cargo run -p garuda-cli -- check "https://www.coinbаse.com/wallet"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 4: BRAND IN SUBDOMAIN / PATH — Brand Containment (Expected: Block)
# Legitimate brand name used in a subdomain or path of a fake domain
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-4] Brand Containment in Subdomain/Path — Expected: BLOCK\n"

# TC-20: PayPal brand in subdomain of attacker domain
cargo run -p garuda-cli -- check "https://paypal.secure-update.com/login"

# TC-21: Google brand injected in subdomain
cargo run -p garuda-cli -- check "https://google.accounts-verify.net/signin"

# TC-22: Apple brand injected into path
cargo run -p garuda-cli -- check "https://support-apple.com/id/verify"

# TC-23: Netflix keyword injected subdomain
cargo run -p garuda-cli -- check "https://netflix.billing-update.com/account"

# TC-24: HDFC bank brand in fake domain
cargo run -p garuda-cli -- check "https://hdfc-netbanking-secure.com/login"

# TC-25: SBI (State Bank India) phishing
cargo run -p garuda-cli -- check "https://sbi.netbanking-verify.in/otp"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 5: FREE HOSTING + BRAND COMBO (Expected: Block)
# Phishing kits on Vercel / Netlify / GitHub Pages / Firebase
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-5] Free Hosting + Brand Combo — Expected: BLOCK\n"

# TC-26: PayPal KYC on Vercel — from spec
cargo run -p garuda-cli -- check "https://paypal-kyc-verify.vercel.app"

# TC-27: Microsoft login on Netlify
cargo run -p garuda-cli -- check "https://microsoft-login-secure.netlify.app"

# TC-28: Binance wallet connect on GitHub Pages
cargo run -p garuda-cli -- check "https://binance-wallet-connect.github.io"

# TC-29: Google account recovery on Firebase
cargo run -p garuda-cli -- check "https://google-account-recovery.web.app/signin"

# TC-30: HDFC OTP portal on Vercel
cargo run -p garuda-cli -- check "https://hdfc-otp-verify.vercel.app"

# TC-31: Coinbase seed phrase page on Netlify
cargo run -p garuda-cli -- check "https://coinbase-seed-recovery.netlify.app"

# TC-32: Apple ID recovery on GitHub Pages
cargo run -p garuda-cli -- check "https://apple-id-unlock.github.io/verify"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 6: CRYPTO WALLET / SEED PHRASE PHISHING (Expected: Block)
# High-value targets: MetaMask, Ledger, Phantom, Coinbase Wallet
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-6] Crypto Wallet Phishing — Expected: BLOCK\n"

# TC-33: MetaMask seed phrase harvesting
cargo run -p garuda-cli -- check "https://metamask-recovery.com/seed"

# TC-34: Ledger Live fake support
cargo run -p garuda-cli -- check "https://ledger-live-support.com/recovery"

# TC-35: Phantom wallet phishing
cargo run -p garuda-cli -- check "https://phantom-wallet-verify.com/connect"

# TC-36: Trust Wallet seed recovery
cargo run -p garuda-cli -- check "https://trustwallet-seed.net/restore"

# TC-37: Uniswap fake liquidity claim
cargo run -p garuda-cli -- check "https://uniswap-airdrop-claim.vercel.app"

# TC-38: Generic "crypto wallet secure login" combo
cargo run -p garuda-cli -- check "https://crypto-wallet-secure-login.com"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 7: SUSPICIOUS KEYWORD HITS (Expected: Caution / Block)
# login, otp, verify, secure, recovery, seed in suspicious contexts
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-7] Suspicious Keywords — Expected: CAUTION / BLOCK\n"

# TC-39: OTP keyword on unknown domain
cargo run -p garuda-cli -- check "https://secure-otp-verify.com/login"

# TC-40: Seed + recovery keywords
cargo run -p garuda-cli -- check "https://wallet-seed-recovery.net"

# TC-41: Multiple stacked keywords
cargo run -p garuda-cli -- check "https://login-verify-secure-otp.com"

# TC-42: Account locked + verify
cargo run -p garuda-cli -- check "https://account-locked-verify.net/reset"

# TC-43: KYC verification scam domain
cargo run -p garuda-cli -- check "https://kyc-verification-update.com"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 8: DANGEROUS URI SCHEMES (Expected: Block — immediate flag)
# javascript:, data:, blob: URI scheme attacks
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-8] Dangerous URI Schemes — Expected: BLOCK (immediate)\n"

# TC-44: javascript: scheme XSS injection
cargo run -p garuda-cli -- check "javascript:alert(document.cookie)"

# TC-45: data: URI base64 payload
cargo run -p garuda-cli -- check "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

# TC-46: blob: URI phishing payload
cargo run -p garuda-cli -- check "blob:https://evil.com/fake-login-page"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 9: STRUCTURAL ANOMALIES (Expected: Caution / Block)
# Excessive subdomains, IP-as-hostname, long domains, hyphen abuse
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-9] Structural Anomalies — Expected: CAUTION / BLOCK\n"

# TC-47: IP address as hostname
cargo run -p garuda-cli -- check "http://185.220.101.45/login/verify"

# TC-48: Excessive subdomains (5 levels deep)
cargo run -p garuda-cli -- check "https://secure.login.verify.account.update.com"

# TC-49: Extremely long hyphenated domain
cargo run -p garuda-cli -- check "https://secure-login-verify-otp-account-update-portal.com"

# TC-50: HTTP (not HTTPS) financial portal with brand name
cargo run -p garuda-cli -- check "http://paypal-secure.com/wallet/login"

echo -e "\n════════════════════════════════════════════════════════"
echo " Test Suite Complete — 50 / 50"
echo "════════════════════════════════════════════════════════"
