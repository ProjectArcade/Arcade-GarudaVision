# ════════════════════════════════════════════════════════════════════════════
# BATCH 4 — TC-151 to TC-200
# Critical Red-Team Tests
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "════════════════════════════════════════════════════════"
echo " GarudaVision Test Suite — Batch 4 (TC-151 to TC-200)"
echo "════════════════════════════════════════════════════════"

# ──────────────────────────────────────────────────────────────
# CAT-25: REDIRECT PARAMETER ABUSE
# Expected: BLOCK / CAUTION
# ──────────────────────────────────────────────────────────────

cargo run -p garuda-cli -- check "https://google.com/url?q=https://evil.com"
cargo run -p garuda-cli -- check "https://google.com/url?q=https://paypal-login.com"
cargo run -p garuda-cli -- check "https://youtube.com/redirect?q=https://wallet-drainer.com"
cargo run -p garuda-cli -- check "https://github.com/login/oauth/authorize?redirect_uri=https://evil.com"
cargo run -p garuda-cli -- check "https://accounts.google.com/o/oauth2/auth?redirect_uri=https://evil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?next=https://evil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?continue=https://evil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?url=https://evil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?target=https://evil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?dest=https://evil.com"

# ──────────────────────────────────────────────────────────────
# CAT-26: DOUBLE ENCODED REDIRECTS
# Expected: BLOCK
# ──────────────────────────────────────────────────────────────

cargo run -p garuda-cli -- check "https://auth.example.com/login?next=https%3A%2F%2Fevil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?next=https%253A%252F%252Fevil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?redirect=https%25253A%25252F%25252Fevil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?return=https%3A%2F%2Fpaypal-reset.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?continue=https%3A%2F%2Fwallet-drainer.com"

# ──────────────────────────────────────────────────────────────
# CAT-27: USERINFO ABUSE
# Expected: BLOCK
# ──────────────────────────────────────────────────────────────

cargo run -p garuda-cli -- check "https://paypal.com@evil.com/login"
cargo run -p garuda-cli -- check "https://google.com@evil.com"
cargo run -p garuda-cli -- check "https://microsoft.com@evil.com/auth"
cargo run -p garuda-cli -- check "https://accounts.google.com@phishing.com"
cargo run -p garuda-cli -- check "https://github.com@evil.com/login"

# ──────────────────────────────────────────────────────────────
# CAT-28: CDN / FILE HOSTING ABUSE
# Expected: CAUTION / BLOCK
# ──────────────────────────────────────────────────────────────

cargo run -p garuda-cli -- check "https://cdn.discordapp.com/attachments/123/login.html"
cargo run -p garuda-cli -- check "https://cdn.discordapp.com/attachments/123/paypal_verify.html"
cargo run -p garuda-cli -- check "https://raw.githubusercontent.com/user/repo/main/login.html"
cargo run -p garuda-cli -- check "https://raw.githubusercontent.com/user/repo/main/paypal.html"
cargo run -p garuda-cli -- check "https://storage.googleapis.com/secure-login/index.html"
cargo run -p garuda-cli -- check "https://objects.githubusercontent.com/login-verification.html"
cargo run -p garuda-cli -- check "https://cdn.jsdelivr.net/gh/user/repo/paypal.html"
cargo run -p garuda-cli -- check "https://pastebin.com/raw/abcdef"

# ──────────────────────────────────────────────────────────────
# CAT-29: SAML / SSO FALSE POSITIVE REGRESSION
# Expected: CLEAN
# ──────────────────────────────────────────────────────────────

cargo run -p garuda-cli -- check "https://idp.company.com/saml/login"
cargo run -p garuda-cli -- check "https://auth.company.com/adfs/ls"
cargo run -p garuda-cli -- check "https://sso.company.com/auth/realms/main/protocol/saml"
cargo run -p garuda-cli -- check "https://sso.company.com/openid-connect/auth"
cargo run -p garuda-cli -- check "https://company.okta.com/app/google/sso/saml"
cargo run -p garuda-cli -- check "https://login.microsoftonline.com/common/saml2"
cargo run -p garuda-cli -- check "https://sts.windows.net/tenant-id"
cargo run -p garuda-cli -- check "https://login.salesforce.com/idp/login"

# ──────────────────────────────────────────────────────────────
# CAT-30: HOSTNAME PARSER CONFUSION
# Expected: BLOCK
# ──────────────────────────────────────────────────────────────

cargo run -p garuda-cli -- check "https://paypal.com..evil.com"
cargo run -p garuda-cli -- check "https://login.paypal.com.evil.com"
cargo run -p garuda-cli -- check "https://secure-paypal.evil.com"
cargo run -p garuda-cli -- check "https://paypal.com%00.evil.com"
cargo run -p garuda-cli -- check "https://paypal.com%2F%2Fevil.com"
cargo run -p garuda-cli -- check "https://paypal.com%252F%252Fevil.com"
cargo run -p garuda-cli -- check "https://paypal-login.com#@evil.com"
cargo run -p garuda-cli -- check "https://evil.com/paypal.com/login"

# ──────────────────────────────────────────────────────────────
# CAT-31: HOSTING PROVIDER COVERAGE
# Expected: BLOCK
# ──────────────────────────────────────────────────────────────

cargo run -p garuda-cli -- check "https://paypal-login.vercel.app"
cargo run -p garuda-cli -- check "https://paypal-login.replit.app"
cargo run -p garuda-cli -- check "https://paypal-login.netlify.app"
cargo run -p garuda-cli -- check "https://paypal-login.fly.dev"
cargo run -p garuda-cli -- check "https://paypal-login.firebaseapp.com"
cargo run -p garuda-cli -- check "https://paypal-login.web.app"
cargo run -p garuda-cli -- check "https://paypal-login.pages.dev"
cargo run -p garuda-cli -- check "https://paypal-login.glitch.me"
cargo run -p garuda-cli -- check "https://paypal-login.deno.dev"

# ──────────────────────────────────────────────────────────────
# CAT-32: INDIA TARGETED PHISHING
# Expected: BLOCK
# ──────────────────────────────────────────────────────────────

cargo run -p garuda-cli -- check "https://npci-upi-verify.in"
cargo run -p garuda-cli -- check "https://upi-kyc-update.in"
cargo run -p garuda-cli -- check "https://aadhaar-otp-update.in"
cargo run -p garuda-cli -- check "https://digilocker-document-verify.in"
cargo run -p garuda-cli -- check "https://irctc-ticket-verify.in"

echo ""
echo "════════════════════════════════════════════════════════"
echo " Batch 4 Complete — TC-151 to TC-200"
echo " Full Suite: 200 / 200"
echo "════════════════════════════════════════════════════════"

