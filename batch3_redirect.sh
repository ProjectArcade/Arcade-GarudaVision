# ─════════════════════════════════════════════════════════════════════════════
# BATCH 3 — TC-101 to TC-150
# Focus:
# - Modern Identity Providers
# - OAuth Redirect Abuse
# - Hosting Platform Abuse
# - SAML / Enterprise SSO
# - URL Parsing Edge Cases
# ═════════════════════════════════════════════════════════════════════════════

echo ""
echo "════════════════════════════════════════════════════════"
echo " GarudaVision Test Suite — Batch 3 (TC-101 to TC-150)"
echo "════════════════════════════════════════════════════════"

# ────────────────────────────────────────────────────────────────────────────
# CATEGORY 19: MODERN AUTH PROVIDERS (Expected: CLEAN)
# ────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-19] Modern Auth Providers — Expected: CLEAN\n"

cargo run -p garuda-cli -- check "https://auth.company.workos.com/authorize"
cargo run -p garuda-cli -- check "https://clerk.dev/sign-in"
cargo run -p garuda-cli -- check "https://login.example.descope.com/oauth2/authorize"
cargo run -p garuda-cli -- check "https://id.example.zitadel.cloud/oauth/v2/authorize"
cargo run -p garuda-cli -- check "https://auth.example.com/realms/master/protocol/openid-connect/auth"
cargo run -p garuda-cli -- check "https://try.ory.sh/oauth2/auth"
cargo run -p garuda-cli -- check "https://auth.supertokens.com/auth"
cargo run -p garuda-cli -- check "https://fusionauth.io/oauth2/authorize"
cargo run -p garuda-cli -- check "https://auth0.com/authorize"
cargo run -p garuda-cli -- check "https://accounts.pingidentity.com/as/authorization.oauth2"

# ────────────────────────────────────────────────────────────────────────────
# CATEGORY 20: OAUTH REDIRECT ABUSE (Expected: BLOCK / CAUTION)
# ────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-20] OAuth Redirect Abuse — Expected: BLOCK / CAUTION\n"

cargo run -p garuda-cli -- check "https://accounts.google.com/o/oauth2/auth?redirect_uri=https://evil-login.com"
cargo run -p garuda-cli -- check "https://github.com/login/oauth/authorize?redirect_uri=https://paypal-reset.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?next=https://evil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?return=https://evil.com/login"
cargo run -p garuda-cli -- check "https://auth.example.com/login?redirect=https://wallet-drain.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?next=https%3A%2F%2Fevil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?next=https%253A%252F%252Fevil.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?continue=https://phishing.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?url=https://credential-harvest.com"
cargo run -p garuda-cli -- check "https://auth.example.com/login?dest=https://aadhaar-update.com"

# ────────────────────────────────────────────────────────────────────────────
# CATEGORY 21: HOSTING PLATFORM ABUSE (Expected: BLOCK)
# ────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-21] Hosting Platform Abuse — Expected: BLOCK\n"

cargo run -p garuda-cli -- check "https://paypal-auth.netlify.app"
cargo run -p garuda-cli -- check "https://secure-login.firebaseapp.com"
cargo run -p garuda-cli -- check "https://aadhaar-update.web.app"
cargo run -p garuda-cli -- check "https://sbi-auth.fly.dev"
cargo run -p garuda-cli -- check "https://microsoft365-login.replit.app"
cargo run -p garuda-cli -- check "https://coinbase-wallet.pages.dev"
cargo run -p garuda-cli -- check "https://okta-login.surge.sh"
cargo run -p garuda-cli -- check "https://upi-verification.glitch.me"
cargo run -p garuda-cli -- check "https://aws-auth.koyeb.app"
cargo run -p garuda-cli -- check "https://verify-wallet.deno.dev"

# ────────────────────────────────────────────────────────────────────────────
# CATEGORY 22: SAML / ENTERPRISE SSO (Expected: CLEAN)
# ────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-22] SAML / Enterprise SSO — Expected: CLEAN\n"

cargo run -p garuda-cli -- check "https://login.microsoftonline.com/common/saml2"
cargo run -p garuda-cli -- check "https://sts.windows.net/tenant-id/"
cargo run -p garuda-cli -- check "https://sso.jumpcloud.com/saml2/google"
cargo run -p garuda-cli -- check "https://company.okta.com/app/google/sso/saml"
cargo run -p garuda-cli -- check "https://idp.company.com/saml/login"
cargo run -p garuda-cli -- check "https://accounts.google.com/o/saml2/idp"
cargo run -p garuda-cli -- check "https://auth.company.com/adfs/ls"
cargo run -p garuda-cli -- check "https://login.salesforce.com/idp/login"
cargo run -p garuda-cli -- check "https://sso.company.com/auth/realms/main/protocol/saml"
cargo run -p garuda-cli -- check "https://login.cisco.com/saml"

# ────────────────────────────────────────────────────────────────────────────
# CATEGORY 23: CDN / ATTACHMENT ABUSE (Expected: BLOCK / CAUTION)
# ────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-23] CDN / Attachment Abuse — Expected: BLOCK / CAUTION\n"

cargo run -p garuda-cli -- check "https://cdn.discordapp.com/attachments/12345/99999/login.html"
cargo run -p garuda-cli -- check "https://cdn.discordapp.com/attachments/12345/99999/paypal_verify.html"
cargo run -p garuda-cli -- check "https://raw.githubusercontent.com/test/repo/main/login.html"
cargo run -p garuda-cli -- check "https://user.github.io/paypal-login"
cargo run -p garuda-cli -- check "https://storage.googleapis.com/secure-login/index.html"
cargo run -p garuda-cli -- check "https://pages.dev/paypal-update"
cargo run -p garuda-cli -- check "https://raw.githubusercontent.com/test/repo/main/aadhaar-update.html"
cargo run -p garuda-cli -- check "https://objects.githubusercontent.com/login-verification.html"
cargo run -p garuda-cli -- check "https://firebase.google.com/downloads/login.html"
cargo run -p garuda-cli -- check "https://cdn.jsdelivr.net/gh/test/repo/login.html"

# ────────────────────────────────────────────────────────────────────────────
# CATEGORY 24: URL PARSER EDGE CASES (Expected: BLOCK)
# ────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-24] URL Parser Edge Cases — Expected: BLOCK\n"

cargo run -p garuda-cli -- check "https://paypal.com..evil.com/login"
cargo run -p garuda-cli -- check "https://paypal.com./signin"
cargo run -p garuda-cli -- check "https://paypal-login.com#@evil.com"
cargo run -p garuda-cli -- check "https://%70aypal.com/login"
cargo run -p garuda-cli -- check "https://xn--80ak6aa92e.com/login"
cargo run -p garuda-cli -- check "https://paypal.com%2F%2Fevil.com/login"
cargo run -p garuda-cli -- check "https://paypal.com%252F%252Fevil.com/login"
cargo run -p garuda-cli -- check "https://login.paypal.com.evil.com"
cargo run -p garuda-cli -- check "https://secure-paypal.evil.com"
cargo run -p garuda-cli -- check "https://evil.com/paypal.com/signin"

echo -e "\n════════════════════════════════════════════════════════"
echo " Batch 3 Complete — TC-101 to TC-150"
echo " Full Suite: 150 / 150"
echo "════════════════════════════════════════════════════════"