# ══════════════════════════════════════════════════════════════════════════════
# BATCH 2 — TC-51 to TC-100
# Covers: gTLD false positives, OAuth callbacks, open redirects, URL shorteners,
#         cloud subdomains, evasion techniques, false positive regression,
#         Indian market threats, and adversarial edge cases
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "════════════════════════════════════════════════════════"
echo " GarudaVision Test Suite — Batch 2 (TC-51 to TC-100)"
echo "════════════════════════════════════════════════════════"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 10: BRAND-OWNED gTLD DOMAINS (Expected: Clean)
# Bug 1 fix validation — *.google, *.apple, *.amazon must be trusted
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-10] Brand-Owned gTLD Domains — Expected: CLEAN\n"

# TC-51: The exact URL that exposed Bug 1 — full OAuth callback on *.google gTLD
cargo run -p garuda-cli -- check "https://antigravity.google/oauth-callback?state=-QzJVmFdo35rSVuWi6Qccg&iss=https%3A%2F%2Faccounts.google.com&scope=email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform+openid&authuser=0&prompt=consent"

# TC-52: Google Cloud Console — *.google gTLD subdomain
cargo run -p garuda-cli -- check "https://console.cloud.google/iam-admin/iam"

# TC-53: Google Meet on *.google gTLD
cargo run -p garuda-cli -- check "https://meet.google/abc-defg-hij"

# TC-54: Apple gTLD — legitimate product page
cargo run -p garuda-cli -- check "https://www.apple/iphone"

# TC-55: Microsoft gTLD — Microsoft-owned apex
cargo run -p garuda-cli -- check "https://www.microsoft/en-us/microsoft-365"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 11: LEGITIMATE OAUTH / OIDC CALLBACKS (Expected: Clean)
# Bug 3 fix validation — query string keywords must not trigger scoring
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-11] Legitimate OAuth / OIDC Callbacks — Expected: CLEAN\n"

# TC-56: GitHub OAuth callback with code + state params
cargo run -p garuda-cli -- check "https://github.com/login/oauth/authorize?client_id=abc123&redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback&scope=read%3Auser&state=xyz789"

# TC-57: Google accounts standard OIDC token endpoint
cargo run -p garuda-cli -- check "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=123.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fmyapp.com%2Fauth&scope=openid+email+profile&state=abc"

# TC-58: Microsoft Entra ID (Azure AD) OAuth flow
cargo run -p garuda-cli -- check "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&response_type=code&redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback&scope=openid+profile+email&state=xyz"

# TC-59: Okta OAuth callback — enterprise SSO
cargo run -p garuda-cli -- check "https://mycompany.okta.com/oauth2/v1/authorize?response_type=code&client_id=abc&redirect_uri=https%3A%2F%2Fapp.mycompany.com%2Fcallback&scope=openid+email&state=xyz"

# TC-60: Auth0 OIDC callback with id_token
cargo run -p garuda-cli -- check "https://myapp.auth0.com/authorize?response_type=code&client_id=abc123&redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback&scope=openid+profile+email&state=xyz&nonce=abc"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 12: OPEN REDIRECT ABUSE (Expected: Block / Caution)
# Detection gap 4.7 — legitimate domains used to redirect to evil
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-12] Open Redirect Abuse — Expected: BLOCK / CAUTION\n"

# TC-61: Classic Google open redirect to phishing
cargo run -p garuda-cli -- check "https://google.com/url?q=https://paypal-verify-login.com"

# TC-62: YouTube redirect parameter to evil domain
cargo run -p garuda-cli -- check "https://www.youtube.com/redirect?q=https://metamask-recovery.net/seed"

# TC-63: Bing redirect abuse
cargo run -p garuda-cli -- check "https://www.bing.com/search?q=test&redirect=https://coinbase-seed-recovery.com"

# TC-64: Generic ?next= open redirect on unknown domain
cargo run -p garuda-cli -- check "https://portal-login.com/auth?next=https://evil-harvest.com/steal"

# TC-65: Encoded redirect parameter — percent-encoded evil URL
cargo run -p garuda-cli -- check "https://login.example.com/sso?redirect_uri=https%3A%2F%2Fphishing-site.com%2Flogin%2Fverify"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 13: URL SHORTENERS (Expected: Caution / Suspicious)
# Detection gap 4.2 — shorteners hide the real destination
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-13] URL Shorteners — Expected: CAUTION / SUSPICIOUS\n"

# TC-66: bit.ly — most abused shortener
cargo run -p garuda-cli -- check "https://bit.ly/3xY7zAb"

# TC-67: tinyurl — classic shortener
cargo run -p garuda-cli -- check "https://tinyurl.com/paypal-verify"

# TC-68: t.co — Twitter shortener, often in phishing DMs
cargo run -p garuda-cli -- check "https://t.co/AbCdEfGh"

# TC-69: rb.gy — newer shortener used in crypto phishing
cargo run -p garuda-cli -- check "https://rb.gy/xyz123"

# TC-70: cutt.ly — shortener popular in Indian SMS phishing
cargo run -p garuda-cli -- check "https://cutt.ly/verify-aadhaar-update"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 14: CLOUD SUBDOMAIN PLATFORMS (Expected: Block)
# Detection gap 4.10 — attacker-rented subdomains on legit CDNs
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-14] Cloud Subdomain Phishing — Expected: BLOCK\n"

# TC-71: Azure App Service — microsoft brand on attacker subdomain
cargo run -p garuda-cli -- check "https://microsoft-login-verify.azurewebsites.net"

# TC-72: AWS CloudFront — paypal phishing via CDN subdomain
cargo run -p garuda-cli -- check "https://paypal-secure-update.cloudfront.net/login"

# TC-73: Cloudflare Workers — crypto phishing
cargo run -p garuda-cli -- check "https://metamask-connect-wallet.workers.dev"

# TC-74: Render.com — newer free hosting platform
cargo run -p garuda-cli -- check "https://hdfc-otp-portal.onrender.com/login"

# TC-75: Railway.app — free hosting for phishing kits
cargo run -p garuda-cli -- check "https://sbi-netbanking-login.up.railway.app"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 15: EVASION TECHNIQUES (Expected: Caution / Block)
# Attacks designed to avoid keyword and brand matching
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-15] Evasion Techniques — Expected: CAUTION / BLOCK\n"

# TC-76: No brand name, generic keywords only — pure keyword evasion
cargo run -p garuda-cli -- check "https://secure-portal-v2.vercel.app/signin"

# TC-77: DGA-style random subdomain — entropy evasion
cargo run -p garuda-cli -- check "https://a3x7k9mf.vercel.app/login"

# TC-78: Lookalike TLD — .com.co suffix confusion
cargo run -p garuda-cli -- check "https://paypal.com.co/signin"

# TC-79: Double dot confusion — path traversal attempt
cargo run -p garuda-cli -- check "https://evil-site.com/paypal.com/login/verify"

# TC-80: Subdomain brand injection with random apex
cargo run -p garuda-cli -- check "https://paypal.xn--p1acf/signin"

# TC-81: Zero-width character injection in domain (invisible separator)
cargo run -p garuda-cli -- check "https://pay​pal.com/verify"

# TC-82: Homoglyph on less-watched brand — ICICI bank India
cargo run -p garuda-cli -- check "https://www.icicibаnk.com/login"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 16: FALSE POSITIVE REGRESSION (Expected: Clean)
# Legitimate domains that should NOT be flagged — regression for over-detection
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-16] False Positive Regression — Expected: CLEAN\n"

# TC-83: Legitimate fintech startup with 'pay' in name
cargo run -p garuda-cli -- check "https://www.paytm.com/payment"

# TC-84: Razorpay — Indian payment gateway, 'pay' in brand
cargo run -p garuda-cli -- check "https://razorpay.com/payment-gateway"

# TC-85: Legitimate security company — keywords in path
cargo run -p garuda-cli -- check "https://www.cloudflare.com/learning/security/what-is-two-factor-authentication"

# TC-86: Corporate SSO portal — login in path on known domain
cargo run -p garuda-cli -- check "https://login.microsoftonline.com/common/oauth2/authorize"

# TC-87: Stripe checkout — legitimate payment processor
cargo run -p garuda-cli -- check "https://checkout.stripe.com/pay/cs_test_abc123"

# TC-88: DigiLocker legitimate — gov.in with auth in path
cargo run -p garuda-cli -- check "https://digilocker.gov.in/public/oauth2/1/authorize"

# TC-89: NPCI UPI portal — legitimate Indian payment infra
cargo run -p garuda-cli -- check "https://www.npci.org.in/what-we-do/upi/product-overview"

# TC-90: WazirX crypto exchange India — wallet in path
cargo run -p garuda-cli -- check "https://wazirx.com/exchange/BTC-INR"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 17: INDIA-SPECIFIC THREAT VECTORS (Expected: Block)
# SMS phishing, Aadhaar scams, UPI fraud, govt portal spoofing
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-17] India-Specific Threats — Expected: BLOCK\n"

# TC-91: Aadhaar OTP update scam — common SMS phishing vector
cargo run -p garuda-cli -- check "https://uidai-aadhaar-update.com/otp-verify"

# TC-92: UPI fraud — fake NPCI portal
cargo run -p garuda-cli -- check "https://npci-upi-verify.in/kyc-update"

# TC-93: Fake income tax refund portal
cargo run -p garuda-cli -- check "https://incometax-refund-claim.com/verify-pan"

# TC-94: IRCTC ticket booking phishing
cargo run -p garuda-cli -- check "https://irctc-ticket-booking-verify.in/login"

# TC-95: DigiLocker fake document verification
cargo run -p garuda-cli -- check "https://digilocker-verify-document.com/aadhaar"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 18: ADVERSARIAL EDGE CASES (Expected: Block)
# Tricky structural attacks not covered in batch 1
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n[CAT-18] Adversarial Edge Cases — Expected: BLOCK\n"

# TC-96: Port number in URL to bypass hostname matching
cargo run -p garuda-cli -- check "http://paypal.com.login-verify.com:8080/signin"

# TC-97: Credentials in URL — userinfo field abuse
cargo run -p garuda-cli -- check "https://paypal.com@evil-harvest.com/login"

# TC-98: intent:// deep link scheme — mobile phishing
cargo run -p garuda-cli -- check "intent://evil.com/steal#Intent;scheme=https;end"

# TC-99: Null byte injection attempt in URL
cargo run -p garuda-cli -- check "https://paypal.com%00.evil.com/login"

# TC-100: Mixed script domain — Latin + Cyrillic in same label (confusable)
cargo run -p garuda-cli -- check "https://www.раypal.com/account/login"

echo -e "\n════════════════════════════════════════════════════════"
echo " Batch 2 Complete — TC-51 to TC-100"
echo " Full Suite: 100 / 100"
echo "════════════════════════════════════════════════════════"