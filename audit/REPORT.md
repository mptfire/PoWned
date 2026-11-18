# PoWned (gobrrrme/PoWned) — adversarial audit

Audited SHA: `0009d405ffb87ba610075acf3f783084b6866e1c` ("Update README…", 2026-11-18, v0.1.0, GPL-2.0, main).
Branches: `audit/2026-11-18` (this report + harness) + five fix branches → PRs #1–#5 on upstream.
Issues/PRs at audit time: none (clean slate). Environment: PHP 8.5.12 CLI (Termux/Android); no Podman/Linux box, no WordPress/WooCommerce runtime, no phpcs/phpstan/semgrep/playwright — those parts are hand-off items (§5).

## 1. Executive summary

PoWned is a small, unusually careful proof-of-work gate. The crypto is right
(stateless HMAC-signed challenges, 64-bit truncated MAC, `hash_equals`
everywhere, format-pinned cookie fields so there is no delimiter or padding
confusion, secret from `random_bytes(32)`, PoW re-verified server-side,
base-bits floor re-checked per request), the client binding uses only
`REMOTE_ADDR` (no spoofable `X-Forwarded-For` trust — verified by PoC), the
challenge template escapes everything (`htmlspecialchars` ENT_QUOTES on every
interpolation, no inline script/style), settings are sanitized with proper
bounds (bits 8–28, status whitelist, enforced `/wp-admin/`+`/wp-login.php`
exclusions), and the mu-plugin early loader is a fixed-name, self-guarding,
deactivation-clean generated file.

No exploitable vulnerability was found. Two medium operational findings and a
handful of low ones were fixed in PRs; per the brief, nothing qualified for
private disclosure (no bypass, no HMAC flaw, no XSS).

## 2. Findings

| ID | Sev | Finding | Evidence | Fix |
|----|-----|---------|----------|-----|
| T1 | **Med** | Unauthenticated write amplification: `powned_new` marker + fresh salts → transient row + counter `UPDATE` + `update_option` per block; native attacker mints a block in ~3 ms | PoC harness: 24 write batches / 20 mined blocks, unbounded | **PR #1** (1 counted block per client key per minute) |
| T2 | Med (deployment) | Reverse proxy: `REMOTE_ADDR` = proxy for all visitors → network binding collapses into one shared key; one solve unlocks the site for everyone. No trusted-proxy support exists (and none should be blind) | `client_key()` reads only `REMOTE_ADDR` | **PR #2** (warning notice + remediation guidance) |
| T3 | Med (deployment) | Page-cache drop-ins (`advanced-cache.php`) and CDN edge serve cached protected URLs **before** the gate runs; `DONOTCACHEPAGE` only protects the challenge page itself | WP load order (drop-ins before mu-plugins) | **PR #2** (warning when `WP_CACHE` on) |
| T4 | Low | Multisite: early-loader guard checks `active_plugins` only → network-activated install silently never runs the early check | loader generator code | **PR #3** |
| T5 | Low | No CSP header on the challenge page (template is already CSP-compatible) | template + headers | **PR #4** |
| T6 | Low | No SECURITY.md; readme overstates strength and omits proxy/cache/REST caveats | readme.txt | **PR #5** |
| T7 | Info | `/wp-json/*` (incl. WooCommerce Store API) excluded by default → filtered product **data** reachable without PoW (HTML pages stay gated) | defaults() | documented (PR #5); changing the default is a product call |
| T8 | Info | Effectiveness: 18 bits ≈ 260k SHA-256 ≈ **milliseconds natively**; per-/24 binding is useless against clouds/residential-proxy pools spanning /24s, and CGNAT /24s can share thousands of real users. The gate is a cost-per-URL speed bump, not an anti-bot boundary | arithmetic + design | documented (PR #5) |
| T9 | Info | Challenge harvest/replay: a block solved at idle (base 18) stays valid for 24 h even during load spikes (extra load-bits are not re-checked; only `base_bits` is) | `valid_cookie()` | VERIFIED — deliberate trade-off (re-checking would lock humans out after difficulty rises); documented |
| T10 | Info | `wildcard()` builds regex from admin-supplied patterns; pathological admin input (nested `*`) can self-ReDoS the admin's own site | code | VERIFIED (admin-only input; not attacker-controlled) |
| T11 | Info | `powned_secret` option is autoloaded (64 hex chars; negligible) and never rotated (no endpoint) | `secret()` | noted |
| T12 | Info | Uninstall leaves `_transient_powned_block_*`/`powned_rl_*` rows (≤60 s TTL — negligible); multisite uninstall is single-site | uninstall.php | noted |

## 3. Verified-by-PoC behaviors (all against the real class, WP-stubbed)

24 passing assertions + cross-process test (`php poc.php`):

- full mint → mine (PHP brute force) → `valid_cookie()` accept path
- nonce/mac/expiry/zero-pad/oversize/non-hex mutations all rejected
- `client_key()` unchanged under `X-Forwarded-For` / `CF-Connecting-IP` / `X-Real-IP` spoofing
- `/24` sharing accepted; different `/24` rejected
- bits floor across processes: 18-bit cookie **REJECTED** at base 20; control accepted (REJECTED/ACCEPTED printed)
- `filter_pa[]=`, `FILTER_PA`, substring non-match, POST never gated, `/wp-admin` exclusion wins over protected params, REST excluded, `//`-path param gating
- `zero_bits`/`hash256` vectors; **worker.js cross-check**: single-block double-SHA256 with correct padding and ≤55-byte input verified by source review (identical construction to PHP `hash256` on `challenge.nonce`)
- T1 after fix: writes stop after first counted block per client key

## 4. Environment matrix actually tested

| Component | Result |
|---|---|
| PHP 8.5.12 CLI, plugin class outside WP | all PoCs run |
| WordPress 6.2 / latest × PHP 7.4 / 8.3 × Apache / nginx × WC | **NOT RUN** (no container host on this device) — hand-off §5 |
| Reverse proxy / Cloudflare / WP Rocket / LiteSpeed / W3TC / APO | NOT RUN — analyzed statically (T2/T3) |
| Browser flow (human, no-JS, mobile, CSP console) | NOT RUN — no Playwright; template/JS reviewed line-by-line instead |

## 5. Hand-off (exact commands)

```
# container matrix (Linux box with podman):
podman run -d --name wp -p 8080:80 wordpress:6.2-php8.3 apache
# then: install plugin from audit branch, hit /shop/?filter_color=x,
# expect 403 challenge; solve in browser; expect reload; check wp_options
# writes while replaying powned_new (T1 pre-fix only)
podman run --rm -v $PWD:/app -w /app php:8.3-cli php poc.php
# static analysis:
composer require --dev wp-coding-standards/wpcs dealerdirect/phpcodesniffer-composer-plugin phpcompatibility/phpcompatibility-wp
vendor/bin/phpcs -p --standard=WordPress-Extra,WordPress-Security,PHPCompatibilityWP --runtime-set testVersion 7.4- .
vendor/bin/phpstan analyse -l 6 includes/ (with szepeviktor/phpstan-wordpress)
semgrep --config=p/php --config=p/wordpress --config=p/javascript .
npx eslint --ext .js assets/
gitleaks detect --source . --redact
wp plugin-check (Plugin Check) on an install
# Playwright: challenge flow, no-JS fallback, CSP console errors, cache-plugin runs
```

## 6. Priority order

1. Merge PR #1 (T1) — only finding with server impact.
2. Merge PR #2 (T2/T3) — protects every proxied/cached deployment.
3. Merge PR #3 (T4) if multisite is in scope.
4. Merge PR #4 (T5), PR #5 (T6) — hardening + honesty.
5. Consider later: trusted-proxy CIDR setting (proper T2 fix), difficulty re-issuance on load spikes (T9), secret rotation endpoint (T11).
