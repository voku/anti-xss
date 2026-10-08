# voku/anti-xss threat model

## What it is
PHP library (src/voku/helper/AntiXSS.php) that sanitizes untrusted strings/arrays
via `xss_clean()` and reports detection via `isXssFound()`.

## Adversarial input
Everything passed to `xss_clean()` (strings and array values/keys) is attacker
controlled, including its encoding (UTF-8, entities, null bytes, broken markup).
Configuration methods (`add*`/`remove*`, `setReplacement`, ...) are called by the
trusted application developer and are NOT attacker controlled.

## In scope
- Sanitizer bypass: output of `xss_clean()` that executes script when inserted in
  an HTML body, quoted/unquoted attribute, or href/src context in a modern browser,
  using default settings.
- `isXssFound()` returning false for input that `xss_clean()` had to alter
  to remove an XSS payload.
- ReDoS / pathological CPU or memory use on crafted input (denial of service).
- PHP errors/fatals triggered by crafted input.

## Out of scope
- Contexts the library does not claim to protect (inside <script>/<style>, JS
  string or CSS contexts, inline event contexts); callers must escape there.
- Bypasses needing non-default config or developer-supplied weakening.
- Issues in dev dependencies, tests, or tooling.

## Severity
- High: default-config bypass that yields script execution in HTML body/attribute.
- Medium: bypass needing an uncommon but plausible config, or a browser-quirk-only vector.
- Medium/High: ReDoS with input under 100 KB causing multi-second hangs.
- Low: hardening, inconsistent `isXssFound()`, non-exploitable warnings.

## Reports
Please include a minimal PHP reproducer (input string -> output) and the browser
context in which it executes. Minimal patches plus a regression test in
tests/XssTest.php are preferred. Deduplicate by root-cause regex/code path.
