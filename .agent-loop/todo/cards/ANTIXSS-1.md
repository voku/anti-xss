# ANTIXSS-1: Add modern XSS payload regressions

- **Ticket:** ANTIXSS-1
- **Lane:** VERIFY
- **Status:** Verified
- **Domain:** Security
- **Summary:** Add focused regression coverage derived from PayloadsAllTheThings XSS vectors and fix only demonstrated sanitizer gaps.
- **Validation:** php vendor/bin/phpunit -c phpunit.xml --filter PayloadsAllTheThingsTest && php vendor/bin/phpunit -c phpunit.xml
- **Priority:** 0
- **Format version:** 1

## Agent Task Brief

Use the XSS Injection README from swisskyrepo/PayloadsAllTheThings as the external attack-catalog reference. Add representative regression cases for script tags, event handlers, SVG/HTML5 vectors, dangerous URI schemes, and encoded/whitespace-obfuscated schemes. Preserve the existing PHP 7.1+ runtime support. Change production code only for a failing case that still represents executable browser behavior after sanitization, then run the full test suite.
