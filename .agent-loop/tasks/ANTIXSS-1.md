# ANTIXSS-1: Add modern XSS payload regressions

Goal: turn representative vectors from the PayloadsAllTheThings XSS Injection catalog into focused regression tests for `AntiXSS::xss_clean()`.

Constraints:

- preserve PHP 7.1+ support;
- do not change production code unless a new regression test demonstrates an executable XSS primitive survives sanitization;
- prefer assertions about security properties over brittle full-output snapshots;
- run the focused regression test first, then the complete PHPUnit suite.

External reference:

- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md
