# Changelog

### 4.1.50 (2026-11-19)

- security: "xss_clean()" fails closed, if PCRE fails (e.g. "pcre.backtrack_limit" exhausted, also with "pcre.jit" disabled): before, e.g. "pcre.jit=0" + "pcre.backtrack_limit=1" returned '<script>alert(1)</script>' unchanged with "isXssFound() === false", because a failed "preg_replace()" erased the string before the backup (also inside "portable-utf8", e.g. "UTF8::rawurldecode()" / "UTF8::remove_invisible_characters()"), and other steps kept the unfiltered string ("$tmp ?? $str"); every PCRE call on the cleaning path was checked: a failed guard now runs its step, a failed removal uses a non-regex fallback ("_failClosedRemoveAttributesByName()" or the one terminal fallback "_failClosedNeutralize()": decode character references, remove ":", "+" and control chars, HTML-encode everything incl. every remaining "&", so that the result has no tag and no URL scheme, also in a quoted attribute), the "portable-utf8" calls are checked via "preg_last_error()", and "%uXXXX" is decoded without PCRE (a failure in "portable-utf8" there was hidden by a later successful PCRE call)
- tests: add "PcreFailureTest" (every "pcre.jit" 0 / 1 + "pcre.backtrack_limit" 1 - 1000 setting in a separate PHP process, also for the code coverage; the existing test only used a tight limit with the JIT enabled, which hides most failures) and direct tests of the fail-closed fallbacks
- security: remove every event handler attribute ("on" + ASCII letters as attribute name, e.g. "ongesturestart", "onwebkitmouseforcedown" or a future event), not only the names on "_never_allowed_on_events_afterwards"; the attributes are found with the rules of the HTML tokenizer (from every possible start tag), so text and attribute values like 'title="onreading mode"', 'data-onclick' or "on:click" are kept (WebKit gesture / force-touch events were not on the list and stayed executable in Safari)
- security: with the old list, 264 - 281 (depending on the payload) of 514 event names known to the specs and browser engines survived "xss_clean()"; now none does (checked in PHP and in Chromium, also for random unknown names)
- fix: an event name directly after a "-" is not removed from text and attribute names anymore (e.g. 'data-onclick="..."' was changed to 'data-="..."', 'aria-onfocus-hint' to 'aria--hint')
- breaking (security): unknown "on..." attributes with a value are removed now, e.g. '<x onxxx=1>' (they were kept as unknown names before); "removeNeverAllowedOnEventsAfterwards()" still allows the removed names
- tests: add "EventHandlerAttributeTest" (contract, syntax variations, seeded random event names, parser contexts, public API, runtime budget / fail-closed fallback), benign content cases and a Chromium browser test ("tests/browser/event-handler-attributes.php", also in CI)
- tests: add "tests/fixtures/browser-event-handlers.txt" (514 names, generated from pinned upstream revisions by "build/event-handlers/extract.py") as a test resource; the runtime list is unchanged; names that start with "on" but are not "on" + ASCII letters are listed there as "excluded" (currently none), so that a new one shows up in the check
- tests: regenerate the differential corpus (18 of 2000 results changed, all reviewed)

### 4.1.49 (2026-11-18)

- fix regression from 4.1.47: harmless HTML from Microsoft Word / Excel (e.g. "<o:Title>", "<x:Selected/>", "<x:Header>", "<x:FormulaHidden/>") was encoded and reported as XSS; a tag with an XML namespace prefix is now only treated as an evil tag, if its local name is exactly the (lowercase) evil tag name (e.g. "<x:script>")
- fix regression from 4.1.47: ANSI color codes (e.g. "ESC [ 32 m") were removed and reported as XSS; only the ISO-2022-JP escape sequences ("ESC (" and "ESC $") are treated as XSS now
- tests: add a regression test for harmless real-world content (unchanged + not reported as XSS, like in 4.1.46)
- tests: the browser tests initialize their "payload executed" flags before any payload is rendered
- tests: add a deterministic differential corpus (2,000 seeded inputs, compared with the results of 4.1.48 / 4.1.47)
- ci: raise the Infection gate for changed lines from 65% to 70% MSI (measured: 73.7% for 4.1.47, 97% for 4.1.48)

### 4.1.48 (2026-11-18)

- security: fix a memory-amplification (denial of service) regression from 4.1.47: the event-handler removal needed ~150x and the html-tag scan ~35x the memory of the input (e.g. 1.5 MB of " onclick" needed > 200 MB); both now need ~4x (like 4.1.46)
- add memory-budget regression tests (in a separate PHP process with a fixed "memory_limit")
- add a Chromium browser test for the XSS-filter bypasses fixed in 4.1.47 (GHSA-v42h-26cv-jpgq), incl. a raw negative control

### 4.1.47 (2026-11-17)

- security: fix an XSS-filter bypass via a numeric character reference without ";" (e.g. "&#x3a" / "&#58") followed by a char that is removed before decoding (e.g. "%0b", "%0c", U+FEFF)
- security: fix an XSS-filter bypass on XHTML pages via namespace-prefixed tags (e.g. "<x:script>")
- security: fix an XSS-filter bypass via other spellings of encoded script-tags (e.g. "&lt;script &gt;", "&lt;script/x&gt;", "&#60;script>")
- security: fix an XSS-filter bypass on ISO-2022-JP pages via ESC-sequences (e.g. "ESC ( B") inside of keywords
- security: fix an XSS-filter bypass via "javascript" + an encoded ":" (e.g. "javascript&colon;") in text next to html-tags
- security: fix an XSS-filter bypass where an evil tag directly after a look-alike tag (e.g. "<header><style>") was not encoded
- security: fix several denial-of-service issues (quadratic / exponential runtime on crafted input): compacting of exploded words, event-handler removal, the base64-image check, the html-tag decoding, nested attribute cleaning and the removal of nested url-encoded control chars
- fix: "addEvilHtmlTags()" with a short name (e.g. "s") does not shadow built-in evil tags (e.g. "style") anymore
- fix: content after an "<img>" / "<audio>" / "<video>" / "<source>" tag without attributes is not deleted anymore
- fix: many event names in front of one ">" do not throw a "non-converging sanitization loop"-exception anymore
- fix: an inline option (e.g. "(?-i)") in a regex from "addNeverAllowedRegex()" does not change the built-in regexes anymore
- fix: "removeNeverAllowedRegex(['regex' => 'replacement'])" removes only this regex (and not every regex with the same replacement)
- fix: remove the "shadowrootmode" attribute (declarative shadow DOM)
- fix: detect "data:" URLs split by tabs / newlines (e.g. "da\tta:", "image/s\nvg")
- "%0C" (url-encoded form feed) is now replaced by a space instead of being removed
- add regression tests for all findings (GHSA-v42h-26cv-jpgq), thanks to Anthropic's OSS Scanner
- ci: lower the Infection gate for changed lines (MSI 100% -> 65%, max. 40 timeouts)

### 4.1.46 (2026-11-07)

- security: fix XSS-filter bypass via missing HTML tags (e.g. "<geolocation>", "<permission>", "<camera>", "<microphone>", "<portal>") and missing modern DOM event handlers (e.g. "onvalidationstatuschange", "onpromptaction", "onpromptdismiss", "onnavigate*", "onvisibilitychange", ...) (GHSA-28pp-7fjp-8v32)

### 4.1.45 (2026-10-09)

- security: fix an XSS-filter bypass where an evil tag followed by a tab, CR, LF or FF instead of a space (e.g. "<style\t>", "<svg\n>", "<math\r>", "<frameset\f>") was emitted unencoded; a raw "<style>" stayed open (its closing tag is encoded) and allowed CSS injection (e.g. "@import", "url()" exfiltration) and swallowed the following page content
- add OSS Scanner configuration (".oss-scanner/") and document how to run the tests

### 4.1.44 (2026-07-10)

- add more modern DOM event handlers to the blacklist (e.g. "onAppInstalled", "onBeforeInstallPrompt", "onFormData", "onGamepadConnected/Disconnected", "onMessageError", "onScrollEnd", "onSecurityPolicyViolation", "onSlotChange", "onVRDisplay*", ...)
- harden detection of hyphen-/colon-suffixed event-handler lookalikes (e.g. "onmessageerror-foo") so the whole attribute is removed instead of leaving a broken attribute with leftover payload text
- fix regression: the lookalike-hardening above could also strip the value of unrelated, legitimate compound attributes that merely contain an event name after a hyphen (e.g. "data-onchange-debounce="300""); only real handler-lookalikes are removed now
- harden CSS "expression(...)" detection, incl. escaped and uppercase variants, and fix a regex backtracking risk
- add a hard cap on internal sanitization retry-loops (throws "RuntimeException" instead of looping forever if a loop can't converge)
- preserve custom / removed "_never_allowed_regex" entries across "setReplacement()" calls
- fix: several tag/attribute-stripping steps silently wiped the whole string to "" when "preg_replace()"/"preg_replace_callback()" hit "pcre.backtrack_limit" (or its fallback also failed); they now fail closed via a bounded, non-regex removal of the specific dangerous tag/attribute instead of discarding unrelated content or falling back to the still-dangerous raw input
- add regression test for issue #201 (template + slot "onslotchange" XSS)
- add mutation testing (Infection) to CI with a diff MSI gate

### 4.1.43 (2026-04-22)

- 10-50% better performance
- add "addNaughtyJavascriptPatterns()"
- add "setKeepPreAndCodeTagContent()" to preserve content inside "pre" and "code" tags
- fix regression when sanitizing text inside "pre" / "code" tags
- fix false-positives for valid "href" / "src" URLs and plain text such as "system (...)", "behavior:", "< abc" and "< 35kg"
- improve detection of obfuscated style / attribute payloads and JSON-escaped HTML attributes
- keep valid base64 payloads ending with "==" and avoid blank output if "preg_replace()" returns "null"
- update "portable-utf8" to "~6.1.0"
- improve CI / test compatibility (incl. PHP 8.5 + PHPUnit 12)

### 4.1.42 (2023-07-03)

- add more js events e.g. "onbeforetoggle"

### 4.1.41 (2023-02-12)

- remove debug call (thx @gharlan [Gregor Harlan]

### 4.1.40 (2023-02-11)

- fix xss bypass (issue 115 | thx @thanosgn [Thanos Giannopoulos])
- add more blacklisted js calls (thx @peter-mw [Peter Ivanov])
- fix false positive on self-close tags (issue 111 | thx @genetus [Maxim Antonov])

### 4.1.39 (2022-03-08)

- "To people of Russia": There is a war in Ukraine right now. The forces of the Russian Federation are attacking civilians.

### 4.1.38 (2022-03-07)

- optimize "_sanitize_naughty_javascript" (issue 99 | thx @Fahl-Design)
- optimize "_do_never_allowed_afterwards", at least for strings in tags

### 4.1.37 (2022-02-15)

- move more static data into the object
  - allow to modify the "_never_allowed_call_strings"-data"
  - allow to modify the "_never_allowed_js_callback_regex"-data"

### 4.1.36 (2022-01-27)

- update "portable-utf8"

### 4.1.35 (2021-12-08)

- update "portable-utf8"

### 4.1.34 (2021-11-29)

- allow e.g. "< 1 year" (issue 83)
- fix false-positive issue (issue 85 | thx @gharlan)

### 4.1.33 (2021-10-04)

- fix errors in large strings
- fix "_xss_found" if xss string was found in array value

### 4.1.32 (2021-03-29)

- micro-optimize performance
- optimize phpdocs + use phpstan-syntax


### 4.1.31 (2020-12-02)

- optimize performance (thx @staabm)
- update vendor lib (Portable UTF-8)


### 4.1.30 (2020-11-12)

- update vendor lib (Portable UTF-8)


### 4.1.29 (2020-11-09)

- allow e.g. "<35%" (issue #62)
- allow to skip some html tags from auto closing (issue #63)
- run tests with PHP 8.0 rc3


### 4.1.28 (2020-08-28)

- fix allow base64 encoded images in <img>-tags (issue #61)
- fix performance issue of regex with "preg_match_all"


### 4.1.27 (2020-08-23)

- allow e.g. "< $2.20" (issue #60)
- optimize protection against HTML "script" tag stripping evasion
- auto-generate the api documentation into the README


### 4.1.26 (2020-08-08)

- allow base64 encoded images in <img>-tags (issue #59)


### 4.1.25 (2020-06-12)

- fix false-positive (issue #58)


### 4.1.24 (2020-03-08)

- allow to change the "_never_allowed_str_afterwards" (issue #56)
- fix false-positive (issue #55)


### 4.1.23 (2020-03-06)

- use some more bad strings from "https://github.com/s0md3v/AwesomeXSS"
- optimize some regex (use strpos before the regex)


### 4.1.22 (2020-02-06)

- fix false-positive (issue #54)
- optimize internal caching of strings


### 4.1.21 (2019-12-30)

- fix false-positive (issue #53)
- fix for "server-sent events"
- optimize regex for encoded script-tags (%3C && %3E)


### 4.1.20 (2019-12-07)

- fix additional false positives in string (issue #52)
- remove support for "Netscape 4 JS entities"


### 4.1.19 (2019-11-11)

- keep more non XSS content from html input


### 4.1.18 (2019-11-11)

- fix open tags problem e.g. "<img/"


### 4.1.17 (2019-11-08)

- add "addNeverAllowedRegex()"
- add "removeNeverAllowedRegex()"


### 4.1.16 (2019-11-03)

- fix replacing of "-->" (issue #50)
- update vendor lib (Portable UTF-8)


### 4.1.15 (2019-09-26)

- optimize regex
- update vendor lib (Portable UTF-8)


### 4.1.14 (2019-06-27)

- add "removeNeverAllowedOnEventsAfterwards()" && "addNeverAllowedOnEventsAfterwards()"
- update "_never_allowed_on_events_afterwards" -> add "onTouchend" + "onTouchLeave" + "onTouchMove" (thx @DmytroChymyrys)
- optimize phpdoc for array => string[]


### 4.1.13 (2019-06-08)

- fix replacing of false-positive xss words e.g. "<script@gmail.com>" (issue #44)


### 4.1.12 (2019-05-31)

- fix replacing of false-positive xss words e.g. "<video@gmail.com>" (issue #44)


### 4.1.11 (2019-05-28)

- fix replacing of false-positive xss words e.g. "<styler_tester@gmail.com>" (issue #44)


### 4.1.10 (2019-04-19)

- fix replacing of false-positive xss words e.g. "ANAMNESI E VAL!DEFINITE BREVI ORTO" (issue #43)


### 4.1.9 (2019-04-19)

- optimize the spacing regex


### 4.1.8 (2019-04-19)

- fix replacing of false-positive xss words e.g. "MONDRAGÓN" (issue #43)


### 4.1.7 (2019-04-19)

- fix replacing of false-positive xss words e.g. "DE VAL HERNANDEZ" (issue #43)


### 4.1.6 (2019-04-12)

- fix replacing of false-positive xss words e.g. "Mondragon" (issue #43)


### 4.1.5 (2019-02-13)

- fix issue with "()" in some html attributes (issue #41)


### 4.1.4 (2019-01-22)

- use new version of "Portable UTF8"


### 4.1.3 (2018-10-28)

- fix for url-decoded stored-xss
- fix return type (?string -> string)


### 4.1.2 (2018-09-13)

- use new version of "Portable UTF8"
- add some more event listener
- use PHPStan


### 4.1.1 (2018-04-26)

- "UTF7 repack corrected" | thx @alechner #34


### 4.1.0 (2018-04-17)

- keep the input value (+ encoding), if no xss was detected #32


### 4.0.3 (2018-04-12)

- fix "href is getting stripped" #30


### 4.0.2 (2018-02-14)

- fix "URL escaping bug" #29


### 4.0.1 (2018-01-07)

- fix usage of "Portable UTF8"


### 4.0.0 (2017-12-23)
- update "Portable UTF8" from v4 -> v5

  -> this is a breaking change without API-changes - but the requirement
     from "Portable UTF8" has been changed (it no longer requires all polyfills from Symfony)


### 3.1.0 (2017-11-21)
- add "_evil_html_tags" -> so you can remove / add html-tags


### 3.0.1 (2017-11-19)
- "php": ">=7.0"
  * use "strict_types"
- simplify a regex


### 3.0.0 (2017-11-19)
- "php": ">=7.0"
  * drop support for PHP < 7.0
