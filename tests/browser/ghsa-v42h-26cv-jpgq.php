<?php

declare(strict_types=1);

require \dirname(__DIR__, 2) . '/vendor/autoload.php';

use voku\helper\AntiXSS;

// Explicit negative-control mode: render the same payloads without sanitization.
$rawMode = ($argv[1] ?? null) === '--raw' && \count($argv) === 2;
if (\count($argv) > 1 && !$rawMode) {
    throw new \InvalidArgumentException('Expected no arguments or only --raw.');
}

/**
 * Generate a static browser fixture for the XSS-filter bypasses fixed in 4.1.47 (GHSA-v42h-26cv-jpgq).
 *
 * The browser checks the resulting DOM (after its own HTML and URL parsing), instead of trusting that a
 * PHP string assertion describes how the HTML will be parsed. The XHTML ("<x:script>") and ISO-2022-JP
 * cases need another content type / charset and are covered by "tests/SecurityRegressionTest.php".
 *
 * @var array<string, array{0: string, 1: callable|null}> $payloads
 */
$payloads = [
    // ";"-less numeric character reference + a char that was removed before decoding
    'numeric-reference-hex' => ['<a href="javascript&#x3a%0bwindow.__xssExecuted=true">x</a>', null],
    'numeric-reference-dec' => ['<a href="javascript&#58%0c1;window.__xssExecuted=true">x</a>', null],
    'numeric-reference-bom' => ["<a href=\"javascript&#x3a\u{FEFF}window.__xssExecuted=true\">x</a>", null],
    // "javascript&colon;" in text next to a tag (e.g. printed into an attribute by the application)
    'encoded-colon' => ['<a href="javascript&colon;window.__xssExecuted=true//<b>">x</a>', null],
    // other spellings of an encoded script-tag in "srcdoc" (iframes allowed)
    'srcdoc-script' => [
        '<iframe srcdoc=&lt;script/x&gt;parent.__xssExecuted=true&lt;/script/x&gt;></iframe>',
        static function (AntiXSS $antiXss) {
            $antiXss->removeEvilHtmlTags(['iframe']);
        },
    ],
    // an evil tag directly after a look-alike tag
    'header-style' => ['<header><style>body{--xss:1}</style></header>', null],
    // a short custom evil tag must not shadow "<style>"
    'custom-short-tag' => [
        '<style>body{--xss:1}</style>',
        static function (AntiXSS $antiXss) {
            $antiXss->addEvilHtmlTags(['s']);
        },
    ],
    // declarative shadow DOM
    'shadowrootmode' => ['<div><template shadowrootmode="open"><b>hidden</b></template>x</div>', null],
    'safe-url' => ['<a href="https://example.invalid/?onlyEnabled=1">allowed link</a>', null],
    'safe-content' => ['<div class="safe" data-test="preserve">safe text</div>', null],
];

// INFO: the flag is initialized before any payload is rendered, so that a payload that runs while the page is
//       parsed can not be hidden by a later reset
echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>GHSA-v42h-26cv-jpgq browser smoke</title>',
    '<script>window.__xssExecuted = false;</script></head><body>', "\n";

foreach ($payloads as $name => [$payload, $config]) {
    $antiXss = new AntiXSS();
    if ($config !== null) {
        $config($antiXss);
    }

    $cleaned = $rawMode ? $payload : $antiXss->xss_clean($payload);

    echo '<section class="sanitized" data-case="',
        \htmlspecialchars($name, ENT_QUOTES, 'UTF-8'),
        '">',
        $cleaned,
        '</section>',
        "\n";
}
?>
<script>
'use strict';

window.addEventListener('load', function () {
    const errors = [];
    try {
        const sections = Array.from(document.querySelectorAll('section.sanitized'));
        if (sections.length !== 10) {
            errors.push('missing-sanitized-cases');
        }

        for (const section of sections) {
            const name = section.dataset.case;

            for (const element of Array.from(section.querySelectorAll('*'))) {
                if (['SCRIPT', 'STYLE'].includes(element.tagName)) {
                    errors.push('dangerous-element-' + name);
                }

                if (element.shadowRoot !== null || element.hasAttribute('shadowrootmode')) {
                    errors.push('shadow-root-' + name);
                }

                for (const attribute of Array.from(element.attributes)) {
                    if (/^on/i.test(attribute.name)) {
                        errors.push('inline-event-' + name);
                    }
                }

                // the URL as the browser parsed it (incl. entity decoding and removal of tabs / newlines)
                if (element.tagName === 'A' && element.hasAttribute('href')) {
                    const protocol = new URL(element.getAttribute('href'), document.baseURI).protocol;
                    if (protocol === 'javascript:') {
                        errors.push('javascript-url-' + name);
                    } else if (name !== 'safe-url' && protocol !== 'about:' && element.getAttribute('href') !== '') {
                        // the dangerous links must not survive as another (unexpected) URL either
                        errors.push('unexpected-url-' + name + ':' + protocol);
                    }
                }

                if (element.tagName === 'IFRAME' && element.hasAttribute('srcdoc')) {
                    const framed = new DOMParser().parseFromString(element.getAttribute('srcdoc'), 'text/html');
                    if (framed.querySelector('script') !== null) {
                        errors.push('srcdoc-script-' + name);
                    }
                }
            }
        }

        // click every remaining "javascript:" link (only the raw negative control has them), so that the
        // harness proves real execution; other links are not clicked, because they would navigate away
        for (const link of Array.from(document.querySelectorAll('section.sanitized a[href]'))) {
            if (new URL(link.getAttribute('href'), document.baseURI).protocol === 'javascript:') {
                link.click();
            }
        }

        const safe = document.querySelector('section[data-case="safe-content"] .safe');
        if (safe === null || safe.dataset.test !== 'preserve' || safe.textContent !== 'safe text') {
            errors.push('safe-content-changed');
        }

        const safeUrl = document.querySelector('section[data-case="safe-url"] a');
        if (safeUrl === null || safeUrl.getAttribute('href') !== 'https://example.invalid/?onlyEnabled=1') {
            errors.push('safe-url-changed');
        }
    } catch (error) {
        errors.push('harness-exception:' + String(error));
    }

    // give clicked "javascript:" links / framed documents the time to run
    setTimeout(function () {
        if (window.__xssExecuted === true) {
            errors.push('sanitized-payload-executed');
        }

        document.body.dataset.ghsaExecuted = window.__xssExecuted === true ? 'true' : 'false';
        document.body.dataset.ghsaStatus = errors.length === 0 ? 'pass' : 'fail';
        document.body.dataset.ghsaDetails = errors.length === 0 ? 'none' : errors.join(',');
    }, 500);
});
</script>
</body></html>
