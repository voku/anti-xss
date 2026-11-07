<?php

declare(strict_types=1);

require \dirname(__DIR__, 2) . '/vendor/autoload.php';

use voku\helper\AntiXSS;

/**
 * Generate a static browser fixture for GHSA-28pp-7fjp-8v32.
 *
 * The browser test must independently check the resulting DOM, rather than
 * assuming that a PHP string assertion describes how HTML will be parsed.
 *
 * @var array<string, string> $payloads
 */
$payloads = [
    'geolocation' => '<geolocation onvalidationstatuschange="window.__xssExecuted = true">x</geolocation>',
    'permission' => '<permission type="geolocation" onvalidationstatuschange="window.__xssExecuted = true">x</permission>',
    'modern-event' => '<div onpromptaction="window.__xssExecuted = true">x</div>',
    'camera' => '<camera onvalidationstatuschange="window.__xssExecuted = true">x</camera>',
    'microphone' => '<microphone onvalidationstatuschange="window.__xssExecuted = true">x</microphone>',
    'portal' => '<portal onpromptdismiss="window.__xssExecuted = true">x</portal>',
    'navigation-event' => '<div onnavigate="window.__xssExecuted = true">x</div>',
    'visibility-event' => '<div onvisibilitychange="window.__xssExecuted = true">x</div>',
    'safe-url' => '<a href="https://example.invalid/?onlyEnabled=1">allowed link</a>',
    'safe-content' => '<div class="safe" data-test="preserve">safe text</div>',
];

echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>GHSA browser smoke</title></head><body>', "\n";

foreach ($payloads as $name => $payload) {
    $cleaned = (new AntiXSS())->xss_clean($payload);

    echo '<section class="sanitized" data-case="',
        \htmlspecialchars($name, ENT_QUOTES, 'UTF-8'),
        '">',
        $cleaned,
        '</section>',
        "\n";
}

// A deliberately UNSANITIZED control verifies that inline browser events work.
// It must never be treated as sanitized input.
echo '<button id="raw-control" onclick="window.__controlExecuted = true" type="button">control</button>', "\n";
?>
<script>
'use strict';

window.__controlExecuted = false;
window.__xssExecuted = false;

window.addEventListener('load', function () {
    const errors = [];
    document.getElementById('raw-control').click();

    if (window.__controlExecuted !== true) {
        errors.push('positive-control-not-executed');
    }

    const sections = Array.from(document.querySelectorAll('section.sanitized'));
    if (sections.length !== 10) {
        errors.push('missing-sanitized-cases');
    }

    for (const section of sections) {
        const descendants = Array.from(section.querySelectorAll('*'));

        for (const element of descendants) {
            if (['GEOLOCATION', 'PERMISSION', 'CAMERA', 'MICROPHONE', 'PORTAL'].includes(element.tagName)) {
                errors.push('dangerous-element-' + section.dataset.case);
            }

            for (const attribute of Array.from(element.attributes)) {
                if (/^on/i.test(attribute.name)) {
                    errors.push('inline-event-' + section.dataset.case);
                }
            }

            element.dispatchEvent(new Event('validationstatuschange', { bubbles: true }));
            element.dispatchEvent(new Event('promptaction', { bubbles: true }));
            element.dispatchEvent(new Event('navigate', { bubbles: true }));
            element.dispatchEvent(new Event('visibilitychange', { bubbles: true }));
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

    if (window.__xssExecuted === true) {
        errors.push('sanitized-handler-executed');
    }

    document.body.dataset.ghsaStatus = errors.length === 0 ? 'pass' : 'fail';
    document.body.dataset.ghsaDetails = errors.length === 0 ? 'none' : errors.join(',');
});
</script>
</body></html>
