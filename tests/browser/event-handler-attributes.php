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
 * Generate a static browser fixture for the structural event handler filter (4.1.49).
 *
 * 1. Every case is parsed by the browser (DOMParser, one document per case, so that a broken case can not hide the
 *    next ones): no element may have an attribute "on" + ASCII letters, and the harmless cases must keep their
 *    attributes. The attributes of an element are found by the HTML tokenizer, which is the same in all browsers,
 *    so this also shows that e.g. Safari can not see an "ongesturestart" attribute.
 * 2. Payloads that run without user interaction are rendered into the page, to check that nothing is executed.
 */
$known = [];
foreach (\file(\dirname(__DIR__) . '/fixtures/browser-event-handlers.txt', \FILE_IGNORE_NEW_LINES | \FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
    if ($line[0] !== '#') {
        $known[] = \explode(' ', $line, 2)[0];
    }
}

$attacks = [];
foreach ($known as $name) {
    $attacks['known-' . $name] = '<div class="keep" ' . $name . '="window.__xssExecuted = true">x</div>';
}

\mt_srand(20261119);
$letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
for ($i = 0; $i < 100; ++$i) {
    $name = 'on';
    for ($j = \mt_rand(1, 20); $j > 0; --$j) {
        $name .= $letters[\mt_rand(0, 51)];
    }
    $attacks['random-' . $i] = '<svg><rect ' . $name . '=window.__xssExecuted=true /></svg><p title="t" ' . $name . '=\'1\'>x</p>';
}

$attacks += [
    'advisory-gesturestart'   => '<div ongesturestart="alert(1)">x</div>',
    'advisory-gesturechange'  => '<a ongesturechange="location=name">x</a>',
    'advisory-forcedown'      => '<div onwebkitmouseforcedown="alert(1)">x</div>',
    'syntax-no-whitespace'    => '<a href="#"onfoo=1>x</a>',
    'syntax-slash'            => '<img/onfoo=1>',
    'syntax-form-feed'        => "<div\x0Confoo=1>x</div>",
    'syntax-uppercase'        => '<DIV ONFOO=1>x</DIV>',
    'context-textarea'        => '<textarea><p title="</textarea><img src=x onfoo=alert(1)>"></textarea>',
    'context-comment'         => '<!-- <p title=" --><img src=x onfoo=alert(1)>"> -->',
    'context-title'           => '<title><a title="</title><img onfoo=alert(1)>"></title>',
    'context-attribute-value' => '<p title="<b onfoo=alert(1)>">x</p>',
    'context-template'        => '<template><div onfoo=1>x</div></template>',
    'context-mathml'          => '<math><mi onfoo=1>x</mi></math>',
];

/** @var array<string, array{0: string, 1: string, 2: string}> $benign case => [html, selector, attribute] */
$benign = [
    'data-onclick'      => ['<div data-onclick="example">x</div>', 'div', 'data-onclick'],
    'data-onupdate'     => ['<div data-onupdate="manual">Example</div>', 'div', 'data-onupdate'],
    'aria-onfocus-hint' => ['<div aria-onfocus-hint="x">x</div>', 'div', 'aria-onfocus-hint'],
    'title-onreading'   => ['<p title="onreading mode">Read</p>', 'p', 'title'],
    'class-onboarding'  => ['<div class="onboarding">x</div>', 'div', 'class'],
    'svelte-on-click'   => ['<div on:click="save">Save</div>', 'div', 'on:click'],
    'url-online'        => ['<a href="https://example.invalid/?online=1">x</a>', 'a', 'href'],
];

/** @var array<string, string> $autofire payloads that run without user interaction */
$autofire = [
    'img-onerror'     => '<img src="data:," onerror="window.__xssExecuted = true">',
    'svg-onload'      => '<svg onload="window.__xssExecuted = true"></svg>',
    'details-toggle'  => '<details open ontoggle="window.__xssExecuted = true">x</details>',
    'input-autofocus' => '<input autofocus onfocus="window.__xssExecuted = true">',
    'unknown-onerror' => '<img src="data:," oNeRrOr = \'window.__xssExecuted = true\'>',
    'context-textarea' => '<textarea><p title="</textarea><img src="data:," onerror="window.__xssExecuted = true">"></textarea>',
];

$clean = static function ($html) use ($rawMode) {
    return $rawMode ? $html : (new AntiXSS())->xss_clean($html);
};

$parseCases = [];
foreach ($attacks as $name => $html) {
    $parseCases[] = ['name' => $name, 'html' => $clean($html), 'benign' => null];
}
foreach ($benign as $name => $case) {
    $parseCases[] = ['name' => 'benign-' . $name, 'html' => $clean($case[0]), 'benign' => [$case[1], $case[2]]];
}

$json = \json_encode($parseCases, \JSON_HEX_TAG | \JSON_HEX_AMP | \JSON_HEX_APOS | \JSON_HEX_QUOT | \JSON_UNESCAPED_UNICODE | \JSON_INVALID_UTF8_SUBSTITUTE);

// INFO: the flags are initialized before any payload is rendered, so that a payload that runs while the page is
//       parsed can not be hidden by a later reset
echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Event handler attributes browser test</title>',
    '<script>window.__controlExecuted = false; window.__xssExecuted = false;</script>',
    '</head><body>', "\n";

foreach ($autofire as $name => $payload) {
    echo '<section class="sanitized" data-case="', \htmlspecialchars($name, \ENT_QUOTES, 'UTF-8'), '">',
        $clean($payload),
        '</section>', "\n";
}

// A deliberately UNSANITIZED control verifies that inline browser events work.
echo '<button id="raw-control" onclick="window.__controlExecuted = true" type="button">control</button>', "\n";
?>
<script>
'use strict';

const parseCases = <?php echo $json; ?>;
const autofireCount = <?php echo \count($autofire); ?>;

function elementsOf(root) {
    const result = [];
    for (const element of Array.from(root.querySelectorAll('*'))) {
        result.push(element);
        if (element.tagName === 'TEMPLATE') {
            result.push(...elementsOf(element.content));
        }
    }
    return result;
}

window.addEventListener('load', function () {
    const errors = [];
    try {
        document.getElementById('raw-control').click();
        if (window.__controlExecuted !== true) {
            errors.push('positive-control-not-executed');
        }

        const parser = new DOMParser();
        for (const testCase of parseCases) {
            const parsed = parser.parseFromString(testCase.html, 'text/html');
            for (const element of elementsOf(parsed)) {
                for (const attribute of Array.from(element.attributes)) {
                    if (/^on[a-z]+$/i.test(attribute.name)) {
                        errors.push('event-attribute:' + testCase.name + ':' + attribute.name);
                    }
                }
            }

            if (testCase.benign !== null) {
                const element = parsed.body.querySelector(testCase.benign[0]);
                if (element === null || !element.hasAttribute(testCase.benign[1])) {
                    errors.push('benign-changed:' + testCase.name);
                }
            }
        }

        const sections = document.querySelectorAll('section.sanitized');
        if (sections.length !== autofireCount) {
            errors.push('missing-autofire-cases:' + sections.length);
        }

        if (window.__xssExecuted === true) {
            errors.push('sanitized-handler-executed');
        }
    } catch (error) {
        errors.push('harness-exception:' + String(error));
    } finally {
        document.body.dataset.eventsCases = String(parseCases.length);
        document.body.dataset.eventsExecuted = window.__xssExecuted === true ? 'true' : 'false';
        document.body.dataset.eventsStatus = errors.length === 0 ? 'pass' : 'fail';
        document.body.dataset.eventsDetails = errors.length === 0 ? 'none' : errors.slice(0, 50).join(',');
        document.body.dataset.eventsErrorCount = String(errors.length);
    }
});
</script>
</body></html>
