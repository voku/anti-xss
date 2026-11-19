<?php

declare(strict_types=1);

use voku\helper\AntiXSS;

/**
 * Deterministic differential regression test: a seeded corpus of random XSS-like inputs, compared against the
 * stored results of the previous release (output + "isXssFound()").
 *
 * The corpus was generated with 4.1.48 and was identical with 4.1.47. Any change in the output of the sanitizer
 * shows up here, so changes in behaviour are always visible and reviewed.
 *
 * Regenerated for 4.1.49 (18 of 2000 results changed, all reviewed): event names directly after a "-" are kept
 * (e.g. "&lt;-onclick", "<!--onerror="), and an event handler attribute with an unclosed quoted value is removed
 * up to the end of the input.
 *
 * Regenerate the fixture (only for intended changes): ANTI_XSS_UPDATE_CORPUS=1 php vendor/bin/phpunit tests/DifferentialCorpusTest.php
 *
 * @internal
 */
final class DifferentialCorpusTest extends \PHPUnit\Framework\TestCase
{
    private const SEED = 20261118;

    private const COUNT = 2000;

    /**
     * INFO: only ASCII tokens, so that the results are the same on all supported PHP versions
     *
     * @var string[]
     */
    private const TOKENS = [
        '<a ', '<img ', '<img>', '<svg', '<script>', '</script>', '<style>', '<iframe ', '<x:script>', '<header>',
        'href=', 'src=', 'srcdoc=', 'style=', '"', "'", '>', '<', ' ', "\t", "\n", '/', '\\', '`', '=', '(', ')',
        'javascript:', 'java', 'script', ':', '&#58', '&#x3a', '&#x3a;', '&colon;', '&lt;', '&gt;', '&lt;script',
        '&quot;', '%0b', '%0c', '%0d', '%00', '%3C', '%253C', '+ADw-', '-', 'onclick', 'onerror=', 'onload',
        'alert(1)', 'data:', 'text/html', 'image/svg+xml', 'base64,', 'PHNjcmlwdD4=', 'document.cookie',
        'expression(', '<!--', '-->', 'url(', 'shadowrootmode', 'b', 'x', '1',
    ];

    public function testCorpus()
    {
        $file = __DIR__ . '/fixtures/differential_corpus.json';

        $actual = [];
        \mt_srand(self::SEED);
        for ($i = 0; $i < self::COUNT; ++$i) {
            $input = '';
            $tokens = \mt_rand(1, 14);
            for ($j = 0; $j < $tokens; ++$j) {
                $input .= self::TOKENS[\mt_rand(0, \count(self::TOKENS) - 1)];
            }

            $antiXss = new AntiXSS();
            $output = $antiXss->xss_clean($input);

            $actual[] = [
                'input'  => $input,
                'output' => $output,
                'found'  => $antiXss->isXssFound(),
            ];
        }

        if (\getenv('ANTI_XSS_UPDATE_CORPUS') === '1') {
            \file_put_contents($file, \json_encode($actual, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES) . "\n");
        }

        $expected = \json_decode((string) \file_get_contents($file), true);

        static::assertCount(self::COUNT, $expected);
        foreach ($expected as $i => $case) {
            static::assertSame($case['input'], $actual[$i]['input'], 'corpus #' . $i . ': the generated input changed');
            static::assertSame($case['output'], $actual[$i]['output'], 'corpus #' . $i . ': ' . $case['input']);
            static::assertSame($case['found'], $actual[$i]['found'], 'corpus #' . $i . ' (isXssFound): ' . $case['input']);
        }
    }
}
