<?php

declare(strict_types=1);

use voku\helper\AntiXSS;

/**
 * "xss_clean()" must fail closed, if PCRE fails (e.g. "pcre.backtrack_limit" exhausted, also with "pcre.jit"
 * disabled): it must never return the original, unchecked input or skip a sanitizing step.
 *
 * Before 4.1.49, e.g. "pcre.jit=0" + "pcre.backtrack_limit=1" returned '<script>alert(1)</script>' unchanged
 * (and "isXssFound() === false"): a failed "preg_replace()" erased the string before the backup in "_do()", so
 * that the result looked unchanged; other steps kept the unfiltered string ("$tmp ?? $str").
 *
 * Every PCRE setting runs in its own process ("@runInSeparateProcess"), because PHP caches compiled patterns (a
 * pattern that was compiled with the JIT in this process would not fail here).
 *
 * @internal
 */
final class PcreFailureTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @return string[]
     */
    private static function payloads(): array
    {
        return [
            '<script>alert(1)</script>',
            '<SCRIPT SRC=//evil.example/x.js></SCRIPT>',
            '<img src=x onerror=alert(1)>',
            '<div onclick="alert(1)">x</div>',
            '<div onfoo="alert(1)">x</div>',
            '<div ongesturestart="alert(1)">x</div>',
            '<svg onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<a href="javascript:alert(1)">x</a>',
            '<a href="java&#x09;script:alert(1)">x</a>',
            "<a href=\"java\0script:alert(1)\">x</a>",
            '<a href="javascript&colon;alert(1)">x</a>',
            '<a href="%6A%61%76%61%73%63%72%69%70%74:alert(1)">x</a>',
            '<iframe src="javascript:alert(1)"></iframe>',
            '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
            '<form action="javascript:alert(1)"><button>x</button></form>',
            '<object data="javascript:alert(1)"></object>',
            '<embed src="javascript:alert(1)">',
            '<base href="javascript:alert(1)//">',
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            '<div style="width: expression(alert(1))">x</div>',
            '<svg><a xlink:href="javascript:alert(1)"><text>x</text></a></svg>',
            '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">x</a>',
            '+ADw-script+AD4-alert(1)+ADw-/script+AD4-',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '<template shadowrootmode=open><img src=x onerror=alert(1)></template>',
            '<textarea><p title="</textarea><img src=x onerror=alert(1)>"></textarea>',
            \str_repeat('a', 3000) . '<script>alert(1)</script>',
        ];
    }

    /**
     * @param string $output
     *
     * @return string[]
     */
    private static function dangers($output): array
    {
        $dangers = [];

        foreach (['<script', 'javascript:', 'vbscript:', '<iframe', '<object', '<embed', '<base', '<meta', '<frame', '<style', '<link', 'data:text/html'] as $needle) {
            if (\stripos($output, $needle) !== false) {
                $dangers[] = $needle;
            }
        }

        // attribute and CSS keywords are only dangerous inside of a tag
        if (\strpos($output, '<') !== false) {
            foreach (['srcdoc', 'expression(', 'formaction', 'shadowrootmode', 'xlink:href'] as $needle) {
                if (\stripos($output, $needle) !== false) {
                    $dangers[] = $needle;
                }
            }
        }

        // event handler attributes, for every possible start tag
        $method = new \ReflectionMethod(AntiXSS::class, '_remove_event_handler_attributes');
        $method->setAccessible(true);
        if ($method->invoke(new AntiXSS(), $output) !== $output) {
            $dangers[] = 'event handler attribute';
        }

        return $dangers;
    }

    public function testPayloadsAreNotDangerousWithDefaultSettings()
    {
        foreach (self::payloads() as $payload) {
            $antiXss = new AntiXSS();
            $output = $antiXss->xss_clean($payload);

            static::assertSame([], self::dangers($output), $payload . ' => ' . $output);
            static::assertTrue($antiXss->isXssFound(), $payload);
        }
    }

    /**
     * @return array<string, array{0: string, 1: int}>
     */
    public static function providePcreSettings(): array
    {
        $settings = [];
        foreach (['0', '1'] as $jit) {
            foreach ([1, 2, 3, 6, 16, 100, 1000] as $backtrackLimit) {
                $settings['pcre.jit=' . $jit . ', pcre.backtrack_limit=' . $backtrackLimit] = [$jit, $backtrackLimit];
            }
        }

        return $settings;
    }

    /**
     * INFO: in a separate process, so that no pattern was compiled (e.g. with the JIT) before the settings are used;
     *       PHPUnit also collects the code coverage of separate processes
     *
     * @dataProvider providePcreSettings
     *
     * @runInSeparateProcess
     *
     * @preserveGlobalState disabled
     *
     * @param string $jit
     * @param int    $backtrackLimit
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('providePcreSettings')]
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    #[\PHPUnit\Framework\Attributes\PreserveGlobalState(false)]
    public function testXssCleanFailsClosedIfPcreFails($jit, $backtrackLimit)
    {
        $payloads = self::payloads();

        $originalJit = \ini_get('pcre.jit');
        $originalBacktrackLimit = \ini_get('pcre.backtrack_limit');
        \ini_set('pcre.jit', $jit);
        \ini_set('pcre.backtrack_limit', (string) $backtrackLimit);

        $results = [];
        try {
            foreach ($payloads as $payload) {
                $antiXss = new AntiXSS();
                $results[] = [$antiXss->xss_clean($payload), $antiXss->isXssFound()];
            }
        } finally {
            \ini_set('pcre.jit', (string) $originalJit);
            \ini_set('pcre.backtrack_limit', (string) $originalBacktrackLimit);
        }

        $failures = [];
        foreach ($results as $i => $result) {
            $dangers = self::dangers($result[0]);
            if ($dangers !== []) {
                $failures[] = $payloads[$i] . ' => ' . $result[0] . ' (' . \implode(', ', $dangers) . ')';
            }

            // every payload must be reported as XSS (with the default settings, it's reported, too); so the
            // original input is never returned unchecked
            if ($result[1] !== true) {
                $failures[] = $payloads[$i] . ' => ' . $result[0] . ' (not reported as XSS)';
            }
        }

        static::assertSame([], $failures);
    }

    /**
     * The same check in this process: the patterns here are already compiled (with the JIT, if enabled), but a tiny
     * "pcre.backtrack_limit" also lets the JIT fail. So this does not depend on the separate processes above (e.g.
     * for the code coverage).
     *
     * @return void
     */
    public function testXssCleanFailsClosedIfPcreFailsInThisProcess()
    {
        $payloads = self::payloads();

        $failures = [];
        foreach ([1, 2, 3, 6, 16] as $backtrackLimit) {
            $originalBacktrackLimit = \ini_get('pcre.backtrack_limit');
            \ini_set('pcre.backtrack_limit', (string) $backtrackLimit);

            $results = [];
            try {
                foreach ($payloads as $payload) {
                    $antiXss = new AntiXSS();
                    $results[] = [$antiXss->xss_clean($payload), $antiXss->isXssFound()];
                }
            } finally {
                \ini_set('pcre.backtrack_limit', (string) $originalBacktrackLimit);
            }

            foreach ($results as $i => $result) {
                $dangers = self::dangers($result[0]);
                if ($dangers !== [] || $result[1] !== true) {
                    $failures[] = 'pcre.backtrack_limit=' . $backtrackLimit . ': ' . $payloads[$i] . ' => ' . $result[0]
                        . ' (' . ($dangers !== [] ? \implode(', ', $dangers) : 'not reported as XSS') . ')';
                }
            }
        }

        static::assertSame([], $failures);
    }

    /**
     * @param string $name
     *
     * @return \ReflectionMethod
     */
    private static function method($name): \ReflectionMethod
    {
        $method = new \ReflectionMethod(AntiXSS::class, $name);
        $method->setAccessible(true);

        return $method;
    }

    /**
     * Call a private method with a tiny "pcre.backtrack_limit" (also the JIT respects it).
     *
     * @param AntiXSS $antiXss
     * @param string  $name
     * @param mixed[] $args
     *
     * @return mixed
     */
    private static function invokeWithFailingPcre(AntiXSS $antiXss, $name, array $args)
    {
        $originalBacktrackLimit = \ini_get('pcre.backtrack_limit');
        \ini_set('pcre.backtrack_limit', '1');
        try {
            return self::method($name)->invokeArgs($antiXss, $args);
        } finally {
            \ini_set('pcre.backtrack_limit', (string) $originalBacktrackLimit);
        }
    }

    /**
     * The fail-closed branch of every step, called directly (the end-to-end tests above can not reach all of them,
     * because an earlier step already fails closed).
     *
     * @return void
     */
    public function testFailClosedBranchesOfTheSteps()
    {
        // "_remove_disallowed_javascript()": the regex-based removal and its simpler fallback regex fail -> tag removal
        foreach (['<audio src="javascript:alert(1)"></audio>', '<video src="javascript:alert(1)"></video>', '<a href="javascript:alert(1)">x</a>'] as $payload) {
            $output = (string) self::invokeWithFailingPcre(new AntiXSS(), '_remove_disallowed_javascript', [$payload]);
            static::assertFalse(\stripos($output, 'javascript:') !== false, $payload . ' => ' . $output);
        }

        // "_do_never_allowed_afterwards()": no event handler is left
        $output = (string) self::invokeWithFailingPcre(new AntiXSS(), '_do_never_allowed_afterwards', ['<div onclick=alert(1)>x</div>']);
        static::assertSame([], self::dangers($output), $output);

        // "_remove_never_allowed_on_events_afterwards()": the event names can not be marked -> neutralized
        //
        // INFO: a new pattern (unique, empty group), compiled without the JIT, so that the tiny limit lets it fail
        $antiXss = new AntiXSS();
        $originalJit = \ini_get('pcre.jit');
        \ini_set('pcre.jit', '0');
        try {
            $output = (string) self::invokeWithFailingPcre($antiXss, '_remove_never_allowed_on_events_afterwards', [
                '<div onclick=alert(1)>x</div>',
                '(?<before>[^\p{L}@.!?>-]|^)(?<name>onclick)(?:x' . \mt_rand() . '){0}',
            ]);
        } finally {
            \ini_set('pcre.jit', (string) $originalJit);
        }
        static::assertSame('&lt;div onclick=alert(1)&gt;x&lt;/div&gt;', $output);
        static::assertTrue($antiXss->isXssFound());

    }

    /**
     * "_events_tail_summary_compose()" treats the name as followed by "=" (remove it), and "_entity_decode()"
     * neutralizes the string, if PCRE fails.
     *
     * INFO: their patterns are fixed and already compiled with the JIT in this process, so this needs a fresh process
     *
     * @runInSeparateProcess
     *
     * @preserveGlobalState disabled
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    #[\PHPUnit\Framework\Attributes\PreserveGlobalState(false)]
    public function testEventsTailSummaryFailsClosed()
    {
        $originalJit = \ini_get('pcre.jit');
        \ini_set('pcre.jit', '0');

        $antiXss = new AntiXSS();
        $empty = self::method('_events_tail_summary_empty')->invoke($antiXss);
        $antiXssDecode = new AntiXSS();
        try {
            $tail = self::invokeWithFailingPcre($antiXss, '_events_tail_summary_compose', ['abc', $empty]);
            $decoded = (string) self::invokeWithFailingPcre($antiXssDecode, '_entity_decode', ['&lt;script&gt;alert(1)&lt;/script&gt; <b>']);
        } finally {
            \ini_set('pcre.jit', (string) $originalJit);
        }

        static::assertTrue($tail['a']);
        static::assertFalse(\strpos($decoded, '<') !== false, $decoded);
        static::assertTrue($antiXssDecode->isXssFound());
    }

    public function testNeutralizeFallback()
    {
        $antiXss = new AntiXSS();
        $neutralize = self::method('_failClosedNeutralize');

        $cases = [
            '<a href="javascript:alert(1)">x</a>' => '&lt;a href=&quot;javascriptalert(1)&quot;&gt;x&lt;/a&gt;',
            "a+b & c\x00d\x1Fe\x7Ff"              => 'a&#43;b &amp; cdef',
            "keep\t\n\r whitespace"               => "keep\t\n\r whitespace",
            '+ADw-script+AD4-'                    => '&#43;ADw-script&#43;AD4-',
            "it's"                                => 'it&#039;s',
        ];
        foreach ($cases as $input => $expected) {
            $output = $neutralize->invoke($antiXss, $input);

            static::assertSame($expected, $output, $input);
            // idempotent, so that the cleaning loops converge
            static::assertSame($output, $neutralize->invoke($antiXss, $output), $input);
        }

        static::assertTrue($antiXss->isXssFound());
    }

    public function testOnNullFallback()
    {
        $antiXss = new AntiXSS();
        $onNull = self::method('_failClosedOnNull');

        static::assertSame('result', $onNull->invoke($antiXss, 'result', '<b>'));
        static::assertNull($antiXss->isXssFound());

        static::assertSame('&lt;b&gt;', $onNull->invoke($antiXss, null, '<b>'));
        static::assertTrue($antiXss->isXssFound());
    }

    public function testVendorCallFallback()
    {
        $vendorCall = self::method('_failClosedVendorCall');

        // the vendor result is used, if PCRE did not fail
        $antiXss = new AntiXSS();
        static::assertSame('A', $vendorCall->invoke($antiXss, 'strtoupper', 'a'));
        static::assertNull($antiXss->isXssFound());

        // "" is a valid result for invisible chars only
        static::assertSame('', $vendorCall->invoke($antiXss, static function () {
            return '';
        }, "\x00\x01"));
        static::assertNull($antiXss->isXssFound());

        // "" for printable input: PCRE failed in the vendor code ("(string) preg_replace()")
        static::assertSame('&lt;b&gt;', $vendorCall->invoke($antiXss, static function () {
            return '';
        }, '<b>'));
        static::assertTrue($antiXss->isXssFound());

        // a PCRE error in the vendor code, also if its result looks fine (here: invalid UTF-8 with "/u")
        $antiXss = new AntiXSS();
        $output = $vendorCall->invoke($antiXss, static function ($str) {
            \preg_match('/x/u', "\xC3\x28");

            return $str;
        }, '<b>');
        static::assertSame('&lt;b&gt;', $output);
        static::assertTrue($antiXss->isXssFound());

        // an old PCRE error (from before the vendor call) is not reported as a failure of the vendor call
        \preg_match('/x/u', "\xC3\x28");
        $antiXss = new AntiXSS();
        static::assertSame('B', $vendorCall->invoke($antiXss, 'strtoupper', 'b'));
        static::assertNull($antiXss->isXssFound());
    }

    /**
     * The default settings in a fresh process (the same code path as with a failing PCRE, but without failures).
     *
     * @runInSeparateProcess
     *
     * @preserveGlobalState disabled
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    #[\PHPUnit\Framework\Attributes\PreserveGlobalState(false)]
    public function testHarmlessContentIsUnchangedIfPcreWorks()
    {
        foreach (['<p class="x">Hello <b>world</b></p>', 'plain text: online, on time', '<a href="https://example.com/?a=1">x</a>'] as $harmless) {
            $antiXss = new AntiXSS();
            static::assertSame($harmless, $antiXss->xss_clean($harmless));
            static::assertFalse($antiXss->isXssFound());
        }
    }
}
