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
 * Every PCRE setting runs in its own process, because PHP caches compiled patterns (a pattern that was compiled with
 * the JIT in this process would not fail here).
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
     * @param string[] $payloads
     * @param string   $jit
     * @param int      $backtrackLimit
     *
     * @return array<int, array{output: string|null, found: bool|null, error: string|null}>
     */
    private static function cleanInProcess(array $payloads, $jit, $backtrackLimit): array
    {
        $command = \escapeshellarg(\PHP_BINARY)
            . ' -d pcre.jit=' . $jit
            . ' -d pcre.backtrack_limit=' . $backtrackLimit
            . ' ' . \escapeshellarg(__DIR__ . '/pcre/run-payloads.php');

        $process = \proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        static::assertIsResource($process);

        \fwrite($pipes[0], (string) \json_encode($payloads));
        \fclose($pipes[0]);
        $stdout = (string) \stream_get_contents($pipes[1]);
        $stderr = (string) \stream_get_contents($pipes[2]);
        \fclose($pipes[1]);
        \fclose($pipes[2]);
        \proc_close($process);

        $results = \json_decode($stdout, true);
        static::assertIsArray($results, $stderr . $stdout);

        return $results;
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

    public function testXssCleanFailsClosedIfPcreFails()
    {
        if (!\function_exists('proc_open')) {
            static::markTestSkipped('"proc_open()" is not available');
        }

        $payloads = self::payloads();

        $failures = [];
        foreach (['0', '1'] as $jit) {
            foreach ([1, 2, 3, 6, 16, 100, 1000] as $backtrackLimit) {
                foreach (self::cleanInProcess($payloads, $jit, $backtrackLimit) as $i => $result) {
                    $setting = 'pcre.jit=' . $jit . ', pcre.backtrack_limit=' . $backtrackLimit . ': ' . $payloads[$i];

                    if ($result['error'] !== null) {
                        $failures[] = $setting . ' => ' . $result['error'];

                        continue;
                    }

                    $dangers = self::dangers((string) $result['output']);
                    if ($dangers !== []) {
                        $failures[] = $setting . ' => ' . $result['output'] . ' (' . \implode(', ', $dangers) . ')';
                    }

                    // every payload must be reported as XSS (with the default settings, it's reported, too); so the
                    // original input is never returned unchecked
                    if ($result['found'] !== true) {
                        $failures[] = $setting . ' => ' . $result['output'] . ' (not reported as XSS)';
                    }
                }
            }
        }

        static::assertSame([], $failures);
    }

    public function testHarmlessContentIsUnchangedIfPcreWorks()
    {
        if (!\function_exists('proc_open')) {
            static::markTestSkipped('"proc_open()" is not available');
        }

        // the default settings in a fresh process (the same code path as with a failing PCRE, but without failures)
        $harmless = ['<p class="x">Hello <b>world</b></p>', 'plain text: online, on time', '<a href="https://example.com/?a=1">x</a>'];
        foreach (self::cleanInProcess($harmless, '1', 1000000) as $i => $result) {
            static::assertSame($harmless[$i], $result['output']);
            static::assertFalse($result['found']);
        }
    }
}
