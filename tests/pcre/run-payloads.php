<?php

declare(strict_types=1);

/**
 * Helper for "PcreFailureTest": clean every payload (JSON on STDIN) and print the results (JSON on STDOUT).
 *
 * This runs in its own process with e.g. "-d pcre.jit=0 -d pcre.backtrack_limit=1", because PHP caches compiled
 * patterns: in the test process, patterns that were already compiled with the JIT would not fail.
 */

require \dirname(__DIR__, 2) . '/vendor/autoload.php';

use voku\helper\AntiXSS;

$payloads = \json_decode((string) \stream_get_contents(\STDIN), true);

$results = [];
foreach ($payloads as $payload) {
    $antiXss = new AntiXSS();
    try {
        $output = $antiXss->xss_clean($payload);
        $results[] = ['output' => $output, 'found' => $antiXss->isXssFound(), 'error' => null];
    } catch (\Throwable $e) {
        $results[] = ['output' => null, 'found' => null, 'error' => \get_class($e) . ': ' . $e->getMessage()];
    }
}

echo \json_encode($results, \JSON_INVALID_UTF8_SUBSTITUTE);
