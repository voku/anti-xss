<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/vendor/autoload.php';

use voku\helper\AntiXSS;

const DEFAULT_WARMUP_ITERATIONS = 5;
const DEFAULT_MEASURE_ITERATIONS = 8;

$measureIterations = DEFAULT_MEASURE_ITERATIONS;
$warmupIterations = DEFAULT_WARMUP_ITERATIONS;
$jsonOutput = false;
$implementationFile = null;

foreach (array_slice($argv, 1) as $argument) {
    if ($argument === '--json') {
        $jsonOutput = true;

        continue;
    }

    if (strpos($argument, '--iterations=') === 0) {
        $measureIterations = max(1, (int) substr($argument, strlen('--iterations=')));

        continue;
    }

    if (strpos($argument, '--warmup=') === 0) {
        $warmupIterations = max(0, (int) substr($argument, strlen('--warmup=')));

        continue;
    }

    if (strpos($argument, '--impl-file=') === 0) {
        $implementationFile = (string) substr($argument, strlen('--impl-file='));
    }
}

if ($implementationFile !== null) {
    if (!is_file($implementationFile)) {
        fwrite(STDERR, "Implementation file not found: {$implementationFile}\n");

        exit(1);
    }

    require_once $implementationFile;
}

$fixturesDir = __DIR__ . '/fixtures';

$cases = [
    'plain_text_small' => [
        'input' => 'Regular prose with punctuation, emoji-free ASCII, prices like <35% and > 1 year, plus harmless onload words in content.',
        'iterations' => $measureIterations * 20,
    ],
    'safe_html_fragment' => [
        'input' => (string) file_get_contents($fixturesDir . '/image_clean.html'),
        'iterations' => $measureIterations * 6,
    ],
    'malicious_html_fragment' => [
        'input' => (string) file_get_contents($fixturesDir . '/xss_v4.html'),
        'iterations' => $measureIterations * 12,
    ],
    'malicious_html_large' => [
        'input' => (string) file_get_contents($fixturesDir . '/xss_v3.html'),
        'iterations' => $measureIterations,
    ],
    'svg_payload' => [
        'input' => (string) file_get_contents($fixturesDir . '/xss_v3.svg'),
        'iterations' => $measureIterations * 10,
    ],
    'large_base64_html' => [
        'input' => (string) file_get_contents($fixturesDir . '/base64_image.html'),
        'iterations' => max(2, (int) ceil($measureIterations / 2)),
    ],
    'encoded_url_payload' => [
        'input' => '<a href="j a v a s c r i p t:alert(1)">click</a>?foo=%26%2397%3B%26%23108%3B%26%23101%3B%26%23114%3B%26%23116%3B',
        'iterations' => $measureIterations * 8,
    ],
];

$results = [];
$aggregateNanoseconds = 0;
$aggregateOperations = 0;

foreach ($cases as $name => $case) {
    $antiXss = new AntiXSS();

    for ($i = 0; $i < $warmupIterations; ++$i) {
        $antiXss->xss_clean($case['input']);
    }

    $startedAt = hrtime(true);

    for ($i = 0; $i < $case['iterations']; ++$i) {
        $antiXss->xss_clean($case['input']);
    }

    $durationNanoseconds = hrtime(true) - $startedAt;
    $nanosecondsPerOp = (int) round($durationNanoseconds / $case['iterations']);

    $results[$name] = [
        'iterations' => $case['iterations'],
        'bytes' => strlen($case['input']),
        'total_ms' => round($durationNanoseconds / 1_000_000, 3),
        'ns_per_op' => $nanosecondsPerOp,
        'ops_per_sec' => (int) round(1_000_000_000 / max(1, $nanosecondsPerOp)),
    ];

    $aggregateNanoseconds += $durationNanoseconds;
    $aggregateOperations += $case['iterations'];
}

$payload = [
    'php' => PHP_VERSION,
    'warmup_iterations' => $warmupIterations,
    'measure_iterations' => $measureIterations,
    'cases' => $results,
    'summary' => [
        'total_ms' => round($aggregateNanoseconds / 1_000_000, 3),
        'total_operations' => $aggregateOperations,
        'avg_ns_per_op' => (int) round($aggregateNanoseconds / max(1, $aggregateOperations)),
        'avg_ops_per_sec' => (int) round(($aggregateOperations * 1_000_000_000) / max(1, $aggregateNanoseconds)),
    ],
    'implementation_file' => $implementationFile,
];

if ($jsonOutput) {
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;

    exit(0);
}

printf(
    "PHP %s\nWarmup iterations: %d\nMeasure iterations seed: %d\n\n",
    $payload['php'],
    $warmupIterations,
    $measureIterations
);
printf(
    "%-24s %10s %8s %12s %14s %12s\n",
    'Case',
    'Iterations',
    'Bytes',
    'Total ms',
    'ns/op',
    'ops/sec'
);

foreach ($results as $name => $result) {
    printf(
        "%-24s %10d %8d %12.3f %14d %12d\n",
        $name,
        $result['iterations'],
        $result['bytes'],
        $result['total_ms'],
        $result['ns_per_op'],
        $result['ops_per_sec']
    );
}

printf(
    "\n%-24s %10d %8s %12.3f %14d %12d\n",
    'summary',
    $payload['summary']['total_operations'],
    '-',
    $payload['summary']['total_ms'],
    $payload['summary']['avg_ns_per_op'],
    $payload['summary']['avg_ops_per_sec']
);
