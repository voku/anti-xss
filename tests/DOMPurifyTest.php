<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use voku\helper\AntiXSS;
use voku\helper\UTF8;

/**
 * Class DOMPurifyTest
 *
 * @internal
 */
final class DOMPurifyTest extends TestCase
{
    //
    // https://github.com/cure53/DOMPurify/blob/master/test/fixtures/expect.js
    //

    public function testFromDOMPurify(): void
    {
        // init
        $expected = require __DIR__ . '/fixtures/expect_result.php';
        $result   = [];
        $testData = $this->xssProvider();

        foreach ($testData as $index => $test) {
            echo "Processing test case #$index: " . substr($test['payload'], 0, 100) . "...\n";
            flush();

            $result[] = (new AntiXSS())->xss_clean($test['payload']);

            echo "Completed test case #$index\n";
            flush();
        }

        // DEBUG
        //\var_export($result);

        DOMPurifyTest::assertTrue(\count($result) > 0);
        DOMPurifyTest::assertSame($expected, $result);
    }

    public function xssProvider(): array
    {
        $jsonString = UTF8::file_get_contents(__DIR__ . '/fixtures/expect.json');

        return \json_decode($jsonString, true);
    }
}
