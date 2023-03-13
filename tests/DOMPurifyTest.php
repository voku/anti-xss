<?php

use voku\helper\AntiXSS;
use voku\helper\UTF8;

/**
 * Class DOMPurifyTest
 *
 * @internal
 */
final class DOMPurifyTest extends \PHPUnit\Framework\TestCase
{
    //
    // https://github.com/cure53/DOMPurify/blob/master/test/fixtures/expect.js
    //

    public function testFromDOMPurify()
    {
        // init
        $expected = require __DIR__ . '/fixtures/expect_result.php';
        $result = [];

        foreach ($this->xssProvider() as $test) {
            $result[] = (new AntiXSS())->xss_clean($test['payload']);
        }

        // DEBUG
        //\var_export($result);

        static::assertTrue(\count($result) > 0);
        static::assertSame($expected, $result);
    }

    public function xssProvider()
    {
        $jsonString = UTF8::file_get_contents(__DIR__ . '/fixtures/expect.json');

        yield from \json_decode($jsonString, true);
    }
}
