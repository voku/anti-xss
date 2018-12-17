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
    // https://github.com/cure53/DOMPurify/edit/master/test/expect.json
    //

    /**
     * @var AntiXSS
     */
    public $security;

    /**
     * @var array
     */
    public $testArray;

    protected function setUp()
    {
        $this->security = new AntiXSS();
        $this->setTestArray();
    }

    public function testFromDOMPurify()
    {
        foreach ($this->testArray as $test) {
            static::assertSame($test['expected'], $this->security->xss_clean($test['payload']), 'testing: ' . $test['payload']);
        }
    }

    public function setTestArray()
    {
        $jsonString = UTF8::file_get_contents(__DIR__ . '/fixtures/expect.json');

        $this->testArray = \json_decode($jsonString, true);
    }
}
