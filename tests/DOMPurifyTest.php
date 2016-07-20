<?php

use voku\helper\AntiXSS;
use voku\helper\UTF8;

/**
 * Class DOMPurifyTest
 */
class DOMPurifyTest extends PHPUnit_Framework_TestCase
{

  //
  // https://github.com/cure53/DOMPurify/edit/master/test/expect.json
  //

  /**
   * @var $security AntiXSS
   */
  public $security;

  /**
   * @var array
   */
  public $testArray;

  public function setUp()
  {
    $this->security = new AntiXSS();
    $this->setTestArray();
  }

  public function testFromDOMPurify()
  {
    foreach ($this->testArray as $test) {
      self::assertSame($test['expected'], $this->security->xss_clean($test['payload']), 'testing: ' . $test['payload']);
    }

  }

  public function setTestArray()
  {
    $jsonString = UTF8::file_get_contents(__DIR__ . '/fixtures/expect.json');

    $this->testArray = json_decode($jsonString, true);
  }

}
