<?php

/*
 * This file is part of Laravel Security.
 *
 * (c) Graham Campbell <graham@alt-three.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use voku\helper\AntiXSS;

/**
 * Class LibFilterSecurityTest
 */
class LibFilterSecurityTest extends PHPUnit_Framework_TestCase
{

  //
  // https://github.com/iamcal/lib_filter/blob/master/t/01_basics.t
  //

  private $testArray = array();

  /**
   * @return AntiXSS
   */
  protected function getSecurity()
  {
    return new AntiXSS();
  }

  /**
   * @param $test
   * @param $result
   */
  public function addToTestArray($test, $result) {
    $this->testArray[$test] = $result;
  }

  public function testClean()
  {
    $this->addToTestArray('<script', '');
    $this->addToTestArray('<script woo="yay<b>', '');
    $this->addToTestArray('<script woo="yay<b>hello', '<b>hello</b>');
    $this->addToTestArray('<script<script>>', '');
    $this->addToTestArray('<<script>script<script>>', 'script');
    $this->addToTestArray('<<script><script>>', '');
    $this->addToTestArray('<<script>script>>', '');
    $this->addToTestArray('<<script<script>>', '');

    $this->addToTestArray('<script', '&lt;script');
    $this->addToTestArray('<script woo="yay<b>', '');
    $this->addToTestArray('<script woo="yay<b>hello', 'hello');
    $this->addToTestArray('<script<script>>', '>');
    $this->addToTestArray('<<script>script<script>>', '');
    $this->addToTestArray('<<script><script>>', '<>');
    $this->addToTestArray('<<script>script>>', '>');
    $this->addToTestArray('<<script<script>>', '<>');

    # bad protocols
    $this->addToTestArray('<a href="http://foo">bar</a>', '<a href="http://foo">bar</a>');
    $this->addToTestArray('<a href="ftp://foo">bar</a>', '<a href="ftp://foo">bar</a>');
    $this->addToTestArray('<a href="mailto:foo">bar</a>', '<a href="mailto:foo">bar</a>');
    $this->addToTestArray('<a href="javascript:foo">bar</a>', '<a href="foo">bar</a>');
    $this->addToTestArray('<a href="java script:foo">bar</a>', '<a >bar</a>');
    $this->addToTestArray('<a href="java'."\t".'script:foo">bar</a>', '<a >bar</a>');
    $this->addToTestArray('<a href="java'."\n".'script:foo">bar</a>', '<a >bar</a>');
    $this->addToTestArray('<a href="java'."\r".'script:foo">bar</a>', '<a >bar</a>');
    $this->addToTestArray('<a href="java'.chr(1).'script:foo">bar</a>', '<a href="foo">bar</a>');
    $this->addToTestArray('<a href="java'.chr(0).'script:foo">bar</a>', '<a href="foo">bar</a>');
    $this->addToTestArray('<a href="jscript:foo">bar</a>', '<a href="foo">bar</a>');
    $this->addToTestArray('<a href="vbscript:foo">bar</a>', '<a href="foo">bar</a>');
    $this->addToTestArray('<a href="view-source:foo">bar</a>', '<a href="foo">bar</a>');
    $this->addToTestArray('<a href="  javascript:foo">bar</a>', '<a href="  foo">bar</a>');
    $this->addToTestArray('<a href="jAvAsCrIpT:foo">bar</a>', '<a href="foo">bar</a>');

    # bad protocols with entities (semicolons)
    $this->addToTestArray('<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;foo">bar</a>', '<a href="foo">bar</a>');
    $this->addToTestArray('<a href="&#0000106;&#0000097;&#0000118;&#0000097;&#0000115;&#0000099;&#0000114;&#0000105;&#0000112;&#0000116;&#0000058;foo">bar</a>', '<a href="foo">bar</a>');
    $this->addToTestArray('<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;foo">bar</a>', '<a href="foo">bar</a>');

    # bad protocols with entities (no semicolons)
    $this->addToTestArray('<a href="&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58;foo">bar</a>', '<a href="foo">bar</a>');
    $this->addToTestArray('<a href="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058foo">bar</a>', '<a href="foo">bar</a>');
    $this->addToTestArray('<a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A;foo">bar</a>', '<a href="foo">bar</a>');

    $security = $this->getSecurity();

    foreach ($this->testArray as $test => $expected) {
      self::assertSame($expected, $security->xss_clean($test), 'tested: ' . $test);
    }
  }
}
