<?php

use voku\helper\AntiXSS;

class XssTest extends PHPUnit_Framework_TestCase {

  /**
   * @var $security AntiXSS
   */
  public $security;

  public function setUp()
  {
    $this->security = new AntiXSS();
  }

  public function test_xss_clean()
  {
    $harm_string = "Hello, i try to <script>alert('Hack');</script> your site";

    $harmless_string = $this->security->xss_clean($harm_string);

    $this->assertEquals("Hello, i try to alert&#40;'Hack'&#41;; your site", $harmless_string);
  }

  public function test_xss_clean_string_array()
  {
    $harm_strings = array(
        "Hello, i try to <script>alert('Hack');</script> your site",
        "Simple clean string",
        "Hello, i try to <script>alert('Hack');</script> your site",
        "<a href=\"http://test.com?param1=\"+onMouseOver%3D\"alert%281%29%3B&step=2&param12=A\">test</a>"
    );

    $this->security->setReplacement('[removed]');
    $harmless_strings = $this->security->xss_clean($harm_strings);
    $this->security->setReplacement('');

    $this->assertEquals("Hello, i try to [removed]alert&#40;'Hack'&#41;;[removed] your site", $harmless_strings[0]);
    $this->assertEquals("Simple clean string", $harmless_strings[1]);
    $this->assertEquals("Hello, i try to [removed]alert&#40;'Hack'&#41;;[removed] your site", $harmless_strings[2]);
    $this->assertEquals("<a >test</a>", $harmless_strings[3]);
  }

  public function test_xss_clean_image_valid()
  {
    $harm_string = '<img src="test.png">';

    $xss_clean_return = $this->security->xss_clean($harm_string, TRUE);

    $this->assertTrue($xss_clean_return);
  }

  public function test_xss_clean_image_invalid()
  {
    $harm_string = '<img src=javascript:alert(String.fromCharCode(88,83,83))>';

    $xss_clean_return = $this->security->xss_clean($harm_string, TRUE);

    $this->assertFalse($xss_clean_return);
  }

  public function test_xss_clean_entity_double_encoded()
  {
    $testArray = array(
        "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>" => "<IMG >",
        "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>" => "<IMG >",
        "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">" => "<IMG >",
        "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>" => "<IMG >",
        "<a href=\"&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49\">Clickhere</a>" => "<a >Clickhere</a>"
    );

    foreach ($testArray as $before => $after) {
      $this->assertEquals($after, $this->security->xss_clean($before));
    }
  }

  public function test_xss_clean_js_img_removal()
  {
    $input = '<img src="&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49">Clickhere';
    $this->assertEquals('<img >', $this->security->xss_clean($input));
  }

  public function test_xss_clean_sanitize_naughty_html()
  {
    $input = '<blink>';
    $this->assertEquals('&lt;blink&gt;', $this->security->xss_clean($input));
  }

  public function test_remove_evil_attributes()
  {
    $this->assertEquals('onAttribute="bar"', $this->security->remove_evil_attributes('onAttribute="bar"', false));
    $this->assertEquals('<foo >', $this->security->remove_evil_attributes('<foo onAttribute="bar">', false));
    $this->assertEquals('<foo >', $this->security->remove_evil_attributes('<foo onAttributeNoQuotes=bar>', false));
    $this->assertEquals('<foo >', $this->security->remove_evil_attributes('<foo onAttributeWithSpaces = bar>', false));
    $this->assertEquals('<foo prefixOnAttribute="bar">', $this->security->remove_evil_attributes('<foo prefixOnAttribute="bar">', false));
    $this->assertEquals('<foo>onOutsideOfTag=test</foo>', $this->security->remove_evil_attributes('<foo>onOutsideOfTag=test</foo>', false));
    $this->assertEquals('onNoTagAtAll = true', $this->security->remove_evil_attributes('onNoTagAtAll = true', false));
  }
}