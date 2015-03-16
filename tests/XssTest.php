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
    $this->assertEquals("<a href=\"http://test.com?param1=\">test</a>", $harmless_strings[3]);
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

  public function testXssClean()
  {
    $testArray = array(
      "onAttribute=\"bar\"" => "\"bar\"",
      "<BGSOUND SRC=\"javascript:alert('XSS');\">" => "&lt;BGSOUND SRC=\"alert&#40;'XSS'&#41;;\"&gt;", // BGSOUND
      "<BR SIZE=\"&{alert('XSS')}\">" => "<BR SIZE=\"&{alert&#40;'XSS'&#41;}\">", // & JavaScript includes
      "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">" => "&lt;LINK REL=\"stylesheet\" HREF=\"alert&#40;'XSS'&#41;;\"&gt;", // STYLE sheet
      "<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>" => "&lt;STYLE&gt;BODY{:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}&lt;/STYLE&gt;", // Remote style sheet
      "<STYLE>@im\\port'\\ja\vasc\ript:alert(\"XSS\")';</STYLE>" => "&lt;STYLE&gt;@im\port'\jaasc\ript:alert&#40;\"XSS\"&#41;';&lt;/STYLE&gt;", // STYLE tags with broken up JavaScript for XSS
      "<XSS STYLE=\"xss:expression_r(alert('XSS'))\">" => "", // Anonymous HTML with STYLE attribute
      "<XSS STYLE=\"behavior: url(xss.htc);\">" => "", // Local htc file
      "¼script¾alert(¢XSS¢)¼/script¾" => "¼script¾alert&#40;¢XSS¢&#41;¼/script¾", // US-ASCII encoding
      "<IMG defang_SRC=javascript:alert\(&quot;XSS&quot;\)>" => "<IMG >", // IMG
      "<IMG SRC=javascript:alert(&quot;XSS&quot;)>" => "<IMG >",
      "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>" => "<IMG >",
      "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>" => "<IMG >",
      "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>" => "<IMG >",
      "<IMG SRC=\"jav	ascript:alert('XSS');\">" => "<IMG >",
      "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">" => "<IMG >",
      "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">" => "<IMG >",
      "<IMG SRC\n=\n\"\nj\na\nv\n&#x0A;a\ns\nc\nr\ni\np\nt\n:\na\nl\ne\nr\nt\n(\n'\nX\nS\nS\n'\n)\n;\">" => "<IMG SRC\n=\n\"\n\nalert\n&#40;\n'\nX\nS\nS\n'\n&#41;\n;\">",
      "<IMG SRC=java�script:alert('XSS')>" => "<IMG >",
      "<DIV STYLE=\"background-image:\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028\\0027\\0058\\0053\\0053\\0027\\0029'\\0029\">" => "<DIV >",
      "<STYLE>.XSS{background-image:url(\"javascript:alert('XSS')\");}</STYLE><A CLASS=XSS></A>" => "&lt;STYLE&gt;.XSS{background-image:url(\"alert&#40;'XSS'&#41;\");}&lt;/STYLE&gt;&lt;A ></A>",
      "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">" => "&lt;META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=alert&#40;'XSS'&#41;;\"&gt;", // META
      "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>" => "&lt;IFRAME SRC=\"alert&#40;'XSS'&#41;;\"&gt;&lt;/IFRAME>", // IFRAME
      "<applet code=A21 width=256 height=256 archive=\"toir.jar\"></applet>" => "&lt;applet code=A21 width=256 height=256 archive=\"toir.jar\"&gt;&lt;/applet>",
      "<script Language=\"JavaScript\" event=\"FSCommand (command, args)\" for=\"theMovie\">...</script>" => "...", // <script>
      "<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>" => "(\"<SCRI\");PT SRC=\"http://ha.ckers.org/xss.js\">", // XSS using HTML quote encapsulation
      "<SCR�IPT>alert(\"XSS\")</SCR�IPT>" => "alert&#40;\"XSS\"&#41;",
      "Би шил идэй чадна,<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>我能吞下玻璃而不傷身體</br>" => "Би шил идэй чадна,&lt;STYLE&gt;li {list-style-image: url(\"alert&#40;'XSS'&#41;\");}&lt;/STYLE&gt;&lt;UL><LI>我能吞下玻璃而不傷身體</br>",
      "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\"\; alert(String.fromCharCode(88,83,83))//\"\;alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>" => "';alert&#40;String.fromCharCode(88,83,83&#41;)//';alert&#40;String.fromCharCode(88,83,83&#41;)//\"\\; alert&#40;String.fromCharCode(88,83,83&#41;)//\"\\;alert&#40;String.fromCharCode(88,83,83&#41;)//--&gt;\">'>alert&#40;String.fromCharCode(88,83,83&#41;)",
      "म काँच खान सक्छू र मलाई केहि नी हुन्‍न् <IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>।" => "म काँच खान सक्छू र मलाई केहि नी हुन्‍न् <IMG >।",
    );

    foreach ($testArray as $before => $after) {
      $this->assertEquals($after, $this->security->xss_clean($before));
    }
  }

  public function testJavaScriptCleaning()
  {
    // http://cpansearch.perl.org/src/KURIANJA/HTML-Defang-1.02/t/02_xss.t

    $testArray = array(
        "<img FSCommand=\"someFunction()\">",
        "<img onAbort=\"someFunction()\">",
        "<img onActivate=\"someFunction()\">",
        "<img onAfterPrint=\"someFunction()\">",
        "<img onAfterUpdate=\"someFunction()\">",
        "<img onBeforeActivate=\"someFunction()\">",
        "<img onBeforeCopy=\"someFunction()\">",
        "<img onBeforeCut=\"someFunction()\">",
        "<img onBeforeDeactivate=\"someFunction()\">",
        "<img onBeforeEditFocus=\"someFunction()\">",
        "<img onBeforePaste=\"someFunction()\">",
        "<img onBeforePrint=\"someFunction()\">",
        "<img onBeforeUnload=\"someFunction()\">",
        "<img onBegin=\"someFunction()\">",
        "<img onBlur=\"someFunction()\">",
        "<img onBounce=\"someFunction()\">",
        "<img onCellChange=\"someFunction()\">",
        "<img onChange=\"someFunction()\">",
        "<img onClick=\"someFunction()\">",
        "<img onContextMenu=\"someFunction()\">",
        "<img onControlSelect=\"someFunction()\">",
        "<img onCopy=\"someFunction()\">",
        "<img onCut=\"someFunction()\">",
        "<img onDataAvailable=\"someFunction()\">",
        "<img onDataSetChanged=\"someFunction()\">",
        "<img onDataSetComplete=\"someFunction()\">",
        "<img onDblClick=\"someFunction()\">",
        "<img onDeactivate=\"someFunction()\">",
        "<img onDrag=\"someFunction()\">",
        "<img onDragEnd=\"someFunction()\">",
        "<img onDragLeave=\"someFunction()\">",
        "<img onDragEnter=\"someFunction()\">",
        "<img onDragOver=\"someFunction()\">",
        "<img onDragDrop=\"someFunction()\">",
        "<img onDrop=\"someFunction()\">",
        "<img onEnd=\"someFunction()\">",
        "<img onError=\"someFunction()\">",
        "<img onErrorUpdate=\"someFunction()\">",
        "<img onFilterChange=\"someFunction()\">",
        "<img onFinish=\"someFunction()\">",
        "<img onFocus=\"someFunction()\">",
        "<img onFocusIn=\"someFunction()\">",
        "<img onFocusOut=\"someFunction()\">",
        "<img onHelp=\"someFunction()\">",
        "<img onKeyDown=\"someFunction()\">",
        "<img onKeyPress=\"someFunction()\">",
        "<img onKeyUp=\"someFunction()\">",
        "<img onLayoutComplete=\"someFunction()\">",
        "<img onLoad=\"someFunction()\">",
        "<img onLoseCapture=\"someFunction()\">",
        "<img onMediaComplete=\"someFunction()\">",
        "<img onMediaError=\"someFunction()\">",
        "<img onMouseDown=\"someFunction()\">",
        "<img onMouseEnter=\"someFunction()\">",
        "<img onMouseLeave=\"someFunction()\">",
        "<img onMouseMove=\"someFunction()\">",
        "<img onMouseOut=\"someFunction()\">",
        "<img onMouseOver=\"someFunction()\">",
        "<img onMouseUp=\"someFunction()\">",
        "<img onMouseWheel=\"someFunction()\">",
        "<img onMove=\"someFunction()\">",
        "<img onMoveEnd=\"someFunction()\">",
        "<img onMoveStart=\"someFunction()\">",
        "<img onOutOfSync=\"someFunction()\">",
        "<img onPaste=\"someFunction()\">",
        "<img onPause=\"someFunction()\">",
        "<img onProgress=\"someFunction()\">",
        "<img onPropertyChange=\"someFunction()\">",
        "<img onReadyStateChange=\"someFunction()\">",
        "<img onRepeat=\"someFunction()\">",
        "<img onReset=\"someFunction()\">",
        "<img onResize=\"someFunction()\">",
        "<img onResizeEnd=\"someFunction()\">",
        "<img onResizeStart=\"someFunction()\">",
        "<img onResume=\"someFunction()\">",
        "<img onReverse=\"someFunction()\">",
        "<img onRowsEnter=\"someFunction()\">",
        "<img onRowExit=\"someFunction()\">",
        "<img onRowDelete=\"someFunction()\">",
        "<img onRowInserted=\"someFunction()\">",
        "<img onScroll=\"someFunction()\">",
        "<img onSeek=\"someFunction()\">",
        "<img onSelect=\"someFunction()\">",
        "<img onSelectionChange=\"someFunction()\">",
        "<img onSelectStart=\"someFunction()\">",
        "<img onStart=\"someFunction()\">",
        "<img onStop=\"someFunction()\">",
        "<img onSyncRestored=\"someFunction()\">",
        "<img onSubmit=\"someFunction()\">",
        "<img onTimeError=\"someFunction()\">",
        "<img onTrackChange=\"someFunction()\">",
        "<img onUnload=\"someFunction()\">",
        "<img onURLFlip=\"someFunction()\">",
        "<img seekSegmentTime=\"someFunction()\">",
    );

    foreach ($testArray as $test) {
      $this->assertEquals("<img >", $this->security->xss_clean($test));
    }
  }

  public function test_xss_clean_entity_double_encoded()
  {
    $testArray = array(
        "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>" => "<IMG >",
        "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>" => "<IMG >",
        "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">" => "<IMG >",
        "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>" => "<IMG >",
        "<a href=\"&#38&#35&#49&#48&#54&#38&#35&#57&#55&#38&#35&#49&#49&#56&#38&#35&#57&#55&#38&#35&#49&#49&#53&#38&#35&#57&#57&#38&#35&#49&#49&#52&#38&#35&#49&#48&#53&#38&#35&#49&#49&#50&#38&#35&#49&#49&#54&#38&#35&#53&#56&#38&#35&#57&#57&#38&#35&#49&#49&#49&#38&#35&#49&#49&#48&#38&#35&#49&#48&#50&#38&#35&#49&#48&#53&#38&#35&#49&#49&#52&#38&#35&#49&#48&#57&#38&#35&#52&#48&#38&#35&#52&#57&#38&#35&#52&#49\">Clickhere</a>" => "<a >Clickhere</a>",
        "<a href=\"http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D\">Google</a>" => "<a href=\"http://www.google.com\">Google</a>",
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