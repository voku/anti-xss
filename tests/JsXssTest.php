<?php

use voku\helper\AntiXSS;

/**
 * Class JsXssTest
 */
class JsXssTest extends PHPUnit_Framework_TestCase
{

  //
  // https://github.com/leizongmin/js-xss/blob/master/test/test_xss.js
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
  }

  public function testFromJsXss()
  {

    // 兼容各种奇葩输入
    self::assertSame('', $this->security->xss_clean(''));
    self::assertSame('', $this->security->xss_clean(null));
    self::assertSame('123', $this->security->xss_clean(123));
    self::assertSame('{a: 1111}', $this->security->xss_clean('{a: 1111}'));

    // 清除不可见字符
    self::assertSame("a\r\n b", $this->security->xss_clean("a\u0000\u0001\u0002\u0003\r\n b"));

    // 过滤不在白名单的标签
    self::assertSame('<b>abcd</b>', $this->security->xss_clean('<b>abcd</b>'));
    self::assertSame('<o>abcd</o>', $this->security->xss_clean('<o>abcd</o>'));
    self::assertSame('<b>abcd</o>', $this->security->xss_clean('<b>abcd</o>'));
    self::assertSame('<b><o>abcd</b></o>', $this->security->xss_clean('<b><o>abcd</b></o>'));
    self::assertSame('<hr>', $this->security->xss_clean('<hr>'));
    self::assertSame('&lt;xss&gt;', $this->security->xss_clean('<xss>'));
    self::assertSame('&lt;xss o="x"&gt;', $this->security->xss_clean('<xss o="x">'));
    self::assertSame('<a><b>c</b></a>', $this->security->xss_clean('<a><b>c</b></a>'));
    self::assertSame('<a><c>b</c></a>', $this->security->xss_clean('<a><c>b</c></a>'));

    // 过滤不是标签的<>
    self::assertSame('<>>', $this->security->xss_clean('<>>'));
    self::assertSame("''", $this->security->xss_clean("'<scri' + 'pt>'"));
    self::assertSame("''", $this->security->xss_clean("'<script' + '>'"));
    self::assertSame('<<a>b>', $this->security->xss_clean('<<a>b>'));
    self::assertSame('<<<a>>b</a><x>', $this->security->xss_clean('<<<a>>b</a><x>'));

    // 过滤不在白名单中的属性
    self::assertSame('<a oo="1" xx="2" title="3">yy</a>', $this->security->xss_clean('<a oo="1" xx="2" title="3">yy</a>'));
    self::assertSame('<a >pp</a>', $this->security->xss_clean('<a title xx oo>pp</a>'));
    self::assertSame('<a >pp</a>', $this->security->xss_clean('<a title "">pp</a>'));
    self::assertSame('<a t="">', $this->security->xss_clean('<a t="">'));

    // 属性内的特殊字符
    self::assertSame('<a >>">', $this->security->xss_clean('<a title="\'<<>>">'));
    self::assertSame('<a title="">', $this->security->xss_clean('<a title=""">'));
    self::assertSame('<a title="oo">', $this->security->xss_clean('<a h=title="oo">'));
    self::assertSame('<a  title="oo">', $this->security->xss_clean('<a h= title="oo">'));
    self::assertSame('<a title="alert&#40;/xss/&#41;">', $this->security->xss_clean('<a title="javascript&colon;alert(/xss/)">'));

    // 自动将属性值的单引号转为双引号
    self::assertSame('<a title=\'abcd\'>', $this->security->xss_clean('<a title=\'abcd\'>'));
    self::assertSame('<a title=\'"\'>', $this->security->xss_clean('<a title=\'"\'>'));

    // 没有双引号括起来的属性值
    self::assertSame('<a >', $this->security->xss_clean('<a title=home>'));
    self::assertSame('<a >', $this->security->xss_clean('<a title=abc("d")>'));
    self::assertSame('<a >', $this->security->xss_clean('<a title=abc(\'d\')>'));

    // 单个闭合标签
    self::assertSame('<img />', $this->security->xss_clean('<img src/>'));
    self::assertSame('<img  />', $this->security->xss_clean('<img src />'));
    self::assertSame('<img />', $this->security->xss_clean('<img src//>'));
    self::assertSame('<br />', $this->security->xss_clean('<br />'));
    self::assertSame('<br/>', $this->security->xss_clean('<br/>'));

    // 畸形属性格式
    self::assertSame('<a target = "_blank" title ="bbb">', $this->security->xss_clean('<a target = "_blank" title ="bbb">'));
    self::assertSame('<a target = "_blank"  title =  "bbb">', $this->security->xss_clean('<a target = "_blank" title =  title =  "bbb">'));
    self::assertSame('<img  title="xxx">', $this->security->xss_clean('<img width = 100    height     =200 title="xxx">'));
    self::assertSame('<img >', $this->security->xss_clean('<img width = 100    height     =200 title=xxx>'));
    self::assertSame('<img >', $this->security->xss_clean('<img width = 100    height     =200 title= xxx>'));
    self::assertSame('<img  title= "xxx">', $this->security->xss_clean('<img width = 100    height     =200 title= "xxx">'));
    self::assertSame('<img  title= \'xxx\'>', $this->security->xss_clean('<img width = 100    height     =200 title= \'xxx\'>'));
    self::assertSame('<img  title = \'xxx\'>', $this->security->xss_clean('<img width = 100    height     =200 title = \'xxx\'>'));
    self::assertSame('<img  title= "xxx" alt="yyy">', $this->security->xss_clean('<img width = 100    height     =200 title= "xxx" no=yes alt="yyy">'));
    self::assertSame('<img  title= "xxx" alt="\'yyy\'">', $this->security->xss_clean('<img width = 100    height     =200 title= "xxx" no=yes alt="\'yyy\'">'));

    // 过滤所有标签
    self::assertSame('<a title="xx">bb</a>', $this->security->xss_clean('<a title="xx">bb</a>'));
    self::assertSame('<hr>', $this->security->xss_clean('<hr>'));
    // 增加白名单标签及属性
    self::assertSame('<ooxx yy="ok" cc="no">uu</ooxx>', $this->security->xss_clean('<ooxx yy="ok" cc="no">uu</ooxx>'));

    self::assertSame('>">\'>alert&#40;String.fromCharCode(88,83,83&#41;)', $this->security->xss_clean('></SCRIPT>">\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>'));

    self::assertSame(';!--"&lt;XSS&gt;=', $this->security->xss_clean(';!--"<XSS>=&{()}'));

    self::assertSame('', $this->security->xss_clean('<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'));

    self::assertSame('<IMG src="">', $this->security->xss_clean('<IMG SRC="javascript:alert(\'XSS\');">'));

    self::assertSame('<IMG >', $this->security->xss_clean('<IMG SRC=javascript:alert(\'XSS\')>'));

    self::assertSame('<IMG >', $this->security->xss_clean('<IMG SRC=JaVaScRiPt:alert(\'XSS\')>'));

    self::assertSame('<IMG >', $this->security->xss_clean('<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>'));

    self::assertSame('<IMG """><>>', $this->security->xss_clean('<IMG """><SCRIPT>alert("XSS")</SCRIPT>">'));

    self::assertSame('<IMG >', $this->security->xss_clean('<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>'));

    self::assertSame('<IMG >', $this->security->xss_clean('<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>'));

    self::assertSame('<IMG >', $this->security->xss_clean('<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>'));

    self::assertSame('<IMG >', $this->security->xss_clean('<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>'));

    self::assertSame('<IMG src="">', $this->security->xss_clean('<IMG SRC="jav ascript:alert(\'XSS\');">'));

    self::assertSame('<IMG src="">', $this->security->xss_clean('<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">'));

    self::assertSame('<IMG src="">', $this->security->xss_clean('<IMG SRC="jav\nascript:alert(\'XSS\');">'));

    self::assertSame('<IMG >', $this->security->xss_clean('<IMG SRC=java\0script:alert(\"XSS\")>'));

    self::assertSame('<IMG src="">', $this->security->xss_clean('<IMG SRC=" &#14;  javascript:alert(\'XSS\');">'));

    self::assertSame('', $this->security->xss_clean('<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>'));

    self::assertSame('&lt;BODY alert&#40;"XSS"&#41;&gt;', $this->security->xss_clean('<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>'));

    self::assertSame('&lt;alert&#40;"XSS"&#41;;//&lt;', $this->security->xss_clean('<<SCRIPT>alert("XSS");//<</SCRIPT>'));

    self::assertSame('', $this->security->xss_clean('<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >'));

    self::assertSame('&lt;SCRIPT SRC=//ha.ckers.org/.j', $this->security->xss_clean('<SCRIPT SRC=//ha.ckers.org/.j'));

    self::assertSame('<IMG src=""', $this->security->xss_clean('<IMG SRC="javascript:alert(\'XSS\')"'));

    self::assertSame('&lt;iframe src=http://ha.ckers.org/scriptlet.html &lt;', $this->security->xss_clean('<iframe src=http://ha.ckers.org/scriptlet.html <'));

    // 过滤 javascript:
    self::assertSame('<a >', $this->security->xss_clean('<a style="url(\'javascript:alert(1)\')">'));
    self::assertSame('<td background="url(\'alert&#40;1&#41;\')">', $this->security->xss_clean('<td background="url(\'javascript:alert(1)\')">'));

    // 过滤 style
    self::assertSame('<DIV >', $this->security->xss_clean('<DIV STYLE="width: \nexpression(alert(1));">'));
    self::assertSame('<DIV >', $this->security->xss_clean('<DIV STYLE="width: \n expressionexpression((alert(1));">'));
    // 不正常的url
    self::assertSame('<DIV >', $this->security->xss_clean('<DIV STYLE="background:\n url (javascript:ooxx);">'));
    self::assertSame('<DIV >', $this->security->xss_clean('<DIV STYLE="background:url (javascript:ooxx);">'));
    // 正常的url
    self::assertSame('<DIV >', $this->security->xss_clean('<DIV STYLE="background: url (ooxx);">'));

    self::assertSame('<IMG SRC=\'msgbox("XSS")\'>', $this->security->xss_clean('<IMG SRC=\'vbscript:msgbox("XSS")\'>'));

    self::assertSame('<IMG SRC="[code]">', $this->security->xss_clean('<IMG SRC="livescript:[code]">'));

    self::assertSame('<IMG SRC="[code]">', $this->security->xss_clean('<IMG SRC="mocha:[code]">'));

    self::assertSame('<a href="">', $this->security->xss_clean('<a href="javas/**/cript:alert(\'XSS\');">'));

    self::assertSame('<a href="test">', $this->security->xss_clean('<a href="javascript:test">'));
    self::assertSame('<a href="/javascript/a">', $this->security->xss_clean('<a href="/javascript/a">'));
    self::assertSame('<a href="/javascript/a">', $this->security->xss_clean('<a href="/javascript/a">'));
    self::assertSame('<a href="http://aa.com">', $this->security->xss_clean('<a href="http://aa.com">'));
    self::assertSame('<a href="https://aa.com">', $this->security->xss_clean('<a href="https://aa.com">'));
    self::assertSame('<a href="mailto:me@ucdok.com">', $this->security->xss_clean('<a href="mailto:me@ucdok.com">'));
    self::assertSame('<a href="#hello">', $this->security->xss_clean('<a href="#hello">'));
    self::assertSame('<a href="other">', $this->security->xss_clean('<a href="other">'));

    // 这个暂时不知道怎么处理
    //self::assertSame($this->security->xss_clean('¼script¾alert(¢XSS¢)¼/script¾'), '');

    self::assertSame('&lt;!--[if gte IE 4]>alert&#40;\'XSS\'&#41;;<![endif]--&gt; END', $this->security->xss_clean('<!--[if gte IE 4]><SCRIPT>alert(\'XSS\');</SCRIPT><![endif]--> END'));
    self::assertSame('&lt;!--[if gte IE 4]>alert&#40;\'XSS\'&#41;;<![endif]--&gt; END', $this->security->xss_clean('<!--[if gte IE 4]><SCRIPT >alert(\'XSS\');</SCRIPT><![endif]--> END'));

    // HTML5新增实体编码 冒号&colon; 换行&NewLine;
    self::assertSame('<a href="">', $this->security->xss_clean('<a href="javascript&colon;alert(/xss/)">'));
    self::assertSame('<a href="">', $this->security->xss_clean('<a href="javascript&colonalert(/xss/)">'));
    self::assertSame("<a href=\"a\nb\">", $this->security->xss_clean('<a href="a&NewLine;b">'));
    self::assertSame('<a href="a&NewLineb">', $this->security->xss_clean('<a href="a&NewLineb">'));
    self::assertSame('<a href="">', $this->security->xss_clean('<a href="javasc&NewLine;ript&colon;alert(1)">'));

    // data URI 协议过滤
    self::assertSame('<a href="">', $this->security->xss_clean('<a href="data:">'));
    self::assertSame('<a href="">', $this->security->xss_clean('<a href="d a t a : ">'));
    self::assertSame('<a href="">', $this->security->xss_clean('<a href="data: html/text;">'));
    self::assertSame('<a href="">', $this->security->xss_clean('<a href="data:html/text;">'));
    self::assertSame('<a href="">', $this->security->xss_clean('<a href="data:html /text;">'));
    self::assertSame('<a href="">', $this->security->xss_clean('<a href="data: image/text;">'));
    self::assertSame('<img src="">', $this->security->xss_clean('<img src="data: aaa/text;">'));
    self::assertSame('<img src="">', $this->security->xss_clean('<img src="data:image/png; base64; ofdkofiodiofl">'));

    self::assertSame('<img >', $this->security->xss_clean('<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">'));

    // HTML备注处理
    self::assertSame('&lt;!--                               --&gt;', $this->security->xss_clean('<!--                               -->'));
    self::assertSame('&lt;!--      a           --&gt;', $this->security->xss_clean('<!--      a           -->'));
    self::assertSame('&lt;!--sa       --&gt;ss', $this->security->xss_clean('<!--sa       -->ss'));
    self::assertSame('&lt;!--                               ', $this->security->xss_clean('<!--                               '));

  }

}
