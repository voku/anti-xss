<?php

use voku\helper\AntiXSS;

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
    self::assertEquals('', $this->security->xss_clean(''));
    self::assertEquals('', $this->security->xss_clean(null));
    self::assertEquals('123', $this->security->xss_clean(123));
    self::assertEquals('{a: 1111}', $this->security->xss_clean('{a: 1111}'));

    // 清除不可见字符
    self::assertEquals("a\r\n b", $this->security->xss_clean("a\u0000\u0001\u0002\u0003\r\n b"));

    // 过滤不在白名单的标签
    self::assertEquals('<b>abcd</b>', $this->security->xss_clean('<b>abcd</b>'));
    self::assertEquals('<o>abcd</o>', $this->security->xss_clean('<o>abcd</o>'));
    self::assertEquals('<b>abcd</o>', $this->security->xss_clean('<b>abcd</o>'));
    self::assertEquals('<b><o>abcd</b></o>', $this->security->xss_clean('<b><o>abcd</b></o>'));
    self::assertEquals('<hr>', $this->security->xss_clean('<hr>'));
    self::assertEquals('', $this->security->xss_clean('<xss>'));
    self::assertEquals('', $this->security->xss_clean('<xss o="x">'));
    self::assertEquals('<a><b>c</b></a>', $this->security->xss_clean('<a><b>c</b></a>'));
    self::assertEquals('<a><c>b</c></a>', $this->security->xss_clean('<a><c>b</c></a>'));

    // 过滤不是标签的<>
    self::assertEquals('<>>', $this->security->xss_clean('<>>'));
    self::assertEquals("'<scri'   'pt>'", $this->security->xss_clean("'<scri' + 'pt>'"));
    self::assertEquals('<<a>b>', $this->security->xss_clean('<<a>b>'));
    self::assertEquals('<<<a>>b</a><x>', $this->security->xss_clean('<<<a>>b</a><x>'));

    // 过滤不在白名单中的属性
    self::assertEquals('<a oo="1" xx="2" title="3">yy</a>', $this->security->xss_clean('<a oo="1" xx="2" title="3">yy</a>'));
    self::assertEquals('<a >pp</a>', $this->security->xss_clean('<a title xx oo>pp</a>'));
    self::assertEquals('<a >pp</a>', $this->security->xss_clean('<a title "">pp</a>'));
    self::assertEquals('<a t="">', $this->security->xss_clean('<a t="">'));

    // 属性内的特殊字符
    self::assertEquals('<a >>">', $this->security->xss_clean('<a title="\'<<>>">'));
    self::assertEquals('<a title="">', $this->security->xss_clean('<a title=""">'));
    self::assertEquals('<a title="oo">', $this->security->xss_clean('<a h=title="oo">'));
    self::assertEquals('<a  title="oo">', $this->security->xss_clean('<a h= title="oo">'));
    self::assertEquals('<a title="alert&#40;/xss/&#41;">', $this->security->xss_clean('<a title="javascript&colon;alert(/xss/)">'));

    // 自动将属性值的单引号转为双引号
    self::assertEquals('<a title=\'abcd\'>', $this->security->xss_clean('<a title=\'abcd\'>'));
    self::assertEquals('<a title=\'"\'>', $this->security->xss_clean('<a title=\'"\'>'));

    // 没有双引号括起来的属性值
    self::assertEquals('<a >', $this->security->xss_clean('<a title=home>'));
    self::assertEquals('<a >', $this->security->xss_clean('<a title=abc("d")>'));
    self::assertEquals('<a >', $this->security->xss_clean('<a title=abc(\'d\')>'));

    // 单个闭合标签
    self::assertEquals('<img />', $this->security->xss_clean('<img src/>'));
    self::assertEquals('<img  />', $this->security->xss_clean('<img src />'));
    self::assertEquals('<img />', $this->security->xss_clean('<img src//>'));
    self::assertEquals('<br />', $this->security->xss_clean('<br />'));
    self::assertEquals('<br/>', $this->security->xss_clean('<br/>'));

    // 畸形属性格式
    self::assertEquals('<a target = "_blank" title ="bbb">', $this->security->xss_clean('<a target = "_blank" title ="bbb">'));
    self::assertEquals('<a target = "_blank"  title =  "bbb">', $this->security->xss_clean('<a target = "_blank" title =  title =  "bbb">'));
    self::assertEquals('<img  title="xxx">', $this->security->xss_clean('<img width = 100    height     =200 title="xxx">'));
    self::assertEquals('<img >', $this->security->xss_clean('<img width = 100    height     =200 title=xxx>'));
    self::assertEquals('<img >', $this->security->xss_clean('<img width = 100    height     =200 title= xxx>'));
    self::assertEquals('<img  title= "xxx">', $this->security->xss_clean('<img width = 100    height     =200 title= "xxx">'));
    self::assertEquals('<img  title= \'xxx\'>', $this->security->xss_clean('<img width = 100    height     =200 title= \'xxx\'>'));
    self::assertEquals('<img  title = \'xxx\'>', $this->security->xss_clean('<img width = 100    height     =200 title = \'xxx\'>'));
    self::assertEquals('<img  title= "xxx" alt="yyy">', $this->security->xss_clean('<img width = 100    height     =200 title= "xxx" no=yes alt="yyy">'));
    self::assertEquals('<img  title= "xxx" alt="\'yyy\'">', $this->security->xss_clean('<img width = 100    height     =200 title= "xxx" no=yes alt="\'yyy\'">'));

    // 过滤所有标签
    self::assertEquals('<a title="xx">bb</a>', $this->security->xss_clean('<a title="xx">bb</a>'));
    self::assertEquals('<hr>', $this->security->xss_clean('<hr>'));
    // 增加白名单标签及属性
    self::assertEquals('<ooxx yy="ok" cc="no">uu</ooxx>', $this->security->xss_clean('<ooxx yy="ok" cc="no">uu</ooxx>'));

    self::assertEquals('>">\'>alert&#40;String.fromCharCode(88,83,83&#41;)', $this->security->xss_clean('></SCRIPT>">\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>'));

    self::assertEquals(';!--"=', $this->security->xss_clean(';!--"<XSS>=&{()}'));

    self::assertEquals('', $this->security->xss_clean('<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC="javascript:alert(\'XSS\');">'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC=javascript:alert(\'XSS\')>'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC=JaVaScRiPt:alert(\'XSS\')>'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>'));

    self::assertEquals('<IMG """><>>', $this->security->xss_clean('<IMG """><SCRIPT>alert("XSS")</SCRIPT>">'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC="jav ascript:alert(\'XSS\');">'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC="jav\nascript:alert(\'XSS\');">'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC=java\0script:alert(\"XSS\")>'));

    self::assertEquals('<IMG >', $this->security->xss_clean('<IMG SRC=" &#14;  javascript:alert(\'XSS\');">'));

    self::assertEquals('', $this->security->xss_clean('<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>'));

    self::assertEquals('&lt;BODY onload!#$%&()*~ -_.,:;?@[/|\]^`=alert&#40;"XSS"&#41;&gt;', $this->security->xss_clean('<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>'));

    self::assertEquals('&lt;alert&#40;"XSS"&#41;;//&lt;', $this->security->xss_clean('<<SCRIPT>alert("XSS");//<</SCRIPT>'));

    self::assertEquals('', $this->security->xss_clean('<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >'));

    self::assertEquals('&lt;SCRIPT SRC=//ha.ckers.org/.j', $this->security->xss_clean('<SCRIPT SRC=//ha.ckers.org/.j'));

    self::assertEquals('<IMG ', $this->security->xss_clean('<IMG SRC="javascript:alert(\'XSS\')"'));

    self::assertEquals('&lt;iframe src=http://ha.ckers.org/scriptlet.html &lt;', $this->security->xss_clean('<iframe src=http://ha.ckers.org/scriptlet.html <'));

    // 过滤 javascript:
    self::assertEquals('<a >', $this->security->xss_clean('<a style="url(\'javascript:alert(1)\')">'));
    self::assertEquals('<td background="url(\'alert&#40;1&#41;\')">', $this->security->xss_clean('<td background="url(\'javascript:alert(1)\')">'));

    // 过滤 style
    self::assertEquals('<DIV  \nalert&#40;1&#41;);">', $this->security->xss_clean('<DIV STYLE="width: \nexpression(alert(1));">'));
    self::assertEquals('<DIV  \n alert(1&#41;);">', $this->security->xss_clean('<DIV STYLE="width: \n expressionexpression((alert(1));">'));
    // 不正常的url
    self::assertEquals('<DIV  url (ooxx);">', $this->security->xss_clean('<DIV STYLE="background:\n url (javascript:ooxx);">'));
    self::assertEquals('<DIV  (ooxx);">', $this->security->xss_clean('<DIV STYLE="background:url (javascript:ooxx);">'));
    // 正常的url
    self::assertEquals('<DIV  url (ooxx);">', $this->security->xss_clean('<DIV STYLE="background: url (ooxx);">'));

    self::assertEquals('<IMG SRC=\'msgbox("XSS")\'>', $this->security->xss_clean('<IMG SRC=\'vbscript:msgbox("XSS")\'>'));

    self::assertEquals('<IMG SRC="[code]">', $this->security->xss_clean('<IMG SRC="livescript:[code]">'));

    self::assertEquals('<IMG SRC="[code]">', $this->security->xss_clean('<IMG SRC="mocha:[code]">'));

    self::assertEquals('<a >', $this->security->xss_clean('<a href="javas/**/cript:alert(\'XSS\');">'));

    self::assertEquals('<a ">', $this->security->xss_clean('<a href="javascript">'));
    self::assertEquals('<a href="/javascript/a">', $this->security->xss_clean('<a href="/javascript/a">'));
    self::assertEquals('<a href="/javascript/a">', $this->security->xss_clean('<a href="/javascript/a">'));
    self::assertEquals('<a href="http://aa.com">', $this->security->xss_clean('<a href="http://aa.com">'));
    self::assertEquals('<a href="https://aa.com">', $this->security->xss_clean('<a href="https://aa.com">'));
    self::assertEquals('<a href="mailto:me@ucdok.com">', $this->security->xss_clean('<a href="mailto:me@ucdok.com">'));
    self::assertEquals('<a href="other">', $this->security->xss_clean('<a href="other">'));

    // 这个暂时不知道怎么处理
    //self::assertEquals($this->security->xss_clean('¼script¾alert(¢XSS¢)¼/script¾'), '');

    self::assertEquals('&lt;!--[if gte IE 4]>alert&#40;\'XSS\'&#41;;<![endif]--&gt; END', $this->security->xss_clean('<!--[if gte IE 4]><SCRIPT>alert(\'XSS\');</SCRIPT><![endif]--> END'));
    self::assertEquals('&lt;!--[if gte IE 4]>alert&#40;\'XSS\'&#41;;<![endif]--&gt; END', $this->security->xss_clean('<!--[if gte IE 4]><SCRIPT >alert(\'XSS\');</SCRIPT><![endif]--> END'));

    // HTML5新增实体编码 冒号&colon; 换行&NewLine;
    self::assertEquals('<a />', $this->security->xss_clean('<a href="javascript&colon;alert(/xss/)">'));
    self::assertEquals('<a />', $this->security->xss_clean('<a href="javascript&colonalert(/xss/)">'));
    self::assertEquals("<a href=\"a\nb\">", $this->security->xss_clean('<a href="a&NewLine;b">'));
    self::assertEquals('<a href="a&NewLineb">', $this->security->xss_clean('<a href="a&NewLineb">'));
    self::assertEquals('<a >', $this->security->xss_clean('<a href="javasc&NewLine;ript&colon;alert(1)">'));

    // data URI 协议过滤
    self::assertEquals('<a href="data:">', $this->security->xss_clean('<a href="data:">'));
    self::assertEquals('<a href="d a t a : ">', $this->security->xss_clean('<a href="d a t a : ">'));
    self::assertEquals('<a href="data: html/text;">', $this->security->xss_clean('<a href="data: html/text;">'));
    self::assertEquals('<a href="data:html/text;">', $this->security->xss_clean('<a href="data:html/text;">'));
    self::assertEquals('<a href="data:html /text;">', $this->security->xss_clean('<a href="data:html /text;">'));
    self::assertEquals('<a href="data: image/text;">', $this->security->xss_clean('<a href="data: image/text;">'));
    self::assertEquals('<img src="data: aaa/text;">', $this->security->xss_clean('<img src="data: aaa/text;">'));
    self::assertEquals('<img src="data:image/png; base64; ofdkofiodiofl">', $this->security->xss_clean('<img src="data:image/png; base64; ofdkofiodiofl">'));

    self::assertEquals('<img >', $this->security->xss_clean('<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">'));

    // HTML备注处理
    self::assertEquals('&lt;!--                               --&gt;', $this->security->xss_clean('<!--                               -->'));
    self::assertEquals('&lt;!--      a           --&gt;', $this->security->xss_clean('<!--      a           -->'));
    self::assertEquals('&lt;!--sa       --&gt;ss', $this->security->xss_clean('<!--sa       -->ss'));
    self::assertEquals('&lt;!--                               ', $this->security->xss_clean('<!--                               '));

  }

}
