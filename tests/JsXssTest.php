<?php

use voku\helper\AntiXSS;

/**
 * Class JsXssTest
 *
 * @internal
 */
final class JsXssTest extends \PHPUnit\Framework\TestCase
{

  //
    // https://github.com/leizongmin/js-xss/blob/master/test/test_xss.js
    //

    /**
     * @var AntiXSS
     */
    public $security;

    /**
     * @var array
     */
    public $testArray;

    public function testFromJsXss()
    {

        // 兼容各种奇葩输入
        static::assertSame('', (new AntiXSS())->xss_clean(''));
        static::assertNull((new AntiXSS())->xss_clean(null));
        static::assertSame(123, (new AntiXSS())->xss_clean(123));
        static::assertSame('{a: 1111}', (new AntiXSS())->xss_clean('{a: 1111}'));

        // 清除不可见字符
        static::assertSame("a\u0000\u0001\u0002\u0003\r\n b", (new AntiXSS())->xss_clean("a\u0000\u0001\u0002\u0003\r\n b"));

        // 过滤不在白名单的标签
        static::assertSame('<b>abcd</b>', (new AntiXSS())->xss_clean('<b>abcd</b>'));
        static::assertSame('<o>abcd</o>', (new AntiXSS())->xss_clean('<o>abcd</o>'));
        static::assertSame('<b>abcd</o>', (new AntiXSS())->xss_clean('<b>abcd</o>'));
        static::assertSame('<b><o>abcd</b></o>', (new AntiXSS())->xss_clean('<b><o>abcd</b></o>'));
        static::assertSame('<hr>', (new AntiXSS())->xss_clean('<hr>'));
        static::assertSame('<xss>', (new AntiXSS())->xss_clean('<xss>'));
        static::assertSame('<xss o="x">', (new AntiXSS())->xss_clean('<xss o="x">'));
        static::assertSame('<a><b>c</b></a>', (new AntiXSS())->xss_clean('<a><b>c</b></a>'));
        static::assertSame('<a><c>b</c></a>', (new AntiXSS())->xss_clean('<a><c>b</c></a>'));

        // 过滤不是标签的<>
        static::assertSame('&lt;&gt;&gt;', (new AntiXSS())->xss_clean('<>>'));
        static::assertSame("'", (new AntiXSS())->xss_clean("'<scri' + 'pt>'"));
        static::assertSame("'", (new AntiXSS())->xss_clean("'<script' + '>'"));
        static::assertSame('&lt;&lt;a&gt;b&gt;', (new AntiXSS())->xss_clean('<<a>b>'));
        static::assertSame('&lt;&lt;&lt;a&gt;&gt;b&lt;/a&gt;&lt;x&gt;', (new AntiXSS())->xss_clean('<<<a>>b</a><x>'));

        // 过滤不在白名单中的属性
        static::assertSame('<a oo="1" xx="2" title="3">yy</a>', (new AntiXSS())->xss_clean('<a oo="1" xx="2" title="3">yy</a>'));
        static::assertSame('<a title xx oo>pp</a>', (new AntiXSS())->xss_clean('<a title xx oo>pp</a>'));
        static::assertSame('<a title "">pp</a>', (new AntiXSS())->xss_clean('<a title "">pp</a>'));
        static::assertSame('<a t="">', (new AntiXSS())->xss_clean('<a t="">'));

        // 属性内的特殊字符
        static::assertSame('<a title="\'&lt;&lt;&gt;&gt;">', (new AntiXSS())->xss_clean('<a title="\'<<>>">'));
        static::assertSame('<a title="">', (new AntiXSS())->xss_clean('<a title=""">'));
        static::assertSame('<a title="oo">', (new AntiXSS())->xss_clean('<a h=title="oo">'));
        static::assertSame('<a  title="oo">', (new AntiXSS())->xss_clean('<a h= title="oo">'));
        static::assertSame('<a title="(/xss/)">', (new AntiXSS())->xss_clean('<a title="javascript&colon;alert(/xss/)">'));

        // 自动将属性值的单引号转为双引号
        static::assertSame('<a title=\'abcd\'>', (new AntiXSS())->xss_clean('<a title=\'abcd\'>'));
        static::assertSame('<a title=\'"\'>', (new AntiXSS())->xss_clean('<a title=\'"\'>'));

        // 没有双引号括起来的属性值
        static::assertSame('<a >', (new AntiXSS())->xss_clean('<a title=home>'));
        static::assertSame('<a >', (new AntiXSS())->xss_clean('<a title=abc("d")>'));
        static::assertSame('<a >', (new AntiXSS())->xss_clean('<a title=abc(\'d\')>'));

        // 单个闭合标签
        static::assertSame('<img src/>', (new AntiXSS())->xss_clean('<img src/>'));
        static::assertSame('<img src />', (new AntiXSS())->xss_clean('<img src />'));
        static::assertSame('<img src//>', (new AntiXSS())->xss_clean('<img src//>'));
        static::assertSame('<br />', (new AntiXSS())->xss_clean('<br />'));
        static::assertSame('<br/>', (new AntiXSS())->xss_clean('<br/>'));

        // 畸形属性格式
        static::assertSame('<a target = "_blank" title ="bbb">', (new AntiXSS())->xss_clean('<a target = "_blank" title ="bbb">'));
        static::assertSame('<a target = \'_blank\' title =\'bbb\'>', (new AntiXSS())->xss_clean("<a target = '_blank' title ='bbb'>"));
        static::assertSame('<a >', (new AntiXSS())->xss_clean('<a target=_blank title=bbb>'));
        static::assertSame('<a target = "_blank"  title =  "bbb">', (new AntiXSS())->xss_clean('<a target = "_blank" title =  title =  "bbb">'));
        static::assertSame('<a target = " _blank "  title =  "bbb">', (new AntiXSS())->xss_clean('<a target = " _blank " title =  title =  "bbb">'));
        static::assertSame('<a   title =  "bbb">', (new AntiXSS())->xss_clean('<a target = _blank title =  title =  "bbb">'));
        static::assertSame('<a   title =  "bbb">', (new AntiXSS())->xss_clean('<a target = ' . 0x42 . '_blank' . 0x42 . ' title =  title =  "bbb">'));
        static::assertSame('<img  title="xxx">', (new AntiXSS())->xss_clean('<img width = 100    height     =200 title="xxx">'));
        static::assertSame('<img >', (new AntiXSS())->xss_clean('<img width = 100    height     =200 title=xxx>'));
        static::assertSame('<img >', (new AntiXSS())->xss_clean('<img width = 100    height     =200 title= xxx>'));
        static::assertSame('<img  title= "xxx">', (new AntiXSS())->xss_clean('<img width = 100    height     =200 title= "xxx">'));
        static::assertSame('<img  title= \'xxx\'>', (new AntiXSS())->xss_clean('<img width = 100    height     =200 title= \'xxx\'>'));
        static::assertSame('<img  title = \'xxx\'>', (new AntiXSS())->xss_clean('<img width = 100    height     =200 title = \'xxx\'>'));
        static::assertSame('<img  title= "xxx" alt="yyy">', (new AntiXSS())->xss_clean('<img width = 100    height     =200 title= "xxx" no=yes alt="yyy">'));
        static::assertSame('<img  title= "xxx" alt="\'yyy\'">', (new AntiXSS())->xss_clean('<img width = 100    height     =200 title= "xxx" no=yes alt="\'yyy\'">'));

        // 过滤所有标签
        static::assertSame('<a title="xx">bb</a>', (new AntiXSS())->xss_clean('<a title="xx">bb</a>'));
        static::assertSame('<hr>', (new AntiXSS())->xss_clean('<hr>'));
        // 增加白名单标签及属性
        static::assertSame('<ooxx yy="ok" cc="no">uu</ooxx>', (new AntiXSS())->xss_clean('<ooxx yy="ok" cc="no">uu</ooxx>'));

        static::assertSame('>">\'>', (new AntiXSS())->xss_clean('></SCRIPT>">\'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>'));

        static::assertSame(';!--"<XSS>=&{()}', (new AntiXSS())->xss_clean(';!--"<XSS>=&{()}'));

        static::assertSame('', (new AntiXSS())->xss_clean('<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'));

        static::assertSame('<IMG SRC="(\'XSS\');">', (new AntiXSS())->xss_clean('<IMG SRC="javascript:alert(\'XSS\');">'));

        static::assertSame('<IMG >', (new AntiXSS())->xss_clean('<IMG SRC=javascript:alert(\'XSS\')>'));

        static::assertSame('<IMG >', (new AntiXSS())->xss_clean('<IMG SRC=JaVaScRiPt:alert(\'XSS\')>'));

        static::assertSame('<IMG >', (new AntiXSS())->xss_clean('<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>'));

        static::assertSame('<IMG """>">', (new AntiXSS())->xss_clean('<IMG """><SCRIPT>alert("XSS")</SCRIPT>">'));

        static::assertSame('<IMG >', (new AntiXSS())->xss_clean('<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>'));

        static::assertSame('<IMG >', (new AntiXSS())->xss_clean('<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>'));

        static::assertSame('<IMG >', (new AntiXSS())->xss_clean('<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>'));

        static::assertSame('<IMG >', (new AntiXSS())->xss_clean('<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>'));

        static::assertSame('<IMG SRC="(\'XSS\');">', (new AntiXSS())->xss_clean('<IMG SRC="jav ascript:alert(\'XSS\');">'));

        static::assertSame('<IMG SRC="(\'XSS\');">', (new AntiXSS())->xss_clean('<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">'));

        static::assertSame('<IMG src="">', (new AntiXSS())->xss_clean('<IMG SRC="jav\nascript:alert(\'XSS\');">'));

        static::assertSame('<IMG >', (new AntiXSS())->xss_clean('<IMG SRC=java\0script:alert(\"XSS\")>'));

        static::assertSame('<IMG SRC=" &#14;  (\'XSS\');">', (new AntiXSS())->xss_clean('<IMG SRC=" &#14;  javascript:alert(\'XSS\');">'));

        static::assertSame('', (new AntiXSS())->xss_clean('<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>'));

        static::assertSame('&lt;BODY !#$%&()*~+-_.,:;?@[/|\]^`=alert&#40;"XSS"&#41;&gt;', (new AntiXSS())->xss_clean('<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>'));

        static::assertSame('&lt;BODY  !#$%&()*~+-_.,:;?@[/|\]^`=alert&#40;"XSS"&#41;&gt;', (new AntiXSS())->xss_clean('<BODY onload !#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>'));

        static::assertSame('', (new AntiXSS())->xss_clean('<<SCRIPT>alert("XSS");//<</SCRIPT>'));

        static::assertSame('', (new AntiXSS())->xss_clean('<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >'));

        static::assertSame('', (new AntiXSS())->xss_clean('<SCRIPT SRC=//ha.ckers.org/.j'));

        static::assertSame('&lt;IMG src=""', (new AntiXSS())->xss_clean('<IMG SRC="javascript:alert(\'XSS\')"'));

        static::assertSame('&lt;iframe src=http://ha.ckers.org/scriptlet.html <', (new AntiXSS())->xss_clean('<iframe src=http://ha.ckers.org/scriptlet.html <'));

        static::assertSame('&lt;iframe src=http://ha.ckers.org/scriptlet.html &gt;', (new AntiXSS())->xss_clean('<iframe src=http://ha.ckers.org/scriptlet.html >'));

        // 过滤 javascript:
        static::assertSame('<a >', (new AntiXSS())->xss_clean('<a style="url(\'javascript:alert(1)\')">'));
        static::assertSame('<td background="url(\'(1)\')">', (new AntiXSS())->xss_clean('<td background="url(\'javascript:alert(1)\')">'));

        // 过滤 style
        static::assertSame('<DIV >', (new AntiXSS())->xss_clean('<DIV STYLE="width: \nexpression(alert(1));">'));
        static::assertSame('<DIV >', (new AntiXSS())->xss_clean('<DIV STYLE="width: \n expressionexpression((alert(1));">'));
        // 不正常的url
        static::assertSame('<DIV >', (new AntiXSS())->xss_clean('<DIV STYLE="background:\n url (javascript:ooxx);">'));
        static::assertSame('<DIV >', (new AntiXSS())->xss_clean('<DIV STYLE="background:url (javascript:ooxx);">'));
        // 正常的url
        static::assertSame('<DIV >', (new AntiXSS())->xss_clean('<DIV STYLE="background: url (ooxx);">'));

        static::assertSame('<IMG SRC=\'("XSS")\'>', (new AntiXSS())->xss_clean('<IMG SRC=\'vbscript:msgbox("XSS")\'>'));

        static::assertSame('<IMG SRC="">', (new AntiXSS())->xss_clean('<IMG SRC="livescript:[code]">'));

        static::assertSame('<IMG SRC="">', (new AntiXSS())->xss_clean('<IMG SRC="mocha:[code]">'));

        static::assertSame('<a href="">', (new AntiXSS())->xss_clean('<a href="javas/**/cript:alert(\'XSS\');">'));

        static::assertSame('<a href="">', (new AntiXSS())->xss_clean('<a href="javascript:test">'));
        static::assertSame('<a href="/javascript/a">', (new AntiXSS())->xss_clean('<a href="/javascript/a">'));
        static::assertSame('<a href="/javascript/a">', (new AntiXSS())->xss_clean('<a href="/javascript/a">'));
        static::assertSame('<a href="http://aa.com">', (new AntiXSS())->xss_clean('<a href="http://aa.com">'));
        static::assertSame('<a href="https://aa.com">', (new AntiXSS())->xss_clean('<a href="https://aa.com">'));
        static::assertSame('<a href="mailto:me@ucdok.com">', (new AntiXSS())->xss_clean('<a href="mailto:me@ucdok.com">'));
        static::assertSame('<a href="#hello">', (new AntiXSS())->xss_clean('<a href="#hello">'));
        static::assertSame('<a href="other">', (new AntiXSS())->xss_clean('<a href="other">'));

        // 这个暂时不知道怎么处理
        //self::assertSame((new AntiXSS())->xss_clean('¼script¾alert(¢XSS¢)¼/script¾'), '');

        static::assertSame('&lt;!--[if gte IE 4]><![endif]--&gt; END', (new AntiXSS())->xss_clean('<!--[if gte IE 4]><SCRIPT>alert(\'XSS\');</SCRIPT><![endif]--> END'));
        static::assertSame('&lt;!--[if gte IE 4]><![endif]--&gt; END', (new AntiXSS())->xss_clean('<!--[if gte IE 4]><SCRIPT >alert(\'XSS\');</SCRIPT><![endif]--> END'));

        // HTML5新增实体编码 冒号&colon; 换行&NewLine;
        static::assertSame('<a href="(/xss/)">', (new AntiXSS())->xss_clean('<a href="javascript&colon;alert(/xss/)">'));
        static::assertSame('<a href="">', (new AntiXSS())->xss_clean('<a href="javascript&colonalert(/xss/)">'));
        static::assertSame('<a href="a&NewLine;b">', (new AntiXSS())->xss_clean('<a href="a&NewLine;b">'));
        static::assertSame('<a href="a&NewLineb">', (new AntiXSS())->xss_clean('<a href="a&NewLineb">'));
        static::assertSame('<a href="(1)">', (new AntiXSS())->xss_clean('<a href="javasc&NewLine;ript&colon;alert(1)">'));

        // data URI 协议过滤
        static::assertSame('<a href="">', (new AntiXSS())->xss_clean('<a href="data:">'));
        static::assertSame('<a href="">', (new AntiXSS())->xss_clean('<a href="d a t a : ">'));
        static::assertSame('<a href="">', (new AntiXSS())->xss_clean('<a href="data: html/text;">'));
        static::assertSame('<a href="">', (new AntiXSS())->xss_clean('<a href="data:html/text;">'));
        static::assertSame('<a href="">', (new AntiXSS())->xss_clean('<a href="data:html /text;">'));
        static::assertSame('<a href="">', (new AntiXSS())->xss_clean('<a href="data: image/text;">'));
        static::assertSame('<img src="">', (new AntiXSS())->xss_clean('<img src="data: aaa/text;">'));
        static::assertSame('<img src="">', (new AntiXSS())->xss_clean('<img src="data:image/png; base64; ofdkofiodiofl">'));
        static::assertSame('<img src="data:image/png; base64, iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==">', (new AntiXSS())->xss_clean('<img src="data:image/png; base64, iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==">'));
        static::assertSame('<img src="   PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==">', (new AntiXSS())->xss_clean('<img src="data:image/svg+xml  ;   base64  ,   PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==">'));

        static::assertSame('<img src="PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">', (new AntiXSS())->xss_clean('<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">'));

        // HTML备注处理
        static::assertSame('&lt;!--                               --&gt;', (new AntiXSS())->xss_clean('<!--                               -->'));
        static::assertSame('&lt;!--      a           --&gt;', (new AntiXSS())->xss_clean('<!--      a           -->'));
        static::assertSame('&lt;!--sa       --&gt;ss', (new AntiXSS())->xss_clean('<!--sa       -->ss'));
        static::assertSame('&lt;!--                               ', (new AntiXSS())->xss_clean('<!--                               '));
    }
}
