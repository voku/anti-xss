<?php

use voku\helper\AntiXSS;

/**
 * Class XssTestArray
 *
 * @internal
 */
final class XssTestArray extends \PHPUnit\Framework\TestCase
{
    /**
     * @var AntiXSS
     */
    public $security;

    public function testArray()
    {
        $testArray = [
            '<a href="http://www.chaos.org/">www.chaos.org</a>',
            '<a name="X">Short \'a name\' tag</a>',
            '<td colspan="3" rowspan="5">Foo</td>',
            '<td colspan=3 rowspan=5>Foo</td>',
            '<td colspan=\'3\' rowspan=\'5\'>Foo</td>',
            '<td rowspan="2" class="mugwump" style="background-color: rgb(255, 204 204);">Bar</td>',
            '<td nowrap>Very Long String running to 1000 characters...</td>',
            '<td bgcolor="#00ff00" nowrap>Very Long String with a blue background</td>',
            '<a href="proto1://www.foo.com">New protocol test</a>',
            '<img src="proto2://www.foo.com" />',
            '<a href="javascript:javascript:javascript:javascript:javascript:alert(\'Boo!\');">bleep</a>',
            '<a href="proto4://abc.xyz.foo.com">Another new protocol</a>',
            '<a href="proto9://foo.foo.foo.foo.foo.org/">Test of "proto9"</a>',
            '<td width="75">Bar!</td>',
            '<td width="200">Long Cell</td>',
            'search.php?q=%22%3Balert(%22XSS%22)%3B&n=1093&i=410',
            'http://localhost/text.php/"><script>alert(“Gehackt!”);</script></form><form action="/...',
            '<p>Montageprofile(n)</p>',
        ];

        $resultArray = [
            '<a href="http://www.chaos.org/">www.chaos.org</a>',
            '<a name="X">Short \'a name\' tag</a>',
            '<td colspan="3" rowspan="5">Foo</td>',
            '<td colspan=3 rowspan=5>Foo</td>',
            '<td colspan=\'3\' rowspan=\'5\'>Foo</td>',
            '<td rowspan="2" class="mugwump" >Bar</td>',
            '<td nowrap>Very Long String running to 1000 characters...</td>',
            '<td bgcolor="#00ff00" nowrap>Very Long String with a blue background</td>',
            '<a href="proto1://www.foo.com">New protocol test</a>',
            '<img src="proto2://www.foo.com" />',
            '<a href="(\'Boo!\');">bleep</a>',
            '<a href="proto4://abc.xyz.foo.com">Another new protocol</a>',
            '<a href="proto9://foo.foo.foo.foo.foo.org/">Test of "proto9"</a>',
            '<td width="75">Bar!</td>',
            '<td width="200">Long Cell</td>',
            'search.php?q=";alert&#40;"XSS"&#41;;&n=1093&i=410',
            'http://localhost/text.php/">&lt;/form&gt;&lt;form action="/...',
            '<p>Montageprofile(n)</p>',
        ];

        static::assertSame($resultArray, (new AntiXSS())->xss_clean($testArray));
    }
}
