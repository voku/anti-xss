<?php

use voku\helper\AntiXSS;

/**
 * Class XssTestArray
 */
class XssTestArray extends PHPUnit_Framework_TestCase
{

  /**
   * @var $security AntiXSS
   */
  public $security;

  public function setUp()
  {
    $this->security = new AntiXSS();
  }


  public function test_array()
  {
    $testArray = array(
        '<a href="http://www.chaos.org/">www.chaos.org</a>',
        '<a name="X">Short \'a name\' tag</a>',
        '<td colspan="3" rowspan="5">Foo</td>',
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
    );

    $resultArray = array(
        '<a href="http://www.chaos.org/">www.chaos.org</a>',
        '<a name="X">Short \'a name\' tag</a>',
        '<td colspan="3" rowspan="5">Foo</td>',
        '<td rowspan="2" class="mugwump" >Bar</td>',
        '<td nowrap>Very Long String running to 1000 characters...</td>',
        '<td bgcolor="#00ff00" nowrap>Very Long String with a blue background</td>',
        '<a href="proto1://www.foo.com">New protocol test</a>',
        '<img src="proto2://www.foo.com" />',
        '<a href="">bleep</a>',
        '<a href="proto4://abc.xyz.foo.com">Another new protocol</a>',
        '<a href="proto9://foo.foo.foo.foo.foo.org/">Test of "proto9"</a>',
        '<td width="75">Bar!</td>',
        '<td width="200">Long Cell</td>',
        'search.php?q=";alert&#40;"XSS"&#41;;&n=1093&i=410',
        'http://localhost/text.php/">alert&#40;“Gehackt!”&#41;;&lt;/form&gt;&lt;form action="/...',
    );

    self::assertSame($resultArray, $this->security->xss_clean($testArray));
  }

}
