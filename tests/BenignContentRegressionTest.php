<?php

declare(strict_types=1);

use voku\helper\AntiXSS;

/**
 * Harmless real-world content must stay unchanged and must not be reported as XSS.
 *
 * Every case here behaved like this in 4.1.46 (except where noted). Two of the 4.1.47 security fixes broke some of them:
 * - the namespace-prefix rule ("<x:script>") also encoded Office HTML like "<o:Title>", "<x:Selected/>",
 *   "<x:Header>" (XML names are case-sensitive and end at a non-name char, so these are no XHTML elements)
 * - the ISO-2022-JP rule treated every ESC byte as XSS, also ANSI color codes in log output
 *
 * @internal
 */
final class BenignContentRegressionTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @return array<string, array{0: string}>
     */
    public static function benignProvider(): array
    {
        return [
            // HTML exported / pasted from Microsoft Word and Excel
            'word paragraph'        => ['<p class="MsoNormal">Hello<o:p></o:p></p>'],
            'word properties'       => ['<o:DocumentProperties><o:Author>Jane</o:Author><o:Title>Report</o:Title><o:Pages>1</o:Pages></o:DocumentProperties>'],
            'word document'         => ['<w:WordDocument><w:View>Normal</w:View><w:Zoom>0</w:Zoom><w:TrackMoves/></w:WordDocument>'],
            'word styles'           => ['<w:LatentStyles DefLockedState="false"><w:LsdException Locked="false" Name="Normal"/></w:LatentStyles>'],
            'word smart tags'       => ['<st1:place w:st="on"><st1:City w:st="on">Berlin</st1:City></st1:place>'],
            'excel options'         => ['<x:WorksheetOptions><x:Selected/><x:Panes><x:Pane><x:Number>3</x:Number></x:Pane></x:Panes></x:WorksheetOptions>'],
            'excel worksheet'       => ['<x:ExcelWorksheet><x:Name>Sheet1</x:Name><x:WorksheetSource HRef="sheet001.htm"/></x:ExcelWorksheet>'],
            'excel formatting'      => ['<x:FormulaHidden/><x:Formatting/><x:Header>Top</x:Header>'],
            'office smart tag type' => ['<o:SmartTagType name="Script"/>'],
            'namespaced text'       => ['Use the tags <ns:selection> and <app:format> for this.'],
            // log output with ANSI colors
            'ansi colors'           => ["\x1B[32mOK\x1B[0m build finished"],
            // ordinary text
            'numeric references'    => ['Copyright &#169 2026, em dash &#8212 here, &#x2014 there'],
            'entity colon prose'    => ['JavaScript&#58; The Good Parts'],
            'e-mail in brackets'    => ['Write to <info@example.com> or <sales@example.org>'],
            'words with on'         => ['The onboarding is online only once: onset=early, oncall=yes'],
            'percent signs'         => ['Discount 10%0 off? No: 10% off, 100%25 sure, %0d%0a done'],
            'nested quotes'         => ['<p title=\'He said "hi"\'>Quote</p> and <span title="it\'s">x</span>'],
            'template'              => ['<template id="row"><td>cell</td></template>'],
            // "on" in names and values that are no event handler attributes (see "EventHandlerAttributeTest")
            'event word in title'   => ['<p title="onreading mode">Read</p>'],
            'url with on params'    => ['<a href="https://example.com/?online=1&amp;onboarding=2">x</a>'],
            'svelte syntax'         => ['<div on:click="save">Save</div>'],
            'vue syntax'            => ['<div v-on:click="save" @click="save">Save</div>'],
            'xml config'            => ['<config><option name="online" value="on"/></config>'],
            'xml on elements'       => ['<onboarding><online>yes</online></onboarding>'],
            'log line'              => ['2026-11-19 ERROR handler onfoo=null failed (retry on=3)'],
            'json'                  => ['{"online":true,"onboarding":"done","onfoo":"x"}'],
            'email text'            => ["Hi,\nplease switch onboarding=on before Monday.\n> quoted: onfoo=1\nThanks"],
            'markdown code'         => ['Set `onfoo=1` and <kbd>on</kbd> to enable it.'],
            'on with digits'        => ['<my-el on1="x" on-x="y">z</my-el>'],
            // before 4.1.50, the event name after the "-" was removed
            'custom data attributes' => ['<div data-onupdate="manual" data-ontext="label" data-onclick="example">Example</div>'],
            'aria attribute'        => ['<div aria-onfocus-hint="x" class="onboarding">x</div>'],
        ];
    }

    /**
     * @dataProvider benignProvider
     *
     * @param string $html
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('benignProvider')]
    public function testBenignContentIsUnchanged($html)
    {
        $antiXss = new AntiXSS();

        static::assertSame($html, $antiXss->xss_clean($html));
        static::assertFalse($antiXss->isXssFound());
    }

    public function testRealXhtmlElementsWithPrefixAreStillEncoded()
    {
        foreach (['<x:script>alert(1)</x:script>', '<xhtml:iframe src="//evil.example"></xhtml:iframe>', '<x:style>body{}</x:style>'] as $html) {
            $antiXss = new AntiXSS();
            $output = $antiXss->xss_clean($html);

            static::assertTrue($antiXss->isXssFound(), $html);
            static::assertFalse(\strpos($output, '<x:') !== false || \strpos($output, '<xhtml:') !== false, $html . ' -> ' . $output);
        }
    }

    public function testIso2022JpEscapeSequencesAreStillReported()
    {
        foreach (["<scr\x1B(Bipt>", "<scr\x1B(Jipt>", "<scr\x1B\$Bipt>", "<scr\x1B\$@ipt>"] as $html) {
            $antiXss = new AntiXSS();
            $output = $antiXss->xss_clean($html);

            static::assertTrue($antiXss->isXssFound(), \bin2hex($html));
            static::assertFalse(\strpos($output, "\x1B") !== false, \bin2hex($html));
        }
    }
}
