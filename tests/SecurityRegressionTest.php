<?php

declare(strict_types=1);

use voku\helper\AntiXSS;

/**
 * Regression tests for the findings of an automated security scan (2026-11).
 *
 * The DoS tests use inputs that took several seconds (or threw an exception) before the fix and only a few
 * milliseconds afterwards, so the time limits are very generous on purpose (CI runs with Xdebug).
 *
 * @internal
 */
final class SecurityRegressionTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @param string        $input
     * @param callable|null $config
     *
     * @return array{0: string, 1: bool|null, 2: float}
     */
    private static function clean($input, $config = null): array
    {
        $antiXss = new AntiXSS();
        if ($config !== null) {
            $config($antiXss);
        }

        $start = \microtime(true);
        $output = $antiXss->xss_clean($input);
        $duration = \microtime(true) - $start;

        return [$output, $antiXss->isXssFound(), $duration];
    }

    /**
     * INFO: "assertStringNotContainsString()" needs PHPUnit >= 7.5, but we also test with PHPUnit 7.0
     *
     * @param string $needle
     * @param string $haystack
     * @param string $message
     *
     * @return void
     */
    private static function assertNotContainsCaseSensitive($needle, $haystack, $message = '')
    {
        static::assertFalse(\strpos($haystack, $needle) !== false, $message . ' | "' . $needle . '" found in: ' . $haystack);
    }

    /**
     * @param string $needle
     * @param string $haystack
     * @param string $message
     *
     * @return void
     */
    private static function assertNotContainsIgnoringCase($needle, $haystack, $message = '')
    {
        static::assertFalse(\stripos($haystack, $needle) !== false, $message . ' | "' . $needle . '" found in: ' . $haystack);
    }

    public function testSemicolonLessNumericCharacterReferenceBeforeRemovedCharsIsDetected()
    {
        // ANT-2026-I95BDWMG
        $inputs = [
            '<a href="javascript&#x3a%0bfetch(1)">x</a>',
            '<a href="javascript&#x3a%0cfetch(1)">x</a>',
            "<a href=\"javascript&#x3a\u{FEFF}alert(1)\">x</a>",
            '<a href="javascript&#58%0b1;alert(1)">x</a>',
            '<a href="javascript&#x3a\\u0066etch(1)">x</a>',
        ];

        foreach ($inputs as $input) {
            [$output, $found] = self::clean($input);

            static::assertTrue($found, 'testing: ' . $input);
            self::assertNotContainsIgnoringCase('javascript', $output, 'testing: ' . $input);
        }
    }

    public function testNamespacePrefixedEvilTagsAreRemoved()
    {
        // ANT-2026-BCMA4763
        [$output, $found] = self::clean('<x:script xmlns:x="http://www.w3.org/1999/xhtml">print()</x:script>');
        static::assertTrue($found);
        self::assertNotContainsCaseSensitive('<x:script', $output);

        [$output, $found] = self::clean('<xhtml:iframe src="//evil.example"></xhtml:iframe>');
        static::assertTrue($found);
        self::assertNotContainsCaseSensitive('<xhtml:iframe', $output);

        // no false-positive for harmless prefixed tags
        [$output, $found] = self::clean('<b>Note: style matters</b> <x:p>ok</x:p>');
        static::assertFalse($found);
        static::assertSame('<b>Note: style matters</b> <x:p>ok</x:p>', $output);
    }

    public function testEncodedScriptTagSpellingsAreRemoved()
    {
        // ANT-2026-M5424N6G
        $config = static function (AntiXSS $antiXss) {
            $antiXss->removeEvilHtmlTags(['iframe']);
        };
        [$output, $found] = self::clean('<iframe srcdoc=&lt;script/x&gt;print()&lt;/script/x&gt;></iframe>', $config);
        static::assertTrue($found);
        self::assertNotContainsIgnoringCase('script', $output);

        foreach (
            [
                '<b>hi</b>&lt;script &gt;print()&lt;/script &gt;',
                "<b>hi</b>&lt;script\t&gt;print()",
                '<b>hi</b>&#60;script>print()&#60;/script>',
                '<b>hi</b>&#x3c;script/x>print()',
                '<b>hi</b>&LTscript>print()',
            ] as $input
        ) {
            [$output, $found] = self::clean($input);
            static::assertTrue($found, 'testing: ' . $input);
            self::assertNotContainsIgnoringCase('script', $output, 'testing: ' . $input);
        }

        // no false-positive for other tag names
        [$output, $found] = self::clean('I like &lt;scripts&gt; and &lt;b&gt;');
        static::assertFalse($found);
        static::assertSame('I like &lt;scripts&gt; and &lt;b&gt;', $output);
    }

    public function testEscByteForIso2022JpIsNotReturnedUnchecked()
    {
        // ANT-2026-5MDMS9XA
        [$output, $found] = self::clean("<scr\x1B(Bipt>print()</scr\x1B(Bipt>");

        static::assertTrue($found);
        self::assertNotContainsCaseSensitive("\x1B", $output);
    }

    public function testShortCustomEvilTagDoesNotShadowBuiltInEvilTags()
    {
        // ANT-2026-RKI0UXIG
        foreach (['s', 'b', 'i', 'p', 'li', 'em'] as $tag) {
            $config = static function (AntiXSS $antiXss) use ($tag) {
                $antiXss->addEvilHtmlTags([$tag]);
            };

            [$output, $found] = self::clean('<style>@import url(//evil.example/x.css);</style>', $config);
            static::assertTrue($found, 'testing: ' . $tag);
            self::assertNotContainsCaseSensitive('<style>', $output, 'testing: ' . $tag);
        }
    }

    public function testContentAfterImgWithoutAttributesIsKept()
    {
        // ANT-2026-7MX39GUZ
        [$output] = self::clean('<img><i a=b> keep this');
        static::assertSame('<img><i a=b> keep this', $output);

        $input = '<img>' . \str_repeat('a=b>', 100);
        [$output] = self::clean($input);
        static::assertSame($input, $output);

        $input = '<img/>' . \str_repeat('<td width=10>', 3000);
        [$output] = self::clean($input);
        static::assertSame($input, $output);

        [$output, $found] = self::clean('<img src=x onerror=alert(1)>');
        static::assertTrue($found);
        static::assertSame('<img >', $output);
    }

    public function testDosCompactExplodedJavascriptOnUrlEncodedSpacingRuns()
    {
        // ANT-2026-Z8F40WBR
        // a run of "%0d" (quadratic regex) + a nested "document.cookie" (one layer removed per pass of the
        // main loop, so the quadratic regex ran ~90 times): took ~16 seconds before the fix
        $nested = 'x';
        for ($i = 0; $i < 90; ++$i) {
            $nested = 'docu' . $nested . 'ment.cookie';
        }
        [$output, $found, $duration] = self::clean(
            '<b>hi</b>' . \str_repeat('%0d', 8000) . 'ocumenx t ' . \str_replace('x', '', $nested)
        );
        static::assertTrue($found);
        self::assertNotContainsCaseSensitive('document.cookie', $output);
        static::assertLessThan(5.0, $duration);
    }

    public function testDosColonJoinedEventHandlerNames()
    {
        // ANT-2026-M0ZKQH2E
        [$output, $found, $duration] = self::clean('<a ' . \str_repeat(':onclick', 4000) . ' onclick=x>');
        static::assertTrue($found);
        self::assertNotContainsIgnoringCase('onclick', $output);
        static::assertLessThan(5.0, $duration);

        // many event names in front of one ">" (did throw a "non-converging sanitization loop"-exception)
        [$output, $found, $duration] = self::clean('<a x="' . \str_repeat(' onclick', 20000) . '" onclick=1>');
        static::assertTrue($found);
        self::assertNotContainsIgnoringCase('onclick', $output);
        static::assertLessThan(5.0, $duration);

        [$output, $found] = self::clean('x onclick onerror=alert(1)');
        static::assertTrue($found);
        self::assertNotContainsIgnoringCase('onclick', $output);
        self::assertNotContainsIgnoringCase('onerror', $output);
    }

    public function testDosBase64ImageCheck()
    {
        // ANT-2026-EDIARMWR
        [, , $duration] = self::clean(\str_repeat('<img alt="' . \str_repeat('data:image/ base64 ', 70) . '">', 76));
        static::assertLessThan(5.0, $duration);

        // base64 images are still allowed
        [$output, $found] = self::clean('<img src="data:image/png;base64,iVBORw0KGgo=">');
        static::assertFalse($found);
        static::assertSame('<img src="data:image/png;base64,iVBORw0KGgo=">', $output);
    }

    public function testDosHtmlTagDecodingRegex()
    {
        // ANT-2026-WEHNW4GB (took ~9 seconds before)
        [, , $duration] = self::clean(\str_repeat('<a', 4000) . "'>" . \str_repeat("'", 26));
        static::assertLessThan(5.0, $duration);

        [, , $duration] = self::clean(\str_repeat("<a\"'", 30000) . 'x');
        static::assertLessThan(5.0, $duration);

        [, , $duration] = self::clean(\str_repeat("<a\"'", 30000) . 'x>');
        static::assertLessThan(5.0, $duration);

        // a tag with an unclosed quote after a closed one is still decoded
        [$output, $found] = self::clean('<b>x</b><a href="javascript&#58;alert(1)" title="x>');
        static::assertTrue($found);
        self::assertNotContainsIgnoringCase('javascript', $output);
    }

    public function testDosNestedAttributeCleaning()
    {
        // ANT-2026-Y8HRFVF9
        $encode = static function ($level, $char) {
            if ($level === 0) {
                return $char;
            }

            $hex = \sprintf('u%04x', \ord($char));
            if ($level === 1) {
                return '%' . $hex;
            }

            return '%25' . \str_repeat('u0025', $level - 2) . $hex;
        };
        $build = static function ($depth, $level) use (&$build, $encode) {
            if ($depth === 0) {
                return 'x';
            }

            return $encode($level, '<') . 'a href=' . $encode($level, '"')
                   . $build($depth - 1, $level + 1)
                   . $encode($level, '"') . $encode($level, '>') . 'x';
        };

        [, $found, $duration] = self::clean($build(14, 0));
        static::assertTrue($found);
        static::assertLessThan(5.0, $duration);
    }

    public function testDosNestedUrlEncodedControlCharacters()
    {
        // ANT-2026-7MAJ583A (took ~6 seconds before)
        $input = \str_repeat('%0', 32000) . \str_repeat('0', 32000);
        [$output, , $duration] = self::clean($input);
        static::assertLessThan(5.0, $duration);
        static::assertSame($input, $output);

        // "%0C" (form feed) is whitespace and must not join attributes
        [$output, $found] = self::clean('data:text/html,<img%0Csrc=x%0Conerror=print()>');
        static::assertTrue($found);
        self::assertNotContainsIgnoringCase('onerror', $output);
    }

    public function testNeverAllowedRegexInlineOptionDoesNotChangeBuiltInRules()
    {
        // ANT-2026-WGO0FFT4
        $antiXss = new AntiXSS();
        $antiXss->addNeverAllowedRegex(['(?-i)foo' => '']);

        static::assertSame('', $antiXss->xss_clean('DOCUMENT.LOCATION'));
        static::assertTrue($antiXss->isXssFound());
    }

    public function testNeverAllowedRegexWithStartOfPatternDirective()
    {
        // "(*UCP)" is only valid at the start of a pattern, so it must not break the combined regex
        $antiXss = new AntiXSS();
        $antiXss->addNeverAllowedRegex(['(*UCP)foo\w' => '']);

        static::assertSame('', $antiXss->xss_clean('DOCUMENT.LOCATION'));
        static::assertTrue($antiXss->isXssFound());
        static::assertSame('x  y', $antiXss->xss_clean('x fooß y'));
    }

    public function testRemoveNeverAllowedRegexRemovesOnlyTheGivenRegex()
    {
        // ANT-2026-FQPY2TCU
        $antiXss = new AntiXSS();
        $antiXss->addNeverAllowedRegex(['foo123' => '']);
        $antiXss->removeNeverAllowedRegex(['foo123' => '']);

        static::assertSame('foo123', $antiXss->xss_clean('foo123'));
        static::assertSame('<a href="#"></a>', $antiXss->xss_clean('<a href="#">document.location</a>'));
        static::assertTrue($antiXss->isXssFound());
    }

    public function testShadowRootModeIsRemoved()
    {
        // ANT-2026-4KHCT3ES
        [$output, $found] = self::clean('<template shadowrootmode="open"></template>');
        static::assertTrue($found);
        static::assertSame('<template ></template>', $output);
    }

    public function testEncodedColonAfterJavascriptBetweenTagsIsDetected()
    {
        // side note in ANT-2026-M5424N6G: "javascript&colon;print()//<b>" (e.g. printed into <a href="OUT">)
        foreach (
            [
                'javascript&colon;print()//<b>',
                '<b>x</b>javascript&#58print()//',
                '<b>x</b>javascript&#x3a;print()//',
            ] as $input
        ) {
            [$output, $found] = self::clean($input);
            static::assertTrue($found, 'testing: ' . $input);
            self::assertNotContainsIgnoringCase('javascript', $output, 'testing: ' . $input);
        }
    }

    public function testEvilTagDirectlyAfterLookalikeTagIsEncoded()
    {
        // side note in ANT-2026-RKI0UXIG: a tag directly after "<header>" skipped the evil-tag check
        [$output, $found] = self::clean('<header><style>x</style>');
        static::assertTrue($found);
        self::assertNotContainsCaseSensitive('<style>', $output);

        [$output, $found] = self::clean('<header><svg>');
        static::assertTrue($found);
        self::assertNotContainsCaseSensitive('<svg>', $output);
    }

    public function testHtmlTagsWithNonAsciiNamesAreDecoded()
    {
        // tag names that start with a 2-, 3- or 4-byte letter are still decoded (and checked)
        foreach (["\u{E9}a", "\u{4E2D}", "\u{1D49C}"] as $tagName) {
            [$output, $found] = self::clean('<' . $tagName . ' href="javascript&#58;alert(1)">x');
            static::assertTrue($found, 'testing: ' . $tagName);
            self::assertNotContainsIgnoringCase('javascript', $output, 'testing: ' . $tagName);
        }

        // a non-letter after "<" is not a tag (same result as before the linear scan)
        [$output, $found] = self::clean("<\u{20AC} 5> x");
        static::assertTrue($found);
        static::assertSame("&lt;\u{20AC} 5&gt; x", $output);
    }

    public function testEventHandlerRemovalWithReplacementAndUnicodeSpace()
    {
        $config = static function (AntiXSS $antiXss) {
            $antiXss->setReplacement('[removed]');
        };
        [$output, $found] = self::clean('x onclick onerror=alert(1)', $config);
        static::assertTrue($found);
        self::assertNotContainsIgnoringCase('onclick', $output);
        self::assertNotContainsIgnoringCase('onerror', $output);

        // a non-breaking space in front of "=" (no ">" after it)
        [$output, $found] = self::clean("x onclick \u{A0}[a]=alert(1)");
        static::assertTrue($found);
        self::assertNotContainsIgnoringCase('onclick', $output);
    }

    public function testRemoveNeverAllowedRegexByListOfRegexesOrReplacements()
    {
        // a list of regexes (values) removes these regexes
        static::assertSame('&lt;!--', (new AntiXSS())->xss_clean('<!--'));
        $antiXss = new AntiXSS();
        $antiXss->removeNeverAllowedRegex(['<!--']);
        static::assertSame('<!--', $antiXss->xss_clean('<!--'));

        // BC: a list of replacements removes all regexes with this replacement
        $antiXss = new AntiXSS();
        $antiXss->removeNeverAllowedRegex(['']);
        static::assertSame('document.location', $antiXss->xss_clean('document.location'));
        static::assertFalse($antiXss->isXssFound());
    }

    public function testBase64BeforeDataImageIsNotAnAllowedBase64Image()
    {
        [$output, $found] = self::clean('<img alt="base64," src="javascript:alert(1)" title="data:image/png">');
        static::assertTrue($found);
        self::assertNotContainsIgnoringCase('javascript', $output);
    }

    public function testDataUrlSplitByTabOrNewline()
    {
        // ANT-2026-A7VEVFY6
        foreach (
            [
                "data:image/s\tvg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",
                "data:image/s\nvg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",
                "da\tta:text/html;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",
                "data:image/\tsvg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",
                "data:image/\nsvg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+",
            ] as $input
        ) {
            [$output, $found] = self::clean($input);
            static::assertTrue($found, 'testing: ' . $input);
            self::assertNotContainsCaseSensitive('base64', $output, 'testing: ' . $input);
        }
    }
}
