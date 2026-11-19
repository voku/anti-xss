<?php

declare(strict_types=1);

use voku\helper\AntiXSS;

/**
 * Event handler attributes are removed by their *structure* ("on" + ASCII letters as an attribute name, found with
 * the rules of the HTML tokenizer), not only if the name is on the "_never_allowed_on_events_afterwards" list.
 *
 * So the next new browser event (e.g. "ongesturestart" in Safari, which was not on the list) can not bypass the
 * filter, and the list does not have to grow with every new event. Names that only look like an event handler
 * (e.g. 'data-onclick', 'title="onreading mode"', 'class="onboarding"', "on:click") are kept.
 *
 * @internal
 */
final class EventHandlerAttributeTest extends \PHPUnit\Framework\TestCase
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
    private static function assertNotContainsIgnoringCase($needle, $haystack, $message = '')
    {
        static::assertFalse(\stripos($haystack, $needle) !== false, $message . ' | "' . $needle . '" found in: ' . $haystack);
    }

    /**
     * @param string $needle
     * @param string $haystack
     * @param string $message
     *
     * @return void
     */
    private static function assertContainsCaseSensitive($needle, $haystack, $message = '')
    {
        static::assertTrue(\strpos($haystack, $needle) !== false, $message . ' | "' . $needle . '" not found in: ' . $haystack);
    }

    /**
     * The output of "xss_clean()" has no event handler attribute for any possible start tag, so the structural
     * filter does not change it again.
     *
     * @param string $output
     * @param string $message
     *
     * @return void
     */
    private static function assertNoEventHandlerAttributeLeft($output, $message = '')
    {
        $method = new \ReflectionMethod(AntiXSS::class, '_remove_event_handler_attributes');
        $method->setAccessible(true);

        static::assertSame($output, $method->invoke(new AntiXSS(), $output), $message);
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: bool}>
     */
    public static function provideContract(): array
    {
        return [
            // removed: known, WebKit-only and unknown / future event handlers
            'known event'                   => ['<div onclick="alert(1)">x</div>', '<div >x</div>', true],
            'webkit gesture event'          => ['<div ongesturestart="alert(1)">x</div>', '<div >x</div>', true],
            'webkit gesture event, case'    => ['<div onGESTURESTART="alert(1)">x</div>', '<div >x</div>', true],
            'webkit gesture, paren-free'    => ['<a ongesturechange="location=name">x</a>', '<a >x</a>', true],
            'webkit force touch event'      => ['<div onwebkitmouseforcedown="alert(1)">x</div>', '<div >x</div>', true],
            'future event'                  => ['<div onfutureevent="alert(1)">x</div>', '<div >x</div>', true],
            'future event, uppercase'       => ['<DIV ONFUTUREEVENT=1>x</DIV>', '<DIV >x</DIV>', true],
            'unknown event after ">" value' => ['<x 1=">" onxxx=1 (text outside tag)', '<x 1=">"  (text outside tag)', true],
            'other attributes are kept'     => ['<div class="keep" onfoo = "1" id=keep>x</div>', '<div class="keep"  id=keep>x</div>', true],
            'single-quoted value'           => ['<div onfoo=\'1\' class=keep>x</div>', '<div  class=keep>x</div>', true],
            'no whitespace after a value'   => ['<a href="#"onfoo=1>x</a>', '<a href="#">x</a>', true],
            'after "/"'                     => ['<img/onfoo=1>', '<img/>', true],
            'svg'                           => ['<svg><rect onfoo="1"/></svg>', '&lt;svg&gt;<rect />&lt;/svg&gt;', true],
            'mathml'                        => ['<math><mi onfoo=1>x</mi></math>', '&lt;math&gt;<mi >x</mi>&lt;/math&gt;', true],
            // kept: only attribute *names* "on" + ASCII letters are event handlers
            'data-onclick'                  => ['<div data-onclick="example">x</div>', '<div data-onclick="example">x</div>', false],
            'data-onupdate'                 => ['<div data-onupdate="manual">Example</div>', '<div data-onupdate="manual">Example</div>', false],
            'data-ontext'                   => ['<div data-ontext="label">Example</div>', '<div data-ontext="label">Example</div>', false],
            'aria-onfocus-hint'             => ['<div aria-onfocus-hint="x">x</div>', '<div aria-onfocus-hint="x">x</div>', false],
            'event name in a value'         => ['<p title="onreading mode">Read</p>', '<p title="onreading mode">Read</p>', false],
            'class onboarding'              => ['<div class="onboarding">x</div>', '<div class="onboarding">x</div>', false],
            'url query'                     => ['<a href="https://example.com/?online=1&amp;onfoo=2">x</a>', '<a href="https://example.com/?online=1&amp;onfoo=2">x</a>', false],
            'on:click (framework syntax)'   => ['<div on:click="handler">x</div>', '<div on:click="handler">x</div>', false],
            'on_load'                       => ['<div on_load="x">x</div>', '<div on_load="x">x</div>', false],
            'on-click'                      => ['<div on-click="x">x</div>', '<div on-click="x">x</div>', false],
            'on + digit'                    => ['<div onfoo1=x>x</div>', '<div onfoo1=x>x</div>', false],
            'only "on"'                     => ['<div on=1>x</div>', '<div on=1>x</div>', false],
            'no value'                      => ['<div onfoo>x</div>', '<div onfoo>x</div>', false],
            'text in html'                  => ['<p>switch onfoo=1 later</p>', '<p>switch onfoo=1 later</p>', false],
            'plain text'                    => ['turn onfoo=bar on', 'turn onfoo=bar on', false],
            'json'                          => ['{"onfoo":"x","online":true}', '{"onfoo":"x","online":true}', false],
        ];
    }

    /**
     * @dataProvider provideContract
     *
     * @param string $input
     * @param string $expected
     * @param bool   $xssFound
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('provideContract')]
    public function testContract($input, $expected, $xssFound)
    {
        list($output, $found) = self::clean($input);

        static::assertSame($expected, $output);
        static::assertSame($xssFound, $found);
        self::assertNoEventHandlerAttributeLeft($output);
    }

    /**
     * All combinations of name spelling, separator before the name, "=" spacing and value quoting.
     *
     * @return void
     */
    public function testSyntaxVariations()
    {
        $names = ['onfoo', 'ONFOO', 'oNgEsTuReStArT', 'onclick', 'onwebkitmouseforceup'];
        $separators = [' ', "\t", "\n", "\r", '/', ' / ', '" ', '"'];
        $equals = ['=', ' = ', "\t=\n"];
        $values = ['"alert(1)"', '\'alert(1)\'', 'alert(1)', 'location=name', '"x>y"', '\'\''];

        $failures = [];
        foreach ($names as $name) {
            foreach ($separators as $separator) {
                foreach ($equals as $equal) {
                    foreach ($values as $value) {
                        // the separator '"' closes the quoted value of "data-x"
                        $prefix = $separator[0] === '"' ? '<div class="keep" data-x="1' : '<div class="keep"';
                        $input = $prefix . $separator . $name . $equal . $value . ' id="keep">text</div>';

                        list($output, $found) = self::clean($input);

                        if (
                            \stripos($output, $name) !== false
                            ||
                            \strpos($output, 'class="keep"') === false
                            ||
                            \strpos($output, 'id="keep">text</div>') === false
                            ||
                            $found !== true
                        ) {
                            $failures[] = $input . ' => ' . $output;
                        }
                    }
                }
            }
        }

        static::assertSame([], $failures);
    }

    /**
     * Property-based: random (seeded, so reproducible) event names, that are not on any list, on random tags at
     * random positions, between harmless attributes.
     *
     * @return void
     */
    public function testRandomUnknownEventNamesAreRemoved()
    {
        $tags = ['div', 'a', 'span', 'p', 'button', 'details', 'custom-element', 'x', 'DIV', 'Video'];
        $letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

        $failures = [];
        \mt_srand(20261119);
        for ($i = 0; $i < 500; ++$i) {
            $name = \mt_rand(0, 1) === 0 ? 'on' : 'ON';
            $length = \mt_rand(1, 24);
            for ($j = 0; $j < $length; ++$j) {
                $name .= $letters[\mt_rand(0, 51)];
            }

            $tag = $tags[\mt_rand(0, \count($tags) - 1)];
            $before = \str_repeat(' data-k' . \mt_rand(0, 9) . '="v"', \mt_rand(0, 2));
            $after = \str_repeat(' title="t' . \mt_rand(0, 9) . '"', \mt_rand(0, 2));
            $input = '<' . $tag . $before . ' ' . $name . '="alert(' . $i . ')"' . $after . '>text</' . $tag . '>';

            list($output, $found) = self::clean($input);

            // INFO: other filters can encode the tag (e.g. "<button") or merge duplicate attributes
            if (
                \stripos($output, $name) !== false
                ||
                \strpos($output, 'alert') !== false
                ||
                ($before !== '' && \strpos($output, \trim(\substr($before, 0, 13))) === false)
                ||
                ($after !== '' && \strpos($output, \trim(\substr($after, 0, 11))) === false)
                ||
                \strpos($output, 'text') === false
                ||
                $found !== true
            ) {
                $failures[] = $input . ' => ' . $output;
            }

            self::assertNoEventHandlerAttributeLeft($output, $input);
        }

        static::assertSame([], $failures);
    }

    /**
     * The context of a "<" (text, comment, "<textarea>", attribute value, ...) is not parsed, so every possible
     * start tag is checked: the browser can see a start tag where a simple parser sees a quoted value.
     *
     * @return void
     */
    public function testEveryPossibleStartTagIsChecked()
    {
        $inputs = [
            '<textarea><p title="</textarea><img src=x onfoo=alert(1)>"></textarea>',
            '<!-- <p title=" --><img src=x onfoo=alert(1)>"> -->',
            '<title><a title="</title><img onfoo=alert(1)>"></title>',
            '<noscript><p title="</noscript><img onfoo=alert(1)>"></noscript>',
            '<style><p title="</style><img onfoo=alert(1)>"></style>',
            '<svg><![CDATA[<img onfoo=alert(1)>]]></svg>',
            '<p title="<b onfoo=alert(1)>">x</p>',
            '<div x=\'<b onfoo="1\'>" onbar=2>',
        ];

        foreach ($inputs as $input) {
            list($output, $found) = self::clean($input);

            self::assertNotContainsIgnoringCase('onfoo', $output, $input);
            self::assertNoEventHandlerAttributeLeft($output, $input);
            static::assertTrue($found, $input);
        }

        // INFO: an earlier filter rewrites the attributes of "<a>", so that "onbar" is only text afterwards
        list($output) = self::clean('<a x=\'<b onfoo="1\'>" onbar=2>');
        static::assertSame('<a x=\'&lt;b \'>" onbar=2>', $output);
        self::assertNoEventHandlerAttributeLeft($output);
    }

    /**
     * Fixpoint property on random markup: whatever the other filters do, no output has an event handler attribute
     * for any possible start tag.
     *
     * @return void
     */
    public function testRandomMarkupHasNoEventHandlerAttributeLeft()
    {
        $tokens = [
            '<a ', '<b', '<svg ', '<img ', '<textarea>', '</textarea>', '<!--', '-->', '<x:y ', '"', "'", '>', '/', ' ',
            "\t", "\n", '=', 'onfoo', 'ONBAR', 'onclick', 'ongesturestart', 'on', 'x', 'title=', 'href=', 'data-',
            'alert(1)', '`', '&quot;', '&#x6f;n', '%3C', '<![CDATA[', ']]>', '&lt;', '<', 'b=', '1',
        ];

        \mt_srand(20261120);
        for ($i = 0; $i < 3000; ++$i) {
            $input = '';
            $count = \mt_rand(1, 20);
            for ($j = 0; $j < $count; ++$j) {
                $input .= $tokens[\mt_rand(0, \count($tokens) - 1)];
            }

            list($output) = self::clean($input);
            self::assertNoEventHandlerAttributeLeft($output, 'corpus #' . $i . ': ' . $input);
        }
    }

    /**
     * Edge cases of the tokenizer itself (without the other filters).
     *
     * @return void
     */
    public function testTokenizerEdgeCases()
    {
        $method = new \ReflectionMethod(AntiXSS::class, '_remove_event_handler_attributes');
        $method->setAccessible(true);
        $antiXss = new AntiXSS();

        $cases = [
            // first char of the tag name: ASCII letters only, also the boundaries "A", "Z", "a", "z"
            '<A onfoo=1>'                  => '<A >',
            '<Z onfoo=1>'                  => '<Z >',
            '<a onfoo=1>'                  => '<a >',
            '<z onfoo=1>'                  => '<z >',
            '<@ onfoo=1>'                  => '<@ onfoo=1>',
            '<[ onfoo=1>'                  => '<[ onfoo=1>',
            '<{ onfoo=1>'                  => '<{ onfoo=1>',
            '<1 onfoo=1>'                  => '<1 onfoo=1>',
            // only "on" + ASCII letters is an event handler
            '<div onfoo1=x onbar=1>'       => '<div onfoo1=x >',
            '<div on1foo=x onbar=1>'       => '<div on1foo=x >',
            // ranges found by different starts: out of order (the inner start is found later) ...
            '<a x=\'<b onfoo=1 \' onbar=2>' => '<a x=\'<b  \' >',
            // ... and nested (the inner attribute is inside of the value of the outer one)
            '<a onx="<b ony=1>" z=1>'      => '<a  z=1>',
            '<a onx="<b ony=1 onz=2>">'    => '<a >',
            // a start inside of an already scanned tag name
            '<b<b<b onfoo=1>'              => '<b<b<b >',
            // missing value / value until the end
            '<div onfoo=>x'                => '<div >x',
            '<div onfoo="1'                => '<div ',
            '<div onfoo= '                 => '<div ',
        ];

        foreach ($cases as $input => $expected) {
            static::assertSame($expected, $method->invoke($antiXss, $input), $input);
        }
    }

    /**
     * The fallback (too many event handlers) is more conservative than the tokenizer: it also removes "on...=" in
     * text, but it keeps allowed event handlers (case-insensitive).
     *
     * @return void
     */
    public function testFallbackIsMoreConservativeAndKeepsAllowedEventHandlers()
    {
        $method = new \ReflectionMethod(AntiXSS::class, '_remove_event_handler_attributes');
        $method->setAccessible(true);

        $antiXss = new AntiXSS();
        $antiXss->removeNeverAllowedOnEventsAfterwards(['onAbort']);

        $input = \str_repeat('<b onfoo=1>', 10001) . ' text onbar=1 <x ONABORT=1>';
        $output = $method->invoke($antiXss, $input);

        static::assertSame(\str_repeat('<b >', 10001) . ' text  <x ONABORT=1>', $output);

        // below the limit: the tokenizer keeps the text
        $input = \str_repeat('<b onfoo=1>', 100) . ' text onbar=1 <x ONABORT=1>';
        static::assertSame(\str_repeat('<b >', 100) . ' text onbar=1 <x ONABORT=1>', $method->invoke($antiXss, $input));
    }

    /**
     * "removeNeverAllowedOnEventsAfterwards()" allows an event handler (also for the structural filter); it can be
     * disallowed again with "addNeverAllowedOnEventsAfterwards()". Unknown names can not be allowed this way.
     *
     * @return void
     */
    public function testPublicApiCanStillAllowAnEventHandler()
    {
        $antiXss = new AntiXSS();
        $antiXss->removeNeverAllowedOnEventsAfterwards(['onAbort']);

        static::assertSame('<x onabort="alert&#40;1&#41;">', $antiXss->xss_clean('<x onabort="alert(1)">'));
        static::assertSame('<x ONABORT=1>', $antiXss->xss_clean('<x ONABORT=1>'));
        static::assertSame('<x  onabort=1>', $antiXss->xss_clean('<x onfutureevent=1 onabort=1>'));
        static::assertSame('<div onabort="x">y</div>', $antiXss->xss_clean('<div onabort="x">y</div>'));

        // other instances are not changed
        static::assertSame('<x >', (new AntiXSS())->xss_clean('<x onabort=1>'));

        // re-disallow
        $antiXss->addNeverAllowedOnEventsAfterwards(['onAbort']);
        static::assertSame('<x >', $antiXss->xss_clean('<x onabort=1>'));
        static::assertTrue($antiXss->isXssFound());

        // a name that is not on the list can not be removed from it, so it's not allowed
        $antiXss = new AntiXSS();
        $antiXss->removeNeverAllowedOnEventsAfterwards(['onFutureEvent']);
        static::assertSame('<x >', $antiXss->xss_clean('<x onfutureevent=1>'));
        static::assertTrue($antiXss->isXssFound());
    }

    /**
     * @return void
     */
    public function testReplacementIsUsed()
    {
        list($output, $found) = self::clean(
            '<div onfutureevent="1" class=keep>x</div>',
            static function (AntiXSS $antiXss) {
                $antiXss->setReplacement('[removed]');
            }
        );

        static::assertSame('<div [removed] class=keep>x</div>', $output);
        static::assertTrue($found);
    }

    /**
     * Inputs that exceed the runtime budget of the tokenizer (or have more than 10000 event handlers) use the
     * conservative fallback: still no event handler survives, in linear time.
     *
     * @return void
     */
    public function testRuntimeBudgetFallsBackToRemovingAllEventHandlers()
    {
        $inputs = [
            // every "<b" starts a tag inside the same unquoted value -> exceeds the scan budget
            '<a x=' . \str_repeat('<b/y=', 40000) . ' onfoo=1>',
            // more than 10000 event handlers
            '<a ' . \str_repeat('onfoo=1 ', 12000) . '>',
            \str_repeat('<a onfoo="', 20000),
        ];

        foreach ($inputs as $input) {
            list($output, $found, $duration) = self::clean($input);

            self::assertNotContainsIgnoringCase('onfoo=', $output, \substr($input, 0, 50));
            static::assertTrue($found);
            static::assertLessThan(5.0, $duration);
        }

        // more than 10000 event handlers in separate tags
        //
        // INFO: the runtime of this filter is checked (the other filters need most of the time for 12000 tags, also
        //       without this filter, e.g. > 5 seconds on PHP 7.1 with Xdebug code coverage)
        $method = new \ReflectionMethod(AntiXSS::class, '_remove_event_handler_attributes');
        $method->setAccessible(true);
        $start = \microtime(true);
        $output = $method->invoke(new AntiXSS(), \str_repeat('<b onfoo=1>', 12000));
        static::assertLessThan(5.0, \microtime(true) - $start);
        static::assertSame(\str_repeat('<b >', 12000), $output);
        list($output, $found) = self::clean(\str_repeat('<b onfoo=1>', 12000));
        self::assertNotContainsIgnoringCase('onfoo=', $output);
        static::assertTrue($found);

        // the fallback keeps allowed event handlers, too
        list($output) = self::clean(
            '<x ' . \str_repeat('onfoo=1 ', 12000) . 'onabort=1>',
            static function (AntiXSS $antiXss) {
                $antiXss->removeNeverAllowedOnEventsAfterwards(['onAbort']);
            }
        );
        self::assertNotContainsIgnoringCase('onfoo=', $output);
        self::assertContainsCaseSensitive('onabort=1>', $output);
    }

    /**
     * Both sides of the limits (10000 found attributes, scan budget) remove every event handler, and the memory
     * usage stays linear (the found attributes are capped, the "visited" bitmap has 1 byte per input byte).
     *
     * @return void
     */
    public function testLimitsDoNotWeakenTheFilterAndMemoryStaysBounded()
    {
        $method = new \ReflectionMethod(AntiXSS::class, '_remove_event_handler_attributes');
        $method->setAccessible(true);
        $antiXss = new AntiXSS();

        foreach ([9999, 10000, 10001, 10002] as $count) {
            $output = $method->invoke($antiXss, \str_repeat('<b onfoo=1>', $count) . 'x');
            static::assertSame(\str_repeat('<b >', $count) . 'x', $output, (string) $count);
        }

        // scan budget: "8 * length + 4096" bytes; below and above it
        foreach ([100, 400, 2000, 20000] as $count) {
            $output = $method->invoke($antiXss, '<a x=' . \str_repeat('<b/y=', $count) . ' onfoo=1>');
            self::assertNotContainsIgnoringCase('onfoo', $output, (string) $count);
        }

        // ~1 MB with 100000 event handlers: the found attributes are capped at 10000, so the peak memory is a few MB
        //
        // INFO: without "memory_reset_peak_usage()" (PHP < 8.2), the peak can be from an earlier test, so it's only
        //       measured with PHP >= 8.2
        $input = \str_repeat('<b onfoo=1>', 100000);
        $measurePeak = \function_exists('memory_reset_peak_usage');
        if ($measurePeak) {
            \memory_reset_peak_usage();
        }
        $before = \memory_get_usage();
        $output = $method->invoke($antiXss, $input);
        $peak = \memory_get_peak_usage() - $before;

        static::assertSame(\str_repeat('<b >', 100000), $output);
        if ($measurePeak) {
            static::assertLessThan(16 * 1024 * 1024, $peak);
        }
    }

    /**
     * The fallback is fail-closed: if PCRE fails, the terminal fallback "_failClosedNeutralize()" removes all markup.
     *
     * @return void
     */
    public function testFallbackIsFailClosedIfPcreFails()
    {
        $method = new \ReflectionMethod(AntiXSS::class, '_remove_event_handler_attributes_fail_closed');
        $method->setAccessible(true);

        $antiXss = new AntiXSS();
        $input = '<div class=keep onfoo="1" data-x=1>online</div>';

        static::assertSame('<div class=keep  data-x=1>online</div>', $method->invoke($antiXss, $input));

        $backtrackLimit = \ini_get('pcre.backtrack_limit');
        $jit = \ini_get('pcre.jit');
        \ini_set('pcre.jit', '0');
        \ini_set('pcre.backtrack_limit', '1');

        try {
            $output = $method->invoke($antiXss, $input);
        } finally {
            \ini_set('pcre.backtrack_limit', (string) $backtrackLimit);
            \ini_set('pcre.jit', (string) $jit);
        }

        // INFO: with the JIT, this pattern (already compiled in this process) may not fail; both results are safe
        if ($output !== '<div class=keep  data-x=1>online</div>') {
            static::assertSame('&lt;div class=keep onfoo=&quot;1&quot; data-x=1&gt;online&lt;/div&gt;', $output);
            static::assertTrue($antiXss->isXssFound());
        }
    }

    /**
     * The structural filter must not fail open if PCRE fails: a failed quick check ("false", not "0") runs the
     * scan, which does not use PCRE.
     *
     * @return void
     */
    public function testStructuralFilterIsFailClosedIfPcreFails()
    {
        $method = new \ReflectionMethod(AntiXSS::class, '_remove_event_handler_attributes');
        $method->setAccessible(true);
        $antiXss = new AntiXSS();

        $cases = [
            '<div onfoo="alert(1)" class=keep>x</div>' => '<div  class=keep>x</div>',
            '<a ongesturechange=location=name>x</a>'   => '<a >x</a>',
            '<p title="onreading mode">Read</p>'       => '<p title="onreading mode">Read</p>',
        ];

        $backtrackLimit = \ini_get('pcre.backtrack_limit');
        $jit = \ini_get('pcre.jit');
        \ini_set('pcre.jit', '0');
        \ini_set('pcre.backtrack_limit', '1');

        try {
            // INFO: make sure that PCRE really fails in this test
            $pcreFails = \preg_match('#[\t\n\f\r /"\']on[a-z]++[\t\n\f\r ]*+=#i', '<div onfoo="alert(1)">') === false;

            $outputs = [];
            foreach ($cases as $input => $expected) {
                $outputs[$input] = $method->invoke($antiXss, $input);
            }

            // the fallback (budget exceeded) with failing PCRE
            $fallback = $method->invoke($antiXss, '<a x=' . \str_repeat('<b/y=', 2000) . ' onfoo=1>');
        } finally {
            \ini_set('pcre.backtrack_limit', (string) $backtrackLimit);
            \ini_set('pcre.jit', (string) $jit);
        }

        static::assertTrue($pcreFails);
        foreach ($cases as $input => $expected) {
            static::assertSame($expected, $outputs[$input], $input);
        }
        // the fallback removes the event handler, or (if PCRE fails there, too) all markup
        self::assertNoEventHandlerAttributeLeft($fallback);
    }

    /**
     * Every event handler name that a spec or a browser engine knows (see the header of the fixture file for the
     * sources and "build/event-handlers/extract.py" to update it) must be removed, also without the list.
     *
     * @return void
     */
    public function testKnownBrowserEventHandlersAreRemovedWithoutTheList()
    {
        $names = [];
        foreach (\file(__DIR__ . '/fixtures/browser-event-handlers.txt', \FILE_IGNORE_NEW_LINES | \FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            if ($line[0] !== '#') {
                $names[] = \explode(' ', $line, 2)[0];
            }
        }
        static::assertGreaterThan(500, \count($names));

        // INFO: an empty list (without allowing the names via "removeNeverAllowedOnEventsAfterwards()"), so that
        //       only the structural filter can remove the event handlers
        $antiXss = new AntiXSS();
        $property = new \ReflectionProperty(AntiXSS::class, '_never_allowed_on_events_afterwards');
        $property->setAccessible(true);
        $property->setValue($antiXss, []);
        foreach (['_resetNeverAllowedOnEventsAfterwardsCache', '_rebuildEvilAttributesQuickChecksCache'] as $methodName) {
            $method = new \ReflectionMethod(AntiXSS::class, $methodName);
            $method->setAccessible(true);
            $method->invoke($antiXss);
        }

        $survived = [];
        foreach ($names as $name) {
            foreach (['<div class="keep" %s="location=name">x</div>', '<svg><rect class="keep" %s=alert(1) /></svg>'] as $template) {
                $output = $antiXss->xss_clean(\sprintf($template, $name));
                if (\stripos($output, $name) !== false || \strpos($output, 'class="keep"') === false || $antiXss->isXssFound() !== true) {
                    $survived[] = \sprintf($template, $name) . ' => ' . $output;
                }
            }
        }

        static::assertSame([], $survived);
    }
}
