<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use voku\helper\AntiXSS;

/**
 * Regression coverage for browser event attributes introduced after the denylist was written.
 *
 * @internal
 */
final class UnknownEventAttributeTest extends TestCase
{
    public function testUnknownEventAttributeIsRemovedFromHtml(): void
    {
        $sanitizer = new AntiXSS();
        $input = '<geolocation class="safe" onvalidationstatuschange="alert(1)">x</geolocation>';

        $actual = $sanitizer->xss_clean($input);

        self::assertSame(false, \strpos(\strtolower($actual), 'onvalidationstatuschange='));
        self::assertNotSame(false, \strpos($actual, 'class="safe"'));
        self::assertTrue($sanitizer->isXssFound());
    }

    public function testFutureEventAttributeIsRemovedWithoutRemovingDataAttribute(): void
    {
        $sanitizer = new AntiXSS();
        $input = '<div data-onfuturechange="allowed" onfuturechange="alert(1)">hello</div>';

        $actual = $sanitizer->xss_clean($input);

        self::assertNotSame(false, \strpos($actual, 'data-onfuturechange="allowed"'));
        self::assertSame(false, \strpos(\strtolower($actual), ' onfuturechange='));
        self::assertTrue($sanitizer->isXssFound());
    }

    public function testUnknownUnquotedEventAttributeIsRemoved(): void
    {
        $sanitizer = new AntiXSS();
        $actual = $sanitizer->xss_clean('<div onfuturechange=alert(1)>hello</div>');

        self::assertSame(false, \strpos(\strtolower($actual), 'onfuturechange='));
        self::assertTrue($sanitizer->isXssFound());
    }

    public function testPlainTextMentionOfUnknownEventAttributeIsPreserved(): void
    {
        $input = 'Documentation: onvalidationstatuschange="example"';

        self::assertSame($input, (new AntiXSS())->xss_clean($input));
    }
}
