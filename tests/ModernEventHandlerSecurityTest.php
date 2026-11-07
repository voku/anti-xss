<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use voku\helper\AntiXSS;

/**
 * Regression coverage for a newly executable browser element.
 *
 * @internal
 */
final class ModernEventHandlerSecurityTest extends TestCase
{
    public function testGeolocationElementWithUnknownEventIsEncoded(): void
    {
        $payloads = [
            '<geolocation onvalidationstatuschange="alert(1)">x</geolocation>',
            "<GEOLOCATION ONVALIDATIONSTATUSCHANGE='alert(1)'>x</GEOLOCATION>",
            '<geolocation onvalidationstatuschange=alert(1)>x</geolocation>',
        ];

        foreach ($payloads as $payload) {
            $sanitized = (new AntiXSS())->xss_clean($payload);

            self::assertSame(false, \stripos($sanitized, '<geolocation'), $payload);
            self::assertSame(false, \stripos($sanitized, '</geolocation'), $payload);
            self::assertNotSame($payload, $sanitized);
        }
    }

    public function testGeolocationElementWithoutHandlerIsEncoded(): void
    {
        $sanitized = (new AntiXSS())->xss_clean('<geolocation>test</geolocation>');

        self::assertSame(false, \stripos($sanitized, '<geolocation'));
        self::assertSame(false, \stripos($sanitized, '</geolocation'));
    }

    public function testSafeProseAndOtherAttributeNamesStayUnchanged(): void
    {
        $input = '<div data-onfutureevent="safe" title="ok">someone is onboarding</div>';

        self::assertSame($input, (new AntiXSS())->xss_clean($input));
        self::assertSame(
            'The geolocation.com website is not an HTML tag.',
            (new AntiXSS())->xss_clean('The geolocation.com website is not an HTML tag.')
        );
    }
}
