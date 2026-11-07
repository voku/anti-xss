<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use voku\helper\AntiXSS;

/**
 * Regression coverage for new browser element and event-handler names.
 *
 * @internal
 */
final class ModernEventHandlerSecurityTest extends TestCase
{
    public function testGeolocationHandlerIsNeutralized(): void
    {
        $input = '<geolocation onvalidationstatuschange="alert(1)">x</geolocation>';
        $sanitized = (new AntiXSS())->xss_clean($input);

        self::assertSame(false, \stripos($sanitized, '<geolocation'));
        self::assertSame(false, \stripos($sanitized, 'onvalidationstatuschange='));
        self::assertNotSame($input, $sanitized);
    }

    public function testGeolocationTagIsBlockedWithoutEventHandler(): void
    {
        $sanitized = (new AntiXSS())->xss_clean('<GEOLOCATION>test</GEOLOCATION>');

        self::assertSame(false, \stripos($sanitized, '<geolocation'));
    }

    public function testUnknownEventHandlersAreStrippedFromOtherTags(): void
    {
        $inputs = [
            '<div onfutureevent="run()" title="ok">x</div>',
            "<div OnFutureEvent='run()' title='ok'>x</div>",
            '<div onfutureevent=run title="ok">x</div>',
            "<div\nONFUTUREEVENT = 'run()' title='ok'>x</div>",
        ];

        foreach ($inputs as $input) {
            $sanitized = (new AntiXSS())->xss_clean($input);

            self::assertSame(false, \stripos($sanitized, 'onfutureevent='));
            self::assertSame(false, \stripos($sanitized, 'onfutureevent ='));
        }
    }

    public function testSafeAttributeNamesAndPlainTextSurvive(): void
    {
        $input = '<div data-onfutureevent="safe" title="ok">someone is onboarding</div>';

        self::assertSame($input, (new AntiXSS())->xss_clean($input));
        self::assertSame(
            'The onboarding documentation mentions onfutureevent="text".',
            (new AntiXSS())->xss_clean('The onboarding documentation mentions onfutureevent="text".')
        );
    }
}
