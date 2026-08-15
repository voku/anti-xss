<?php

use voku\helper\AntiXSS;

/**
 * Regression coverage derived from attack classes documented by
 * swisskyrepo/PayloadsAllTheThings/XSS Injection.
 *
 * @internal
 */
final class PayloadsAllTheThingsTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @group payloads-all-the-things
     */
    public function testRepresentativePayloadsAreNeutralized()
    {
        foreach ($this->payloads() as $name => $payload) {
            $cleaned = (new AntiXSS())->xss_clean($payload);

            static::assertTrue(\is_string($cleaned), $name . ': sanitizer must return a string');

            $decoded = \html_entity_decode($cleaned, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $compact = (string) \preg_replace('/[\x00-\x20\x7F]+/', '', $decoded);

            static::assertSame(
                0,
                \preg_match('/<\s*script\b/i', $decoded),
                $name . ': executable script tag survived: ' . $cleaned
            );
            static::assertSame(
                0,
                \preg_match('/<[^>]+(?:\s|\/)on[a-z0-9_-]*\s*=/i', $decoded),
                $name . ': executable event handler survived: ' . $cleaned
            );
            static::assertFalse(
                \stripos($compact, 'javascript:') !== false,
                $name . ': javascript URI survived: ' . $cleaned
            );
            static::assertFalse(
                \stripos($compact, 'vbscript:') !== false,
                $name . ': vbscript URI survived: ' . $cleaned
            );
            static::assertFalse(
                \stripos($compact, 'data:text/html') !== false,
                $name . ': executable HTML data URI survived: ' . $cleaned
            );
        }
    }

    /**
     * @return array<string, string>
     */
    private function payloads()
    {
        return [
            'script-tag' => '<script>alert(1)</script>',
            'nested-script-tag' => '<scr<script>ipt>alert(1)</scr<script>ipt>',
            'image-error-handler' => '<img src=x onerror=alert(1)>',
            'svg-load-handler' => '<svg/onload=alert(1)>',
            'focus-handler' => '<input autofocus onfocus=alert(1)>',
            'toggle-handler' => '<details open ontoggle=alert(1)>',
            'content-visibility-handler' => '<input type="hidden" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">',
            'touch-handler' => '<body ontouchstart=alert(1)>',
            'javascript-uri' => '<a href="javascript:alert(1)">x</a>',
            'entity-javascript-uri' => '<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)">x</a>',
            'newline-javascript-uri' => '<a href="java&#10;script:alert(1)">x</a>',
            'data-html-uri' => '<a href="data:text/html,<svg onload=alert(1)>">x</a>',
            'xlink-javascript-uri' => '<svg><a xlink:href="javascript:alert(1)">x</a></svg>',
            'object-data-uri' => '<object data="javascript:alert(1)"></object>',
            'formaction-uri' => '<button formaction="javascript:alert(1)">x</button>',
        ];
    }
}
