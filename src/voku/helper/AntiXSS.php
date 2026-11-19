<?php

declare(strict_types=1);

namespace voku\helper;

use const ENT_DISALLOWED;
use const ENT_HTML5;
use const ENT_QUOTES;
use const ENT_SUBSTITUTE;
use const HTML_ENTITIES;

/**
 * AntiXSS - ported from "CodeIgniter"
 *
 * ## 🇷🇺 Русским гражданам
 * В Украине сейчас идет война. Силами РФ наносятся удары по гражданской инфраструктуре в [Харькове][1], [Киеве][2], [Чернигове][3], [Сумах][4], [Ирпене][5] и десятках других городов. Гибнут люди - и гражданское население, и военные, в том числе российские призывники, которых бросили воевать. Чтобы лишить собственный народ доступа к информации, правительство РФ запретило называть войну войной, закрыло независимые СМИ и принимает сейчас ряд диктаторских законов. Эти законы призваны заткнуть рот всем, кто против войны. За обычный призыв к миру сейчас можно получить несколько лет тюрьмы.
 * Не молчите! Молчание - знак вашего согласия с политикой российского правительства.
 *  **Вы можете сделать выбор НЕ МОЛЧАТЬ.**
 * ---
 * ## 🇺🇸 To people of Russia
 * There is a war in Ukraine right now. The forces of the Russian Federation are attacking civilian infrastructure in [Kharkiv][1], [Kyiv][2], [Chernihiv][3], [Sumy][4], [Irpin][5] and dozens of other cities. People are dying – both civilians and military servicemen, including Russian conscripts who were thrown into the fighting. In order to deprive its own people of access to information, the government of the Russian Federation has forbidden calling a war a war, shut down independent media and is passing a number of dictatorial laws. These laws are meant to silence all those who are against war. You can be jailed for multiple years for simply calling for peace.
 * Do not be silent! Silence is a sign that you accept the Russian government's policy.
 * **You can choose NOT TO BE SILENT.**
 * ---
 * - [1] https://cloudfront-us-east-2.images.arcpublishing.com/reuters/P7K2MSZDGFMIJPDD7CI2GIROJI.jpg "Kharkiv under attack"
 * - [2] https://gdb.voanews.com/01bd0000-0aff-0242-fad0-08d9fc92c5b3_cx0_cy5_cw0_w1023_r1_s.jpg "Kyiv under attack"
 * - [3] https://ichef.bbci.co.uk/news/976/cpsprodpb/163DD/production/_123510119_hi074310744.jpg "Chernihiv under attack"
 * - [4] https://www.youtube.com/watch?v=8K-bkqKKf2A "Sumy under attack"
 * - [5] https://cloudfront-us-east-2.images.arcpublishing.com/reuters/K4MTMLEHTRKGFK3GSKAT4GR3NE.jpg "Irpin under attack"
 *
 * @copyright   Copyright (c) 2008 - 2014, EllisLab, Inc. (http://ellislab.com/)
 * @copyright   Copyright (c) 2014 - 2015, British Columbia Institute of Technology (http://bcit.ca/)
 * @copyright   Copyright (c) 2015 - 2020, Lars Moelleken (https://moelleken.org/)
 * @license     http://opensource.org/licenses/MIT	MIT License
 */
final class AntiXSS
{
    private const MAX_SANITIZATION_PASSES = 100;

    /**
     * Max. depth of nested "xss_clean()"-calls (via a clone) for attribute values.
     *
     * INFO: without a limit the runtime is exponential in the nesting depth of crafted input
     */
    private const MAX_NESTED_CLEAN_DEPTH = 2;

    const VOKU_ANTI_XSS_GT = 'voku::anti-xss::gt';

    /**
     * All printable ASCII chars ("!" - "~").
     *
     * @var string
     */
    const PRINTABLE_ASCII_CHARS = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~';

    const VOKU_ANTI_XSS_LT = 'voku::anti-xss::lt';

    /**
     * @deprecated will be removed in future versions
     */
    const VOKU_ANTI_XSS_STYLE = 'voku::anti-xss::STYLE';

    /**
     * List of never allowed regex replacements.
     *
     * @var string[]
     */
    private $_never_allowed_regex = [];

    /**
     * List of html tags that will not close automatically.
     *
     * @var string[]
     */
    private $_do_not_close_html_tags = [];

    /**
     * List of never allowed call statements.
     *
     * @var string[]
     */
    private $_never_allowed_js_callback_regex = [
        '\(?window\)?\.',
        '\(?history\)?\.',
        '\(?location\)?\.',
        '\(?document\)?\.',
        '\(?cookie\)?\.',
        '\(?ScriptElement\)?\.',
        'd\s*a\s*t\s*a\s*:',
    ];
    
    /**
     * List of simple never allowed call statements.
     *
     * @var string[]
     */
    private $_never_allowed_call_strings = [
        // default javascript
        'javascript',
        // Java: jar-protocol is an XSS hazard
        'jar',
        // Mac (will not run the script, but open it in AppleScript Editor)
        'applescript',
        // IE: https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet#VBscript_in_an_image
        'vbscript',
        'vbs',
        // IE, surprise!
        'wscript',
        // IE
        'jscript',
        // https://html5sec.org/#behavior
        'behavior',
        // old Netscape
        'mocha',
        // old Netscape
        'livescript',
        // default view source
        'view-source',
    ];

    /**
     * @var string[]
     */
    private $_never_allowed_str_afterwards = [
        '&lt;script&gt;',
        '&lt;/script&gt;',
    ];

    /**
     * List of never allowed strings, afterwards.
     *
     * @var string[]
     */
    private $_never_allowed_on_events_afterwards = [
        'onAbort',
        'onActivate',
        'onAddTrack',
        'onAttribute',
        'onAfterPrint',
        'onAfterScriptExecute',
        'onAfterUpdate',
        'onAnimationCancel',
        'onAnimationEnd',
        'onAnimationIteration',
        'onAnimationStart',
        'onAppInstalled',
        'onAriaRequest',
        'onAutoComplete',
        'onAutoCompleteError',
        'onAutoFill',
        'onAuxClick',
        'onBeforeActivate',
        'onBeforeCopy',
        'onBeforeCut',
        'onBeforeInput',
        'onBeforeInstallPrompt',
        'onBeforeMatch',
        'onBeforePrint',
        'onBeforeDeactivate',
        'onBeforeEditFocus',
        'onBeforeFilter',
        'onBeforePaste',
        'onBeforePrint',
        'onBeforeScriptExecute',
        'onBeforeToggle',
        'onBeforeUnload',
        'onBeforeUpdate',
        'onBeforeXRSelect',
        'onBegin',
        'onBlocked',
        'onBlur',
        'onBounce',
        'onCancel',
        'onCanPlay',
        'onCanPlayThrough',
        'onCellChange',
        'onChange',
        'onClick',
        'onClose',
        'onCommand',
        'onCompassNeedsCalibration',
        'onComplete',
        'onConnect',
        'onContentVisibilityAutoStateChange',
        'onContextLost',
        'onContextRestored',
        'onContextMenu',
        'onControlSelect',
        'onCopy',
        'onCueChange',
        'onCurrentEntryChange',
        'onCut',
        'onDataAvailable',
        'onDataSetChanged',
        'onDataSetComplete',
        'onDblClick',
        'onDeactivate',
        'onDeviceChange',
        'onDeviceLight',
        'onDeviceMotion',
        'onDeviceOrientation',
        'onDeviceOrientationAbsolute',
        'onDeviceProximity',
        'onDispose',
        'onDrag',
        'onDragDrop',
        'onDragEnd',
        'onDragExit',
        'onDragEnter',
        'onDragLeave',
        'onDragOver',
        'onDragStart',
        'onDrop',
        'onDurationChange',
        'onEmptied',
        'onEnd',
        'onEnded',
        'onEnter',
        'onEnterPictureInPicture',
        'onError',
        'onErrorUpdate',
        'onExit',
        'onFilterChange',
        'onFinish',
        'onFocus',
        'onFocusIn',
        'onFocusOut',
        'onFormChange',
        'onFormData',
        'onFormInput',
        'onFullScreenChange',
        'onFullScreenError',
        'onGamepadConnected',
        'onGamepadDisconnected',
        'onGotPointerCapture',
        'onHashChange',
        'onHelp',
        'onInput',
        'onInstallResult',
        'onInvalid',
        'onKeyDown',
        'onKeyPress',
        'onKeyUp',
        'onLanguageChange',
        'onLayoutComplete',
        'onLeavePictureInPicture',
        'onLoad',
        'onLoadEnd',
        'onLoadedData',
        'onLoadedMetaData',
        'onLoadStart',
        'onLocation',
        'onLoseCapture',
        'onLostPointerCapture',
        'onMediaComplete',
        'onMediaError',
        'onMessage',
        'onMessageError',
        'onMouseDown',
        'onMouseEnter',
        'onMouseLeave',
        'onMouseMove',
        'onMouseOut',
        'onMouseOver',
        'onMouseUp',
        'onMouseWheel',
        'onMove',
        'onMoveEnd',
        'onMoveStart',
        'onNavigate',
        'onNavigateError',
        'onNavigateSuccess',
        'onMozFullScreenChange',
        'onMozFullScreenError',
        'onMozPointerLockChange',
        'onMozPointerLockError',
        'onMsContentZoom',
        'onMsFullScreenChange',
        'onMsFullScreenError',
        'onMsGestureChange',
        'onMsGestureDoubleTap',
        'onMsGestureEnd',
        'onMsGestureHold',
        'onMsGestureStart',
        'onMsGestureTap',
        'onMsGotPointerCapture',
        'onMsInertiaStart',
        'onMsLostPointerCapture',
        'onMsManipulationStateChanged',
        'onMsPointerCancel',
        'onMsPointerDown',
        'onMsPointerEnter',
        'onMsPointerLeave',
        'onMsPointerMove',
        'onMsPointerOut',
        'onMsPointerOver',
        'onMsPointerUp',
        'onMsSiteModeJumpListItemRemoved',
        'onMsThumbnailClick',
        'onOffline',
        'onOnline',
        'onOpen',
        'onOpenerChange',
        'onOrientationChange',
        'onOutOfSync',
        'onOverScrollCancel',
        'onOverScrollChanging',
        'onOverScrollEnd',
        'onOverScrollStart',
        'onPage',
        'onPageHide',
        'onPageReveal',
        'onPageShow',
        'onPageSwap',
        'onPaste',
        'onPayerDetailChange',
        'onPaymentMethodChange',
        'onPause',
        'onPlay',
        'onPlaying',
        'onPointerCancel',
        'onPointerDown',
        'onPointerEnter',
        'onPointerLeave',
        'onPointerLockChange',
        'onPointerLockError',
        'onPointerMove',
        'onPointerOut',
        'onPointerOver',
        'onPointerRawUpdate',
        'onPointerUp',
        'onPopState',
        'onProgress',
        'onPromptAction',
        'onPromptDismiss',
        'onPropertyChange',
        'onqt_error',
        'onRateChange',
        'onReadyStateChange',
        'onReceived',
        'onRejectionHandled',
        'onRemoveTrack',
        'onRepeat',
        'onReset',
        'onResize',
        'onResizeEnd',
        'onResizeStart',
        'onResume',
        'onReverse',
        'onRowDelete',
        'onRowEnter',
        'onRowExit',
        'onRowInserted',
        'onRowsDelete',
        'onRowsEnter',
        'onRowsExit',
        'onRowsInserted',
        'onScroll',
        'onScrollEnd',
        'onScrollSnapChange',
        'onScrollSnapChanging',
        'onSearch',
        'onSeek',
        'onSeeked',
        'onSeeking',
        'onShippingAddressChange',
        'onShippingOptionChange',
        'onSecurityPolicyViolation',
        'onSelect',
        'onSelectionChange',
        'onSelectStart',
        'onSlotChange',
        'onStalled',
        'onStorage',
        'onStorageCommit',
        'onStream',
        'onStart',
        'onStop',
        'onShow',
        'onSyncRestored',
        'onSubmit',
        'onSuccess',
        'onSuspend',
        'onSynchRestored',
        'onTimeError',
        'onTimeUpdate',
        'onTimeZoneChange',
        'onTimer',
        'onTrack',
        'onTrackChange',
        'onTransitionEnd',
        'onTransitionRun',
        'onTransitionStart',
        'onToggle',
        'onTouchCancel',
        'onTouchEnd',
        'onTouchLeave',
        'onTouchMove',
        'onTouchStart',
        'onTransitionCancel',
        'onTransitionEnd',
        'onUnload',
        'onUnhandledRejection',
        'onUpgradeNeeded',
        'onURLFlip',
        'onUserProximity',
        'onValidationStatusChange',
        'onVersionChange',
        'onVisibilityChange',
        'onVRDisplayActivate',
        'onVRDisplayConnect',
        'onVRDisplayDeactivate',
        'onVRDisplayDisconnect',
        'onVRDisplayPresentChange',
        'onVolumeChange',
        'onWaiting',
        'onWebKitAnimationEnd',
        'onWebKitAnimationIteration',
        'onWebKitAnimationStart',
        'onWebKitFullScreenChange',
        'onWebKitFullScreenError',
        'onWebKitTransitionEnd',
        'onWheel',
    ];

    /**
     * https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet#Event_Handlers
     *
     * @var string[]
     */
    private $_evil_attributes_regex = [
        'style',
        // declarative shadow DOM: "<template shadowrootmode=open>" can hide the rest of the page
        'shadowrootmode',
        'shadowroot',
        'xmlns:xdp',
        'formaction',
        'form',
        'xlink:href',
        'seekSegmentTime',
        'FSCommand',
    ];

    /**
     * @var string[]
     */
    private $_evil_html_tags = [
        'applet',
        'audio',
        'basefont',
        'base',
        'behavior',
        'bgsound',
        'blink',
        'body',
        'camera',
        'embed',
        'eval',
        'expression',
        'form',
        'frameset',
        'frame',
        'geolocation',
        'head',
        'html',
        'ilayer',
        'iframe',
        'input',
        'button',
        'select',
        'isindex',
        'layer',
        'link',
        'meta',
        'microphone',
        'keygen',
        'object',
        'permission',
        'plaintext',
        'portal',
        'style',
        'script',
        'textarea',
        'title',
        'math',
        'noscript',
        'event-source',
        'vmlframe',
        'video',
        'source',
        'svg',
        'xml',
    ];

    /**
     * JavaScript-specific keywords that are essentially never used in natural-language prose before a
     * parenthesis. These are matched even when whitespace appears between the keyword and "(" so that
     * patterns like "eval (variable)" are still caught.
     *
     * @var string[]
     */
    private $_naughty_javascript_patterns = [
        'eval',
        'execScript',
        'setTimeout',
        'setInterval',
        'setImmediate',
        'cmd',
        'passthru',
        'exec',
        'fopen',
        'fsockopen',
        'file_get_contents',
        'readfile',
        'unlink',
    ];

    /**
     * Keywords that are also common English words, making them prone to false positives when whitespace
     * precedes the opening parenthesis (e.g. "operating system (Linux)"). These are only matched when
     * the keyword is followed immediately by "(" with no intervening whitespace.
     *
     * @var string[]
     */
    private $_naughty_javascript_patterns_strict = [
        'alert',
        'prompt',
        'confirm',
        'expression',
        'system',
        'file',
    ];

    /**
     * @var string
     */
    private $_spacing_regex = '(?:\s|"|\'|\+|&#x0[9A-F];|%0[9a-f])*?';

    /**
     * The replacement-string for not allowed strings.
     *
     * @var string
     */
    private $_replacement = '';

    /**
     * List of never allowed strings.
     *
     * @var string[]
     */
    private $_never_allowed_str = [];

    /**
     * If your DB (MySQL) encoding is "utf8" and not "utf8mb4", then
     * you can't save 4-Bytes chars from UTF-8 and someone can create stored XSS-attacks.
     *
     * @var bool
     */
    private $_stripe_4byte_chars = false;

    /**
     * @var bool|null
     */
    private $_xss_found;

    /**
     * @var bool
     */
    private $_keep_pre_and_code_tag_content = false;

    /**
     * Depth of nested "xss_clean()"-calls via a clone (0 === not nested).
     *
     * @var int
     */
    private $_nested_clean_depth = 0;

    /**
     * @var string
     */
    private $_cache_evil_attributes_regex_string = '';

    /**
     * @var string
     */
    private $_cache_never_allowed_regex_string = '';

    /**
     * Regexes that start with a start-of-pattern directive (e.g. "(*UCP)") and can not be combined.
     *
     * @var string[]
     */
    private $_cache_never_allowed_regex_standalone = [];

    /**
     * @var string
     */
    private $_cache__evil_html_tags_str = '';

    /**
     * @var array<string, array{chunk: string, split: string[], regex: string}>
     */
    private $_cache_compact_exploded_words = [];

    /**
     * @var array<string, list<string>>|null
     */
    private $_cache_never_allowed_on_events_afterwards_chunks;

    /**
     * @var array<string, string>
     */
    private $_cache_never_allowed_on_events_afterwards_regex = [];

    /**
     * @var array<string, string>
     */
    private $_cache_never_allowed_regex_replacements = [];

    /**
     * @var string[]
     */
    private $_cache_evil_attributes_quick_checks = [];

    /**
     * @var bool
     */
    private $_cache_can_short_circuit_evil_attributes = true;

    /**
     * Event handler attributes that were explicitly allowed via "removeNeverAllowedOnEventsAfterwards()"
     * (lowercase name => true), so that "_remove_event_handler_attributes()" keeps them, too.
     *
     * @var array<string, true>
     */
    private $_allowed_on_event_attributes = [];

    public function __construct()
    {
        $this->_initNeverAllowedStr();
        $this->_initNeverAllowedRegex();
        
        $this->_rebuildEvilAttributesQuickChecksCache();
    }

    /**
     * Compact any exploded words.
     *
     * <p>
     * <br />
     * INFO: This corrects words like:  j a v a s c r i p t
     * <br />
     * These words are compacted back to their correct state.
     * </p>
     *
     * @param string $str
     *
     * @return string
     */
    private function _compact_exploded_javascript($str)
    {
        $words = [
            'javascript',
            '<script',
            '</script>',
            'base64',
            'document',
            'eval',
        ];

        // check if we need to perform the regex-stuff
        if (\strlen($str) <= 30) {
            $useStrPos = true;
        } else {
            $useStrPos = false;
        }

        foreach ($words as $word) {
            if (!isset($this->_cache_compact_exploded_words[$word])) {
                $splitWord = \str_split($word);
                $chunkWord = \implode(
                    $this->_spacing_regex,
                    \array_map(
                        static function ($char) {
                            return \preg_quote($char, '~');
                        },
                        $splitWord
                    )
                );

                $this->_cache_compact_exploded_words[$word] = [
                    'chunk' => $chunkWord,
                    'split' => $splitWord,
                    // INFO: "(?<!%0)" -> never start a word on the last char of an url-encoded spacing-token
                    //       (e.g. the "d" in "%0d", the "e" in "%0e" or the "b" in "%0b"), otherwise a long run of
                    //       these tokens makes every single token a possible match start (quadratic runtime / ReDoS)
                    'regex' => '~(?<before>[^\p{L}]|^)(?<!%0)(?<word>' . $chunkWord . ')(?<after>[^\p{L}@.!?\' ]|$)~ius',
                ];
            }

            if ($useStrPos) {
                foreach ($this->_cache_compact_exploded_words[$word]['split'] as $charTmp) {
                    if (\stripos($str, $charTmp) === false) {
                        continue 2;
                    }
                }
            }

            // We only want to do this when it is followed by a non-word character.
            // And if there are no char at the start of the string.
            //
            // That way valid stuff like "dealer to!" does not become "dealerto".

            $tmp = \preg_replace_callback(
                $this->_cache_compact_exploded_words[$word]['regex'],
                [$this, '_compact_exploded_words_callback'],
                $str
            );
            $str = $tmp ?? $this->_failClosedNeutralize($str);
        }

        return $str;
    }

    /**
     * Compact exploded words.
     *
     * <p>
     * <br />
     * INFO: Callback method for xss_clean() to remove whitespace from things like 'j a v a s c r i p t'.
     * </p>
     *
     * @param string[] $matches
     *
     * @return  string
     */
    private function _compact_exploded_words_callback($matches)
    {
        return $matches['before'] . \preg_replace(
            '/' . $this->_spacing_regex . '/ius',
            '',
            $matches['word']
        ) . $matches['after'];
    }

    /**
     * HTML-Entity decode callback.
     *
     * @param string[] $match
     *
     * @return string
     */
    private function _decode_entity($match)
    {
        // init
        $str = $match[0];

        // protect GET variables without XSS in URLs
        $needProtection = true;
        if (
            \strpos($str, '=') !== false
            &&
            $this->_nested_clean_depth < self::MAX_NESTED_CLEAN_DEPTH
        ) {
            $strCopy = $str;
            $matchesTmp = [];
            while (\preg_match("/[?|&]?[\p{L}\d_\-\[\]]+\s*=\s*([\"'])(?<attr>[^\1]*?)\\1/u", $strCopy, $matches)) {
                $matchesTmp[] = $matches;
                $strCopy = \str_replace($matches[0], '', $strCopy);

                if (\substr_count($strCopy, '"') <= 1 && \substr_count($strCopy, '\'') <= 1) {
                    break;
                }
            }

            if ($strCopy !== $str) {
                $needProtection = false;
                foreach ($matchesTmp as $matches) {
                    if ($matches['attr'] !== '') {
                        $tmpAntiXss = $this->_clone_for_nested_clean();

                        $urlPartClean = $tmpAntiXss->xss_clean((string) $matches['attr']);

                        if ($tmpAntiXss->isXssFound() === true) {
                            $this->_xss_found = true;

                            $urlPartClean = \str_replace(['&lt;', '&gt;'], [self::VOKU_ANTI_XSS_LT, self::VOKU_ANTI_XSS_GT], $urlPartClean);
                            $urlPartClean = $this->_rawurldecode($urlPartClean);
                            $urlPartClean = \str_replace([self::VOKU_ANTI_XSS_LT, self::VOKU_ANTI_XSS_GT], ['&lt;', '&gt;'], $urlPartClean);

                            $str = \str_ireplace($matches['attr'], $urlPartClean, $str);
                        }
                    }
                }
            }
        }

        if ($needProtection) {
            $str = \str_replace(['&lt;', '&gt;'], [self::VOKU_ANTI_XSS_LT, self::VOKU_ANTI_XSS_GT], $str);
            $str = $this->_entity_decode($this->_rawurldecode($str));
            $str = \str_replace([self::VOKU_ANTI_XSS_LT, self::VOKU_ANTI_XSS_GT], ['&lt;', '&gt;'], $str);
        }

        return $str;
    }

    /**
     * Clone this instance for a nested "xss_clean()"-call (e.g. for an attribute value).
     *
     * @return self
     */
    private function _clone_for_nested_clean()
    {
        $tmpAntiXss = clone $this;
        ++$tmpAntiXss->_nested_clean_depth;

        return $tmpAntiXss;
    }

    /**
     * Decode the html-tags but keep links without XSS.
     *
     * @param string $str
     *
     * @return string
     */
    private function _decode_string($str)
    {
        if (\strpos($str, '<') !== false) {
            $result = '';
            $offset = 0;
            foreach ($this->_find_html_tags($str) as $tag) {
                $result .= \substr($str, $offset, $tag[0] - $offset);
                $result .= $this->_decode_entity([(string) \substr($str, $tag[0], $tag[1] - $tag[0])]);
                $offset = $tag[1];
            }

            if ($offset > 0) {
                return $result . \substr($str, $offset);
            }
        }

        return $this->_rawurldecode($str);
    }

    /**
     * Find html-tags ("<" + letter ... ">", where a ">" inside of quotes does not end the tag).
     *
     * <p>
     * <br />
     * INFO: This replaces the regex '/<\p{L}+(?:[^>"\']|(["\']).*\1)*>/usU', which was exponential on runs
     *       of quotes without a reachable ">" (ReDoS). This scan follows all ways the regex could match at
     *       once (a quote can be closed by any later quote of the same kind) and returns the first ">" that
     *       is reachable outside of quotes. States that a previous scan already visited are remembered in a
     *       bitmap (one byte per input byte), so that no part of the string is scanned twice in the same
     *       state: linear time and linear (1x) memory. The tags are yielded one by one, so that no list of
     *       all tags is built.
     * </p>
     *
     * @param string $str
     *
     * @return \Generator<int, array{0: int, 1: int}>
     *                                                  <p>[start, end) offsets of the tags</p>
     */
    private function _find_html_tags($str)
    {
        // no tag can end after the last ">"
        $lastGt = \strrpos($str, '>');
        if ($lastGt === false) {
            return;
        }

        $length = \strlen($str);

        // bitmap: bit "state" is set for an offset, if a scan already was at this offset in this state
        $visited = null;

        // cache for the first relevant char after a tag name (no '>', '"' or "'" in [$cacheFrom, $cacheTo))
        $cacheFrom = -1;
        $cacheTo = -1;

        $pos = 0;
        while (($start = \strpos($str, '<', $pos)) !== false && $start < $lastGt) {
            $pos = $start + 1;

            // INFO: only check the next char (max. 4 bytes) and not "$str" with an offset, because with "/u"
            //       PHP validates the whole subject on every call (quadratic runtime)
            //
            // INFO: "$pos" is always valid here, because "$start < $lastGt"
            $leadByte = \ord($str[$pos]);
            if ($leadByte < 0x80) {
                $charLength = 1;
                if (!(($leadByte >= 0x41 && $leadByte <= 0x5A) || ($leadByte >= 0x61 && $leadByte <= 0x7A))) {
                    continue;
                }
            } else {
                if ($leadByte < 0xE0) {
                    $charLength = 2;
                } elseif ($leadByte < 0xF0) {
                    $charLength = 3;
                } else {
                    $charLength = 4;
                }
                if (\preg_match('/^\p{L}$/u', (string) \substr($str, $pos, $charLength)) === 0) {
                    continue;
                }
            }

            $cursor = $pos + $charLength;
            if ($cursor < $cacheFrom || $cursor > $cacheTo) {
                $cacheFrom = $cursor;
                $cacheTo = $cursor + \strcspn($str, '>"\'', $cursor);
            }
            $next = $cacheTo;

            // state: is the next relevant char reachable outside of quotes + was a quote of this kind opened
            $reachable = true;
            $openDouble = false;
            $openSingle = false;

            $end = null;
            while ($next < $length) {
                if ($reachable && $openDouble && $openSingle) {
                    // INFO: from this state on, every quote keeps the state "reachable" (both kinds of quotes
                    //       are open, so every quote can close one), so the tag ends at the next ">"
                    $gt = \strpos($str, '>', $next);
                    $end = $gt === false ? null : $gt + 1;

                    break;
                }

                $stateBit = 1 << (($reachable ? 4 : 0) | ($openDouble ? 2 : 0) | ($openSingle ? 1 : 0));
                if ($visited === null) {
                    $visited = \str_repeat("\0", $length);
                } elseif ((\ord($visited[$next]) & $stateBit) !== 0) {
                    // INFO: a previous scan was here in the same state and did not find the end of a tag
                    //       (a successful scan only visits offsets in front of the next start)
                    break;
                }
                $visited[$next] = \chr(\ord($visited[$next]) | $stateBit);

                $char = $str[$next];
                if ($char === '>') {
                    if ($reachable) {
                        $end = $next + 1;

                        break;
                    }
                } elseif ($char === '"') {
                    // quote: it can close any already opened quote of this kind (".*\1" can be extended to any
                    //        later quote), and it opens a new quote if it's reachable outside of quotes
                    $nextReachable = $openDouble;
                    $openDouble = $openDouble || $reachable;
                    $reachable = $nextReachable;
                } else {
                    $nextReachable = $openSingle;
                    $openSingle = $openSingle || $reachable;
                    $reachable = $nextReachable;
                }

                $next += 1 + \strcspn($str, '>"\'', $next + 1);
            }

            if ($end === null) {
                continue;
            }

            yield [$start, $end];

            $pos = $end;
        }
    }

    /**
     * @param string $str
     *
     * @return string
     */
    private function _do($str)
    {
        $str = (string) $str;
        if (
            !$str
            ||
            (\is_numeric($str) && ((string) (int) $str === $str || (string) (float) $str === $str))
        ) {
            // no xss found
            if ($this->_xss_found !== true) {
                $this->_xss_found = false;
            }

            return $str;
        }

        // remove the BOM from UTF-8 / UTF-16 / UTF-32 strings
        $str = UTF8::remove_bom($str);

        // replace the diamond question mark (�) and invalid-UTF8 chars
        $str = UTF8::replace_diamond_question_mark($str, '');

        // terminate numeric character references without ";" (e.g. "&#x3a" or "&#58"), before the next steps
        // remove or decode the chars after it, otherwise e.g. "&#x3a%0bfetch(1)" would become "&#x3afetch(1)"
        // here (U+3AFE), but "javascript:%0bfetch(1)" in the browser
        if (\strpos($str, '&#') !== false) {
            $tmp = \preg_replace('/&#(?:[xX][0-9a-fA-F]++|[0-9]++)(?!;)/', '$0;', $str);
            $str = $tmp ?? $this->_failClosedNeutralize($str);
        }

        // remove invisible characters (also url-encoded ones like "%00")
        $str = $this->_remove_invisible_characters($str);

        // decode UTF-7 characters
        $str = $this->_repack_utf7($str);

        // decode the string
        $str = $this->_decode_string($str);

        // remove all >= 4-Byte chars if needed
        if ($this->_stripe_4byte_chars) {
            $tmp = \preg_replace('/[\x{10000}-\x{10FFFF}]/u', '', $str);
            $str = $tmp ?? $this->_failClosedNeutralize($str);
        }

        // backup the string (for later comparison)
        $str_backup = $str;
        
        // process
        $iterations = 0;
        do {
            $this->_guardAgainstNonConvergingLoop($iterations, __METHOD__);

            // backup the string (for the loop)
            $str_backup_loop = $str;

            // correct words before the browser will do it
            $str = $this->_compact_exploded_javascript($str);
    
            // remove disallowed javascript calls in links, images etc.
            $str = $this->_remove_disallowed_javascript($str);
    
            // remove strings that are never allowed
            $str = $this->_do_callback_outside_of_pre_and_code_tags($str, [$this, '_do_never_allowed']);
    
            // remove all event handler attributes ("on" + any name), also unknown / future events
            $str = $this->_remove_event_handler_attributes($str);

            // remove evil attributes such as style, onclick and xmlns
            $str = $this->_remove_evil_attributes($str);
    
            // sanitize naughty JavaScript elements
            $str = $this->_do_callback_outside_of_pre_and_code_tags($str, [$this, '_sanitize_naughty_javascript']);
    
            // sanitize naughty HTML elements
            $str = $this->_sanitize_naughty_html($str);
    
            // final clean up
            //
            // -> This adds a bit of extra precaution in case something got through the above filters.
            $str = $this->_do_callback_outside_of_pre_and_code_tags($str, [$this, '_do_never_allowed_afterwards']);
        } while ($str_backup_loop !== $str);

        // check for xss
        if ($this->_xss_found !== true) {
            $this->_xss_found = !($str_backup === $str);
        }
        
        return $str;
    }

    /**
     * Remove invisible characters, also url-encoded control characters ("%00" - "%1F", except "%09", "%0A" and
     * "%0D"), like "UTF8::remove_invisible_characters($str, true, '', false)", but in linear time.
     *
     * <p>
     * <br />
     * INFO: The vendor method repeats its regex until nothing changes, so that nested escapes like
     *       "%0%0%000" needed one (full) regex pass per level (quadratic runtime). Here the url-encoded
     *       control characters are removed via a stack, which also removes escapes that are only formed
     *       by removing an inner one. "%0C" (form feed) is HTML whitespace, so it's replaced by a space.
     * </p>
     *
     * @param string $str
     *
     * @return string
     */
    private function _remove_invisible_characters($str)
    {
        $iterations = 0;
        do {
            $this->_guardAgainstNonConvergingLoop($iterations, __METHOD__);
            $strBefore = $str;

            // raw control characters etc. (without the url-encoded ones)
            $str = $this->_failClosedVendorCall(
                static function ($str) {
                    return UTF8::remove_invisible_characters($str, false, '', false);
                },
                $str
            );

            if (\strpos($str, '%') === false) {
                break;
            }

            if (\preg_match('/%[01]/', $str) === 0) {
                break;
            }

            // INFO: a pre-allocated string is used as stack (one byte per char), to keep the memory usage low
            $length = \strlen($str);
            $stack = \str_repeat(' ', $length);
            $stackSize = 0;
            for ($i = 0; $i < $length; ++$i) {
                $stack[$stackSize] = $str[$i];
                ++$stackSize;

                if (
                    $stackSize >= 3
                    &&
                    $stack[$stackSize - 3] === '%'
                ) {
                    $first = $stack[$stackSize - 2];
                    $second = $stack[$stackSize - 1];
                    if (
                        (
                            $first === '0'
                            &&
                            \strpos('012345678bcefBCEF', $second) !== false
                        )
                        ||
                        (
                            $first === '1'
                            &&
                            \strpos('0123456789abcdefABCDEF', $second) !== false
                        )
                    ) {
                        $stackSize -= 3;

                        if ($first === '0' && ($second === 'c' || $second === 'C')) {
                            $stack[$stackSize] = ' ';
                            ++$stackSize;
                        }
                    }
                }
            }

            $str = (string) \substr($stack, 0, $stackSize);
        } while ($strBefore !== $str);

        return $str;
    }

    /**
     * @param string   $str
     * @param callable $callback
     *
     * @return string
     */
    private function _do_callback_outside_of_pre_and_code_tags($str, callable $callback)
    {
        static $REGEX_FOR_PRE_CODE_HTML = '/<(pre|code)\b(?:[^>"\']+|"[^"]*"|\'[^\']*\')*>.*?<\/\1>/is';

        if ($this->_keep_pre_and_code_tag_content !== true) {
            return $callback($str);
        }

        if (
            \stripos($str, '<pre') === false
            &&
            \stripos($str, '<code') === false
        ) {
            return $callback($str);
        }

        $result = '';
        $offset = 0;

        while (
            \preg_match($REGEX_FOR_PRE_CODE_HTML, $str, $matches, PREG_OFFSET_CAPTURE, $offset) === 1
        ) {
            $match = $matches[0][0];
            $start = $matches[0][1];

            $result .= $callback((string) \substr($str, $offset, $start - $offset));
            $result .= $match;
            $offset = $start + \strlen($match);
        }

        if ($offset === 0) {
            return $callback($str);
        }

        $remaining = (string) \substr($str, $offset);

        if ($remaining === '') {
            return $result;
        }

        return $result . $callback($remaining);
    }

    /**
     * @param int    $iterations
     * @param string $context
     *
     * @return void
     */
    private function _guardAgainstNonConvergingLoop(&$iterations, $context)
    {
        ++$iterations;

        if ($iterations > self::MAX_SANITIZATION_PASSES) {
            throw new \RuntimeException(
                'AntiXSS detected a non-converging sanitization loop after '
                . self::MAX_SANITIZATION_PASSES
                . ' passes while running '
                . $context
                . '.'
            );
        }
    }

    /**
     * Remove never allowed strings.
     *
     * @param string $str
     *
     * @return string
     */
    private function _do_never_allowed($str)
    {
        static $NEVER_ALLOWED_CACHE = [];

        if (!isset($NEVER_ALLOWED_CACHE['keys'])) {
            $NEVER_ALLOWED_CACHE['keys'] = \array_keys($this->_never_allowed_str);
        }

        // INFO: repeat until nothing changes, so that nested strings like "docdocument.cookieument.cookie"
        //       are removed here and not only one layer per (expensive) pass of the main loop in "_do()"
        $iterations = 0;
        do {
            $this->_guardAgainstNonConvergingLoop($iterations, __METHOD__);
            $strBefore = $str;
            $str = \str_ireplace(
                $NEVER_ALLOWED_CACHE['keys'],
                $this->_never_allowed_str,
                $str
            );
        } while ($strBefore !== $str);

        // ---

        $replaceNeverAllowedCall = [];
        foreach ($this->_never_allowed_call_strings as $call) {
            if (\stripos($str, $call) !== false) {
                $replaceNeverAllowedCall[] = $call;
            }
        }
        if (\count($replaceNeverAllowedCall) > 0) {
            // INFO: also with an encoded ":" (e.g. "javascript&colon;"), because text between html-tags is
            //       not entity-decoded here, but the browser decodes it e.g. in an attribute value
            $tmp = \preg_replace(
                '#([^\p{L}]|^)(?:' . \implode('|', $replaceNeverAllowedCall) . ')\s*(?::|&colon;|&\#0*+58;?|&\#x0*+3a;?)(?!\s[\p{L}\p{N}\s]*$)(?:.*?([/\\\;()\'">]|$))#ius',
                '$1' . $this->_replacement . '$2',
                $str
            );
            $str = $tmp ?? $this->_failClosedNeutralize($str);
        }

        // ---

        foreach ($this->_cache_never_allowed_regex_replacements as $regex => $replacement) {
            $tmp = \preg_replace(
                '#' . $regex . '#iUus',
                $replacement,
                $str
            );
            $str = $tmp ?? $this->_failClosedNeutralize($str);
        }

        if ($this->_cache_never_allowed_regex_string) {
            $tmp = \preg_replace(
                '#' . $this->_cache_never_allowed_regex_string . '#ius',
                $this->_replacement,
                $str
            );
            $str = $tmp ?? $this->_failClosedNeutralize($str);
        }

        foreach ($this->_cache_never_allowed_regex_standalone as $regex) {
            $tmp = \preg_replace(
                '#' . $regex . '#ius',
                $this->_replacement,
                $str
            );
            $str = $tmp ?? $this->_failClosedNeutralize($str);
        }

        return $str;
    }

    /**
     * @return array
     *
     * @phpstan-return array<string, list<string>>
     */
    private function _get_never_allowed_on_events_afterwards_chunks()
    {
        if ($this->_cache_never_allowed_on_events_afterwards_chunks !== null) {
            return $this->_cache_never_allowed_on_events_afterwards_chunks;
        }

        // init
        $array = [];

        foreach ($this->_never_allowed_on_events_afterwards as $event) {
            $array[$event[0] . $event[1] . $event[2]][] = $event;
        }

        foreach ($array as $eventNameBeginning => $events) {
            // INFO: longest names first, so that e.g. "onLoadEnd" is not matched as "onLoad" + "End"
            \usort(
                $events,
                static function ($a, $b) {
                    return \strlen($b) <=> \strlen($a);
                }
            );

            // INFO: only the "before"-part and the event name are matched here, the "after"-part is checked
            //       in "_remove_never_allowed_on_events_afterwards()" without regex-backtracking
            $this->_cache_never_allowed_on_events_afterwards_regex[$eventNameBeginning] =
                '(?<before>[^\p{L}@.!?>-]|^)(?<name>' . \implode('|', $events) . ')';
        }

        $this->_cache_never_allowed_on_events_afterwards_chunks = $array;

        return $this->_cache_never_allowed_on_events_afterwards_chunks;
    }

    /**
     * Remove all event names (e.g. "onclick") that are followed by something that makes them usable as
     * an event handler ("(...)", "=", a later ">" or the end of the string).
     *
     * <p>
     * <br />
     * INFO: This replaces a regex like "onclick(.*?>|=|$|...)", which removed only one name per ">" and per
     *       pass (so that e.g. 2000 names needed 2000 passes) and which was quadratic as a lookahead. Here the
     *       names are processed from the end of the string to the start, and the "after"-part of each name
     *       is checked against the text that follows it *after* the removal of the following names. So the
     *       result is the same as running the old regex until nothing changes, but in one linear pass.
     * </p>
     *
     * @param string $str
     * @param string $regexNames <p>regex for the "before"-part + event names</p>
     *
     * @return string
     */
    private function _remove_never_allowed_on_events_afterwards($str, $regexNames)
    {
        // INFO: "\x01" and "\x02" are used as markers below (control chars, already removed in "_do()")
        if (\strpos($str, "\x01") !== false || \strpos($str, "\x02") !== false) {
            $str = \str_replace(["\x01", "\x02"], '', $str);
        }

        // INFO: mark the event names via "preg_replace()" instead of "preg_match_all()", because the
        //       match-arrays of "preg_match_all()" need ~150x the memory of the input
        $count = 0;
        $marked = \preg_replace(
            '#' . $regexNames . '#ius',
            '${1}' . "\x01" . '${2}' . "\x02",
            $str,
            -1,
            $count
        );
        if ($marked === null) {
            return $this->_failClosedNeutralize($str);
        }
        if ($count === 0) {
            return $str;
        }

        // offsets of all names ("\x01" and "\x02"), packed into a string (8 bytes per name)
        $offsets = '';
        $offset = 0;
        while (($nameStart = \strpos($marked, "\x01", $offset)) !== false) {
            $nameEnd = (int) \strpos($marked, "\x02", $nameStart);
            $offsets .= \pack('NN', $nameStart, $nameEnd);
            $offset = $nameEnd + 1;
        }
        $count = (int) (\strlen($offsets) / 8);

        $length = \strlen($marked);
        $lastGt = \strrpos($marked, '>');
        $lastClosingParenthesis = \strrpos($marked, ')');

        // summary of the (already cleaned) text after the current event name
        $tail = $this->_events_tail_summary_empty();

        // one byte per name: "1" -> remove it
        $remove = \str_repeat('0', $count);

        $gapEnd = $length;
        for ($i = $count - 1; $i >= 0; --$i) {
            /** @var int[] $name */
            $name = \unpack('Nstart/Nend', \substr($offsets, $i * 8, 8));
            // offsets of the event name (without the markers)
            $nameStart = $name['start'] + 1;
            $nameEnd = $name['end'];

            $gap = (string) \substr($marked, $nameEnd + 1, $gapEnd - $nameEnd - 1);

            $tailAfterName = $this->_events_tail_summary_compose($gap, $tail);

            $isEvent = (
                // "onclick ... >"
                ($lastGt !== false && $lastGt > $nameEnd)
                ||
                // "onclick(...)"
                (
                    $gap !== ''
                    &&
                    $gap[0] === '('
                    &&
                    $lastClosingParenthesis !== false
                    &&
                    $lastClosingParenthesis > $nameEnd
                )
                ||
                // "onclick=", "onclick&equals;", "onclick [foo] =", "onclick" at the end
                $tailAfterName['a']
                ||
                $tailAfterName['b']
                ||
                $tailAfterName['c']
            );

            // summary of the text starting at this event name (after cleaning) for the previous name
            if ($isEvent) {
                $remove[$i] = '1';
                $tail = $this->_replacement === ''
                    ? $tailAfterName
                    : $this->_events_tail_summary_compose($this->_replacement, $tailAfterName);
            } else {
                $tail = $this->_events_tail_summary_compose(
                    (string) \substr($marked, $nameStart, $nameEnd - $nameStart),
                    $tailAfterName
                );
            }

            $gapEnd = $name['start'];
        }

        // build the result (without the markers)
        $result = '';
        $offset = 0;
        for ($i = 0; $i < $count; ++$i) {
            /** @var int[] $name */
            $name = \unpack('Nstart/Nend', \substr($offsets, $i * 8, 8));

            $result .= \substr($marked, $offset, $name['start'] - $offset);
            if ($remove[$i] === '1') {
                $result .= $this->_replacement;
            } else {
                $result .= \substr($marked, $name['start'] + 1, $name['end'] - $name['start'] - 1);
            }
            $offset = $name['end'] + 1;
        }

        return $result . \substr($marked, $offset);
    }

    /**
     * @return array{a: bool, b: bool, bin: bool, c: bool, pre: string}
     */
    private function _events_tail_summary_empty()
    {
        return [
            'a'   => false,
            'b'   => false,
            'bin' => false,
            'c'   => true,
            'pre' => '',
        ];
    }

    /**
     * Summary of "$prefix . <text summarized by $tail>", without building that (maybe long) text.
     *
     * <p>
     * <br />
     * a   -> starts with "[^\p{L}]*?(?:=|&equals;)"<br />
     * b   -> starts with "(?:\s|\[[^\]]*\])*(?:=|&equals;)"<br />
     * bin -> like "b", but starting inside of "[...]"<br />
     * c   -> only whitespace<br />
     * pre -> the first bytes (to detect "&equals;" across the border)
     * </p>
     *
     * @param string $prefix
     * @param array{a: bool, b: bool, bin: bool, c: bool, pre: string} $tail
     *
     * @return array{a: bool, b: bool, bin: bool, c: bool, pre: string}
     */
    private function _events_tail_summary_compose($prefix, array $tail)
    {
        if ($prefix === '') {
            return $tail;
        }

        $prefixLength = \strlen($prefix);
        $str = $prefix . $tail['pre'];

        // a: "[^\p{L}]*?(?:=|&equals;)"
        // (invalid UTF-8 etc.: be strict)
        $matchA = \preg_match('/^(?>[^\p{L}=&]++|&(?!equals;))*+/iu', $str, $matchesA);
        $pos = $matchA === 1 ? \strlen($matchesA[0]) : 0;
        if ($matchA === false) {
            // PCRE failed: fail closed (remove the name)
            $a = true;
        } elseif ($pos >= $prefixLength) {
            $a = $tail['a'];
        } else {
            $a = $str[$pos] === '=' || $str[$pos] === '&';
        }

        // b: "(?:\s|\[[^\]]*\])*(?:=|&equals;)" (outside and inside of "[...]")
        $b = $this->_events_tail_scan_b($prefix, false, $tail);
        $bin = $this->_events_tail_scan_b($prefix, true, $tail);

        // c: only whitespace
        $c = $tail['c'] && \preg_match('/^\s*$/u', $prefix) !== 0;

        // the first chars (not bytes, so that we never cut an UTF-8 char)
        $pre = \preg_match('/^.{0,16}/us', $str, $matchesPre) === 1 ? $matchesPre[0] : '';

        return [
            'a'   => $a,
            'b'   => $b,
            'bin' => $bin,
            'c'   => $c,
            'pre' => $pre,
        ];
    }

    /**
     * @param string $prefix
     * @param bool   $inside
     * @param array{a: bool, b: bool, bin: bool, c: bool, pre: string} $tail
     *
     * @return bool
     */
    private function _events_tail_scan_b($prefix, $inside, array $tail)
    {
        $length = \strlen($prefix);
        $str = $prefix . $tail['pre'];

        for ($i = 0; $i < $length; ++$i) {
            $char = $str[$i];

            if ($inside) {
                if ($char === ']') {
                    $inside = false;
                }

                continue;
            }

            if ($char === '[') {
                $inside = true;

                continue;
            }

            if ($char === '=') {
                return true;
            }

            if ($char === '&') {
                return \stripos($str, '&equals;', $i) === $i;
            }

            if (\strpos(" \t\n\r\f\v", $char) !== false) {
                continue;
            }

            // INFO: non-ASCII whitespace (e.g. a non-breaking space) is already normalized in "_do()"
            return false;
        }

        return $inside ? $tail['bin'] : $tail['b'];
    }

    /**
     * Remove never allowed string, afterwards.
     *
     * <p>
     * <br />
     * INFO: clean-up also some string, if there is no html-tag
     * </p>
     *
     * @param string $str
     *
     * @return  string
     */
    private function _do_never_allowed_afterwards($str)
    {
        if (\stripos($str, 'on') !== false) {
            foreach ($this->_get_never_allowed_on_events_afterwards_chunks() as $eventNameBeginning => $events) {
                if (\stripos($str, $eventNameBeginning) === false) {
                    continue;
                }

                foreach ($events as $event) {
                    if (\stripos($str, $event) === false) {
                        continue;
                    }

                    $iterations = 0;
                    do {
                        $this->_guardAgainstNonConvergingLoop($iterations, __METHOD__);
                        $strBefore = $str;

                        $str = $this->_remove_never_allowed_on_events_afterwards(
                            $str,
                            $this->_cache_never_allowed_on_events_afterwards_regex[$eventNameBeginning]
                        );
                    } while ($strBefore !== $str);

                    break;
                }
            }
        }

        $str = (string) \str_ireplace(
            $this->_never_allowed_str_afterwards,
            $this->_replacement,
            $str
        );

        // also remove all other spellings of the encoded tags from "_never_allowed_str_afterwards" (e.g.
        // "&lt;script&gt;"), that a browser would decode into the same tag (e.g. in a "srcdoc"-attribute):
        // "&lt;script &gt;", "&lt;script/x&gt;", "&#60;script>", "&LTscript\t>", ...
        if (\strpos($str, '&') !== false) {
            $tagNames = [];
            foreach ($this->_never_allowed_str_afterwards as $neverAllowedStr) {
                $matchTagName = \preg_match('#^&lt;/?([a-z][a-z\d-]*+)&gt;$#i', $neverAllowedStr, $matchesTagName);
                if ($matchTagName === false) {
                    return $this->_failClosedNeutralize($str);
                }
                if ($matchTagName === 1) {
                    if (\stripos($str, $matchesTagName[1]) !== false) {
                        $tagNames[\strtolower($matchesTagName[1])] = \preg_quote($matchesTagName[1], '#');
                    }
                }
            }

            if ($tagNames !== []) {
                $tmp = \preg_replace(
                    '#(?:&lt;?|&\#0*+60;?|&\#x0*+3c;?)(?:/|&sol;|&\#0*+47;?|&\#x0*+2f;?)?(?:' . \implode('|', $tagNames) . ')(?=[\s/>]|&(?:gt;?|sol;|tab;|newline;|\#0*+(?:62|47|9|10|12|13|32);?|\#x0*+(?:3e|2f|9|a|c|d|20);?))#i',
                    $this->_replacement,
                    $str
                );
                $str = $tmp ?? $this->_failClosedNeutralize($str);
            }
        }

        return $str;
    }

    /**
     * Entity-decoding.
     *
     * @param string $str
     *
     * @return string
     */
    private function _entity_decode($str)
    {
        static $HTML_ENTITIES_CACHE;

        $flags = ENT_QUOTES | ENT_HTML5 | ENT_DISALLOWED | ENT_SUBSTITUTE;

        // decode-again, for e.g. HHVM or miss configured applications ...
        $entityMatches = \strpos($str, '&') !== false
            ? \preg_match_all('/(?<html_entity>&[A-Za-z]{2,};{0})/', $str, $matches)
            : 0;
        if ($entityMatches === false) {
            return $this->_failClosedNeutralize($str);
        }
        if ($entityMatches > 0) {
            if ($HTML_ENTITIES_CACHE === null) {
                // links:
                // - http://dev.w3.org/html5/html-author/charref
                // - http://www.w3schools.com/charsets/ref_html_entities_n.asp
                $entitiesSecurity = [
                    '&#x00000;'          => '',
                    '&#0;'               => '',
                    '&#x00001;'          => '',
                    '&#1;'               => '',
                    '&nvgt;'             => '',
                    '&#61253;'           => '',
                    '&#x0EF45;'          => '',
                    '&shy;'              => '',
                    '&#x000AD;'          => '',
                    '&#173;'             => '',
                    '&colon;'            => ':',
                    '&#x0003A;'          => ':',
                    '&#58;'              => ':',
                    '&lpar;'             => '(',
                    '&#x00028;'          => '(',
                    '&#40;'              => '(',
                    '&rpar;'             => ')',
                    '&#x00029;'          => ')',
                    '&#41;'              => ')',
                    '&quest;'            => '?',
                    '&#x0003F;'          => '?',
                    '&#63;'              => '?',
                    '&sol;'              => '/',
                    '&#x0002F;'          => '/',
                    '&#47;'              => '/',
                    '&apos;'             => '\'',
                    '&#x00027;'          => '\'',
                    '&#039;'             => '\'',
                    '&#39;'              => '\'',
                    '&#x27;'             => '\'',
                    '&bsol;'             => '\'',
                    '&#x0005C;'          => '\\',
                    '&#92;'              => '\\',
                    '&comma;'            => ',',
                    '&#x0002C;'          => ',',
                    '&#44;'              => ',',
                    '&period;'           => '.',
                    '&#x0002E;'          => '.',
                    '&quot;'             => '"',
                    '&QUOT;'             => '"',
                    '&#x00022;'          => '"',
                    '&#34;'              => '"',
                    '&grave;'            => '`',
                    '&DiacriticalGrave;' => '`',
                    '&#x00060;'          => '`',
                    '&#96;'              => '`',
                    '&#46;'              => '.',
                    '&equals;'           => '=',
                    '&#x0003D;'          => '=',
                    '&#61;'              => '=',
                    '&newline;'          => "\n",
                    '&#x0000A;'          => "\n",
                    '&#10;'              => "\n",
                    '&tab;'              => "\t",
                    '&#x00009;'          => "\t",
                    '&#9;'               => "\t",
                ];

                $HTML_ENTITIES_CACHE = \array_merge(
                    $entitiesSecurity,
                    \array_flip(\get_html_translation_table(HTML_ENTITIES, $flags)),
                    \array_flip(self::_get_data('entities_fallback'))
                );
            }

            $search = [];
            $replace = [];
            foreach ($matches['html_entity'] as $match) {
                $match .= ';';
                if (isset($HTML_ENTITIES_CACHE[$match])) {
                    $search[$match] = $match;
                    $replace[$match] = $HTML_ENTITIES_CACHE[$match];
                }
            }

            if (\count($replace) > 0) {
                $str = \str_ireplace($search, $replace, $str);
            }
        }

        return $str;
    }

    /**
     * Filters tag attributes for consistency and safety.
     *
     * @param string $str
     *
     * @return string
     */
    private function _filter_attributes($str)
    {
        if ($str === '') {
            return '';
        }

        if (\strpos($str, '=') !== false) {
            $matchesTmp = [];
            while (\preg_match('#\s*[\p{L}\d_\-\[\]]+\s*=\s*(?:(["\'])(?:[^\1]*?)\\1|\\\"(?:[^"]*?)\\\")#u', $str, $matches)) {
                $matchesTmp[] = $matches[0];
                $str = \str_replace($matches[0], '', $str);

                if (\substr_count($str, '"') <= 1 && \substr_count($str, '\'') <= 1) {
                    break;
                }
            }
            $out = \implode('', $matchesTmp);
        } else {
            $out = $str;
        }

        return $out;
    }

    /**
     * get data from "/data/*.php"
     *
     * @param string $file
     *
     * @return string[]
     *
     * @phpstan-return array<string, string>
     */
    private static function _get_data($file)
    {
        return include __DIR__ . '/data/' . $file . '.php';
    }

    /**
     * initialize "$this->_never_allowed_str"
     *
     * @return void
     */
    private function _initNeverAllowedStr()
    {
        $this->_never_allowed_str = [
            'document.cookie'   => $this->_replacement,
            '(document).cookie' => $this->_replacement,
            'document.write'    => $this->_replacement,
            '(document).write'  => $this->_replacement,
            '.parentNode'       => $this->_replacement,
            '.innerHTML'        => $this->_replacement,
            '.appendChild'      => $this->_replacement,
            '-moz-binding'      => $this->_replacement,
            '<?'                => '&lt;?',
            '?>'                => '?&gt;',
            '<![CDATA['         => '&lt;![CDATA[',
            '<!ENTITY'          => '&lt;!ENTITY',
            '<!DOCTYPE'         => '&lt;!DOCTYPE',
            '<!ATTLIST'         => '&lt;!ATTLIST',
        ];
    }

    /**
     * initialize "$this->_never_allowed_regex"
     *
     * @return void
     */
    private function _initNeverAllowedRegex()
    {
        $this->_never_allowed_regex = $this->_getDefaultNeverAllowedRegex($this->_replacement);

        $this->_rebuildNeverAllowedRegexCache();
    }

    /**
     * @return array<string, string>
     */
    private function _getDefaultNeverAllowedRegex(string $replacement): array
    {
        return [
            // default javascript
            '(\(?:?document\)?|\(?:?window\)?(?:\.document)?)\.(?:location|on\w*)' => $replacement,
            // data-attribute + base64
            //
            // INFO: browsers remove tabs and newlines in URLs, so "da\tta:" is "data:" and "image/s\nvg" is "image/svg"
            "([\"'])?d[\t\n\r]*+a[\t\n\r]*+t[\t\n\r]*+a\s*:\s*(?!image\s*+\/\s*+(?!s[\t\n\r]*+v[\t\n\r]*+g))[^\1]*?base64[^\1]*?,[^\1]*?\1?" => $replacement,
            // old IE, old Netscape
            'expres(?:\\\\|\s)*sion\s*(?:\(|&\#40;)' => $replacement,
            // src="js"
            'src\=(?<wrapper>[\'|"]).*\.js(?:\g{wrapper})' => $replacement,
            // comments
            '<!--(.*)-->' => '&lt;!--$1--&gt;',
            '<!--'        => '&lt;!--',
        ];
    }

    /**
     * @return void
     */
    private function _rebuildNeverAllowedRegexCache()
    {
        // init
        $regexCombined = [];
        $regexReplacements = [];

        $regexStandalone = [];
        foreach ($this->_never_allowed_regex as $regex => $replacement) {
            if ($replacement === $this->_replacement) {
                // INFO: a start-of-pattern directive (e.g. "(*UCP)") is only valid at the start of a pattern
                if (\strpos((string) $regex, '(*') === 0) {
                    $regexStandalone[] = (string) $regex;

                    continue;
                }

                $regexCombined[] = $regex;

                continue;
            }

            $regexReplacements[$regex] = $replacement;
        }

        // INFO: every regex in its own group, so that e.g. an inline option like "(?-i)" in a custom regex
        //       does not change the following (built-in) regexes
        $this->_cache_never_allowed_regex_string = $regexCombined === []
            ? ''
            : '(?:' . \implode(')|(?:', $regexCombined) . ')';
        $this->_cache_never_allowed_regex_replacements = $regexReplacements;
        $this->_cache_never_allowed_regex_standalone = $regexStandalone;
    }

    /**
     * @return void
     */
    private function _resetNeverAllowedOnEventsAfterwardsCache()
    {
        // reset
        $this->_cache_never_allowed_on_events_afterwards_chunks = null;
        $this->_cache_never_allowed_on_events_afterwards_regex = [];
    }

    /**
     * @return void
     */
    private function _rebuildEvilAttributesQuickChecksCache()
    {
        // init
        $quickChecks = [];
        $canShortCircuit = true;
        $eventQuickChecks = [];
        $allEventsStartWithOn = true;

        foreach ($this->_evil_attributes_regex as $attribute) {
            if (\preg_match('/^[\p{L}\d:_-]+$/u', $attribute) !== 1) {
                $canShortCircuit = false;

                break;
            }

            $quickChecks[] = $attribute;
        }

        foreach ($this->_never_allowed_on_events_afterwards as $event) {
            if (\stripos($event, 'on') !== 0) {
                $allEventsStartWithOn = false;
            }

            $eventQuickChecks[] = (string) \substr($event, 0, \min(3, \strlen($event)));
        }

        if ($canShortCircuit) {
            $quickChecks[] = 'on';
            if ($eventQuickChecks !== [] && !$allEventsStartWithOn) {
                $quickChecks = \array_merge($quickChecks, $eventQuickChecks);
            }
        }

        $this->_cache_can_short_circuit_evil_attributes = $canShortCircuit;
        $this->_cache_evil_attributes_quick_checks = \array_values(\array_unique($quickChecks));
    }

    /**
     * Callback method for xss_clean() to sanitize links.
     *
     * <p>
     * <br />
     * INFO: This limits the PCRE backtracks, making it more performance friendly
     * and prevents PREG_BACKTRACK_LIMIT_ERROR from being triggered in
     * PHP 5.2+ on link-heavy strings.
     * </p>
     *
     * @param string[] $match
     *
     * @return string
     */
    private function _js_link_removal_callback($match)
    {
        return $this->_js_removal_callback($match, 'href');
    }

    /**
     * Check whether an href/src value is URL-like enough to skip JS callback stripping.
     *
     * @param string $value  The extracted attribute value
     *
     * @return bool True for URL-like values that should bypass callback filtering, false otherwise
     */
    private function _isValidUrlForCallbackBypass($value)
    {
        $value = \str_replace(' ', '%20', $value);

        if (\filter_var($value, \FILTER_VALIDATE_URL) !== false) {
            return true;
        }

        if (\stripos($value, 'script') !== false || \strpos($value, ':') !== false) {
            return false;
        }

        return \strpbrk($value, '/?#') !== false;
    }

    /**
     * Callback method for xss_clean() to sanitize tags.
     *
     * <p>
     * <br />
     * INFO: This limits the PCRE backtracks, making it more performance friendly
     * and prevents PREG_BACKTRACK_LIMIT_ERROR from being triggered in
     * PHP 5.2+ on image tag heavy strings.
     * </p>
     *
     * @param string[]  $match
     * @param string $search
     *
     * @return string
     */
    private function _js_removal_callback($match, $search)
    {
        if (!$match[0]) {
            return '';
        }

        $replacer = $this->_filter_attributes($match[1]);

        // filter for "$search"-attributes
        if (\preg_match('#(?:^|[ \t])' . \preg_quote($search, '#') . '[ \t]*=#iu', $match[1]) !== 0) {
            // 1: whitespace before "=", 2: whitespace after "=", 3: quote wrapper, 4: attribute value
            $pattern = '#' . \preg_quote($search, '#') . '([ \t]*)=([ \t]*)([\'"])(.*)(?:\3)#isU';
            $matchInner = [];
            $foundSomethingBad = false;
            $isValidAttributeUrl = false;
            $matchInnerResult = \preg_match($pattern, $match[1], $matchInner);
            if ($matchInnerResult === false) {
                // PCRE failed: fail closed (remove the attribute)
                $foundSomethingBad = true;
                $this->_xss_found = true;
                $replacer = $this->_failClosedRemoveAttributesByName($replacer, [$search]);
            } elseif ($matchInnerResult === 1) {
                $isValidAttributeUrl = $this->_isValidUrlForCallbackBypass($matchInner[4]);
                $needProtection = !$isValidAttributeUrl;

                if ($needProtection) {
                    if ($this->_nested_clean_depth >= self::MAX_NESTED_CLEAN_DEPTH) {
                        // too deeply nested for another clean: fail closed
                        $nestedXssFound = true;
                    } else {
                        $tmpAntiXss = $this->_clone_for_nested_clean();
                        $tmpAntiXss->xss_clean((string) $matchInner[0]);
                        $nestedXssFound = $tmpAntiXss->isXssFound() === true;
                    }

                    if ($nestedXssFound) {
                        $foundSomethingBad = true;
                        $this->_xss_found = true;

                        $tmp = \preg_replace(
                            $pattern,
                            $search . '${1}=${2}"' . $this->_replacement . '"',
                            $replacer
                        );
                        $replacer = $tmp ?? $this->_failClosedRemoveAttributesByName($replacer, [$search]);
                    }
                }
            }

            $shouldFilterJsCallbacks = !$foundSomethingBad && !$isValidAttributeUrl;

            if ($shouldFilterJsCallbacks) {
                // filter for javascript
                $patternTmp = '';
                foreach ($this->_never_allowed_call_strings as $callTmp) {
                    if (\stripos($match[0], $callTmp) !== false) {
                        $patternTmp .= $callTmp . ':|';
                    }
                }
                $pattern = '#' . $search . '=.*(?:' . $patternTmp . \implode('|', $this->_never_allowed_js_callback_regex) . ')#ius';
                $matchInner = [];
                $matchInnerResult = \preg_match($pattern, $match[1], $matchInner);
                if ($matchInnerResult !== 0) {
                    $tmp = $matchInnerResult === 1
                        ? \preg_replace(
                            $pattern,
                            $search . '="' . $this->_replacement . '"',
                            $replacer
                        )
                        : null;
                    if ($tmp === null) {
                        // PCRE failed: fail closed (remove the attribute)
                        $this->_xss_found = true;
                        $tmp = $this->_failClosedRemoveAttributesByName($replacer, [$search]);
                    }
                    $replacer = $tmp;
                }
            }
        }
        
        if (
            \substr($match[0], -3) === ' />'
            &&
            \substr($match[1], -2) === ' /'
            &&
            \substr($replacer, -2) !== ' /'
        ) {
            $replacer .= ' /';
        } elseif (
            \substr($match[0], -2) === '/>'
            &&
            \substr($match[1], -1) === '/'
            &&
            \substr($replacer, -1) !== '/'
        ) {
            $replacer .= '/';
        }
        
        
        return \str_ireplace($match[1], $replacer, (string) $match[0]);
    }

    /**
     * Callback method for xss_clean() to sanitize image tags.
     *
     * <p>
     * <br />
     * INFO: This limits the PCRE backtracks, making it more performance friendly
     * and prevents PREG_BACKTRACK_LIMIT_ERROR from being triggered in
     * PHP 5.2+ on image tag heavy strings.
     * </p>
     *
     * @param string[] $match
     *
     * @return string
     */
    private function _js_src_removal_callback(array $match)
    {
        return $this->_js_removal_callback($match, 'src');
    }

    /**
     * ASCII-only "is alphanumeric" check for a single byte, deliberately not using
     * "ctype_alnum()": "ext-ctype" is not declared in "composer.json" and is not
     * guaranteed to be enabled on every PHP build.
     *
     * @param string $byte exactly one byte
     *
     * @return bool
     */
    private function _isAsciiAlnumByte($byte)
    {
        return ($byte >= 'a' && $byte <= 'z')
            || ($byte >= 'A' && $byte <= 'Z')
            || ($byte >= '0' && $byte <= '9');
    }

    /**
     * Last-resort, backtracking-free removal of "<$tagName ...>" used only when the
     * normal regex-based removal above could not run at all (e.g. because
     * "pcre.backtrack_limit" was exhausted, which an attacker can trigger
     * deliberately with a pathological payload to try to bypass sanitization).
     *
     * <p>
     * <br />
     * We must never fall back to returning the untouched, still-dangerous input in
     * that case ("fail open"); instead every occurrence of the tag is destroyed
     * with the configured replacement ("fail closed"). This only uses "strpos()" and
     * plain byte comparisons, so it cannot itself be driven into catastrophic backtracking.
     * </p>
     *
     * @param string $str
     * @param string $tagName tag name without "<", e.g. "a", "img", "script"
     *
     * @return string
     */
    private function _failClosedRemoveTag($str, $tagName)
    {
        $needle = '<' . $tagName;
        $length = \strlen($str);
        $result = '';
        $offset = 0;

        while ($offset < $length && ($pos = \stripos($str, $needle, $offset)) !== false) {
            $afterName = $pos + \strlen($needle);
            $nextByte = $afterName < $length ? $str[$afterName] : '';

            if ($nextByte !== '' && $this->_isAsciiAlnumByte($nextByte)) {
                // e.g. "<audioplayer" is not "<audio"; keep scanning past the false positive
                $result .= \substr($str, $offset, $afterName - $offset);
                $offset = $afterName;

                continue;
            }

            $result .= \substr($str, $offset, $pos - $offset);

            $closePos = \strpos($str, '>', $afterName);
            if ($closePos === false) {
                // unterminated tag: drop the remainder rather than risk leaving it intact
                return $result . $this->_replacement;
            }

            $result .= $this->_replacement;
            $offset = $closePos + 1;
        }

        return $result . \substr($str, $offset);
    }

    /**
     * The terminal fail-closed fallback, if a sanitizing step could not run, because PCRE failed (e.g.
     * "pcre.backtrack_limit" exhausted, also with "pcre.jit" disabled). It does not use PCRE.
     *
     * <p>
     * <br />
     * Security invariant of the result (also if it's used in an attribute value):
     * - no "<", ">", '"', "'" -> no tag, no attribute, no attribute break-out
     * - no ":" -> no URL scheme (e.g. "javascript:"), also no encoded one: character references are decoded first
     *   and every remaining "&" is encoded, so e.g. "&#58;", "&#x3a", "&colon;" can not become a ":" in the browser
     * - no control chars, which could hide e.g. a "javascript:" from other filters
     * - no "+" -> no UTF-7 shift sequence (e.g. "+ADw-script+AD4-"), if the page is decoded as UTF-7
     *
     * It's lossy on purpose (only used, if a step could not run at all) and idempotent (encode(decode(result)) is the
     * result), so the cleaning loops still converge. It reports the input as XSS.
     * </p>
     *
     * @param string $str
     *
     * @return string
     */
    private function _failClosedNeutralize($str)
    {
        $this->_xss_found = true;

        $str = \html_entity_decode($str, \ENT_QUOTES | \ENT_HTML5, 'UTF-8');

        $remove = [':', '+'];
        foreach (\array_merge(\range(0, 8), [11, 12], \range(14, 31), [127]) as $byte) {
            $remove[] = \chr($byte);
        }
        $str = \str_replace($remove, '', $str);

        // INFO: "double_encode" -> also every "&" of a not decoded reference (e.g. "&#58" without ";") is encoded
        $str = \htmlspecialchars($str, \ENT_QUOTES | \ENT_SUBSTITUTE | \ENT_HTML401, 'UTF-8', true);

        return $str;
    }

    /**
     * "UTF8::rawurldecode()", but the "%uXXXX" escapes are decoded here (without PCRE) and PCRE failures in the
     * vendor method fail closed (see "_failClosedVendorCall()").
     *
     * <p>
     * <br />
     * INFO: The vendor method decodes "%uXXXX" only, if its "preg_match()" succeeds; if that fails, a later
     *       successful PCRE call resets "preg_last_error()", so the failure was not visible and "%u003C" (= "<")
     *       stayed encoded. Here they are replaced like in "UTF8::urldecode_unicode_helper()"
     *       ('/%u([0-9a-fA-F]{3,4})/' -> '&#x\\1;'), so the vendor method has nothing left to skip.
     * </p>
     *
     * @param string $str
     *
     * @return string
     */
    private function _rawurldecode($str)
    {
        if (\strpos($str, '%u') !== false) {
            $result = '';
            $offset = 0;
            while (($pos = \strpos($str, '%u', $offset)) !== false) {
                $hexLength = \strspn($str, '0123456789abcdefABCDEF', $pos + 2, 4);
                if ($hexLength < 3) {
                    $result .= \substr($str, $offset, $pos + 2 - $offset);
                    $offset = $pos + 2;

                    continue;
                }

                $result .= \substr($str, $offset, $pos - $offset) . '&#x' . \substr($str, $pos + 2, $hexLength) . ';';
                $offset = $pos + 2 + $hexLength;
            }
            $str = $result . \substr($str, $offset);
        }

        return $this->_failClosedVendorCall([UTF8::class, 'rawurldecode'], $str);
    }

    /**
     * Call a "portable-utf8" method, that uses PCRE internally, and fail closed, if PCRE failed in there.
     *
     * <p>
     * <br />
     * INFO: These methods cast a failed "preg_replace()" to "" ("(string) preg_replace()"), so that the string was
     *       erased before the backup in "_do()" and "xss_clean()" returned the original, unchecked input.
     * </p>
     *
     * @param callable $call <p>callable(string): string</p>
     * @param string   $str
     *
     * @return string
     */
    private function _failClosedVendorCall(callable $call, $str)
    {
        // reset "preg_last_error()"
        \preg_match('/^/', '');

        $result = (string) $call($str);

        if (
            \preg_last_error() !== \PREG_NO_ERROR
            ||
            // printable ASCII chars are never removed or decoded into nothing, so "" means, that PCRE failed
            ($result === '' && \strcspn($str, self::PRINTABLE_ASCII_CHARS) < \strlen($str))
        ) {
            return $this->_failClosedNeutralize($str);
        }

        return $result;
    }

    /**
     * The result of a sanitizing "preg_replace()" / "preg_replace_callback()", or the fail-closed fallback, if PCRE
     * failed ("null"), see "_failClosedNeutralize()".
     *
     * @param string|null $result
     * @param string      $str    <p>the input of the failed step</p>
     *
     * @return string
     */
    private function _failClosedOnNull($result, $str)
    {
        return $result ?? $this->_failClosedNeutralize($str);
    }

    /**
     * Last-resort, backtracking-free removal of dangerous attributes by name, used
     * only when the regex-based "_remove_evil_attributes()" could not run at all
     * (see "_failClosedRemoveTag()" for why we must not fail open in that case).
     *
     * @param string   $str
     * @param string[] $attrNames literal attribute names to strip, e.g. "onclick", "style"
     *
     * @return string
     */
    private function _failClosedRemoveAttributesByName($str, array $attrNames)
    {
        foreach ($attrNames as $attrName) {
            if ($attrName === '' || \stripos($str, $attrName) === false) {
                continue;
            }

            $length = \strlen($str);
            $needleLen = \strlen($attrName);
            $result = '';
            $offset = 0;

            while ($offset < $length && ($pos = \stripos($str, $attrName, $offset)) !== false) {
                $result .= \substr($str, $offset, $pos - $offset);
                $cursor = $pos + $needleLen;

                while ($cursor < $length && \strpos(" \t\r\n", $str[$cursor]) !== false) {
                    ++$cursor;
                }

                $consumedValue = false;
                if ($cursor < $length && $str[$cursor] === '=') {
                    ++$cursor;
                    while ($cursor < $length && \strpos(" \t\r\n", $str[$cursor]) !== false) {
                        ++$cursor;
                    }

                    $quote = $cursor < $length ? $str[$cursor] : '';
                    if ($quote === '"' || $quote === "'") {
                        $endQuote = \strpos($str, $quote, $cursor + 1);
                        if ($endQuote !== false) {
                            $result .= $this->_replacement;
                            $offset = $endQuote + 1;
                            $consumedValue = true;
                        }
                    }
                }

                if (!$consumedValue) {
                    // no safely-bounded quoted value found right after the name:
                    // still neutralize the bare name so it cannot act as an executable attribute
                    $result .= $this->_replacement;
                    $offset = $pos + $needleLen;
                }
            }

            $str = $result . \substr($str, $offset);
        }

        return $str;
    }

    /**
     * Check for a base64 encoded image ("data:image/...base64...,") in the attributes of an "<img>"-tag.
     *
     * <p>
     * <br />
     * INFO: This was a regex with adjacent unbounded quantifiers (".*" + "[^\1]*", where "\1" in a
     *       double-quoted PHP string is the byte 0x01), which was quadratic on many "data:image/" without a
     *       comma (ReDoS). The first "data:image/" has the most text after it, so it's enough to check that one.
     * </p>
     *
     * @param string $str
     *
     * @return bool
     */
    private function _is_base64_image($str)
    {
        if (\strpos($str, 'base64') === false) {
            return false;
        }

        if (\preg_match('/data\s*+:\s*+image\s*+\//iu', $str, $matches, \PREG_OFFSET_CAPTURE) !== 1) {
            return false;
        }

        $base64Pos = \strpos($str, 'base64', (int) $matches[0][1] + \strlen($matches[0][0]));
        if ($base64Pos === false) {
            return false;
        }

        return \strpos($str, ',', $base64Pos + 6) !== false;
    }

    /**
     * Remove disallowed Javascript in links or img tags
     *
     * <p>
     * <br />
     * We used to do some version comparisons and use of stripos(),
     * but it is dog slow compared to these simplified non-capturing
     * preg_match(), especially if the pattern exists in the string
     * </p>
     *
     * <p>
     * <br />
     * Note: It was reported that not only space characters, but all in
     * the following pattern can be parsed as separators between a tag name
     * and its attributes: [\d\s"\'`;,\/\=\(\x00\x0B\x09\x0C]
     * ... however, UTF8::clean() above already strips the
     * hex-encoded ones, so we'll skip them below.
     * </p>
     *
     * @param string $str
     *
     * @return string
     */
    private function _remove_disallowed_javascript($str)
    {
        $iterations = 0;
        do {
            $this->_guardAgainstNonConvergingLoop($iterations, __METHOD__);
            $original = $str;

            if (\stripos($str, '<a') !== false) {
                $strTmp = \preg_replace_callback(
                    '#<a[^\p{L}@>]+([^>]*?)(?:>|$)#iu',
                    [$this, '_js_link_removal_callback'],
                    $str
                );
                if ($strTmp === null) {
                    $strTmp = \preg_replace_callback(
                        '#<a[^\p{L}@>]+([^>]*)(?:>|$)#iu',
                        [$this, '_js_link_removal_callback'],
                        $str
                    );
                }
                $str = $strTmp ?? $this->_failClosedRemoveTag($str, 'a');
            }

            if (\stripos($str, '<img') !== false) {
                $strTmp = \preg_replace_callback(
                    '#<img[^\p{L}@>]+([^>]*?)(?:\s?/?>|$)#iu',
                    function ($matches) {
                        if ($this->_is_base64_image($matches[1])) {
                            return $matches[0];
                        }

                        return $this->_js_src_removal_callback($matches);
                    },
                    $str
                );
                if ($strTmp === null) {
                    $strTmp = \preg_replace_callback(
                        '#<img[^\p{L}@>]+([^>]*)(?:\s?/?>|$)#iu',
                        function ($matches) {
                            if ($this->_is_base64_image($matches[1])) {
                                return $matches[0];
                            }

                            return $this->_js_src_removal_callback($matches);
                        },
                        $str
                    );
                }
                $str = $strTmp ?? $this->_failClosedRemoveTag($str, 'img');
            }

            if (\stripos($str, '<audio') !== false) {
                $strTmp = \preg_replace_callback(
                    '#<audio[^\p{L}@>]+([^>]*?)(?:\s?/?>|$)#iu',
                    [$this, '_js_src_removal_callback'],
                    $str
                );
                if ($strTmp === null) {
                    $strTmp = \preg_replace_callback(
                        '#<audio[^\p{L}@>]+([^>]*)(?:\s?/?>|$)#iu',
                        [$this, '_js_src_removal_callback'],
                        $str
                    );
                }
                $str = $strTmp ?? $this->_failClosedRemoveTag($str, 'audio');
            }

            if (\stripos($str, '<video') !== false) {
                $strTmp = \preg_replace_callback(
                    '#<video[^\p{L}@>]+([^>]*?)(?:\s?/?>|$)#iu',
                    [$this, '_js_src_removal_callback'],
                    $str
                );
                if ($strTmp === null) {
                    $strTmp = \preg_replace_callback(
                        '#<video[^\p{L}@>]+([^>]*)(?:\s?/?>|$)#iu',
                        [$this, '_js_src_removal_callback'],
                        $str
                    );
                }
                $str = $strTmp ?? $this->_failClosedRemoveTag($str, 'video');
            }

            if (\stripos($str, '<source') !== false) {
                $strTmp = \preg_replace_callback(
                    '#<source[^\p{L}@>]+([^>]*)(?:\s?/?>|$)#iu',
                    [$this, '_js_src_removal_callback'],
                    $str
                );
                $str = $strTmp ?? $this->_failClosedRemoveTag($str, 'source');
            }

            if (\stripos($str, 'script') !== false) {
                // INFO: US-ASCII: ¼ === <
                $strTmp = \preg_replace(
                    '#(?:%3C|¼|<)\s*(?:[\p{L}_][\p{L}\p{N}_.-]*+:)?script[^\p{L}@]+(?:[^>]*)(?:\s?/?(?:%3E|¾|>)|$)#iu',
                    $this->_replacement,
                    $str
                );
                $str = $strTmp ?? $this->_failClosedRemoveTag($str, 'script');
            }

            if (\stripos($str, 'script') !== false) {
                // INFO: US-ASCII: ¼ === <
                $strTmp = \preg_replace(
                    '#(?:%3C|¼|<)[^\p{L}@]*/*[^\p{L}@]*(?:[\p{L}_][\p{L}\p{N}_.-]*+:)?(?:script[^\p{L}@]+).*(?:%3E|¾|>)?#iUus',
                    $this->_replacement,
                    $str
                );
                $str = $strTmp ?? $this->_failClosedRemoveTag($str, 'script');
            }
        } while ($original !== $str);

        return (string) $str;
    }

    /**
     * Remove every attribute whose name starts with "on" (e.g. "onclick", but also event handlers that are not
     * on the "_never_allowed_on_events_afterwards" list, like "ongesturestart" or events that browsers add later).
     *
     * <p>
     * <br />
     * INFO: The attributes are found with the states of the HTML tokenizer (WHATWG HTML, "Tokenization": tag open,
     *       tag name, before / after attribute name, attribute name, before attribute value, attribute value and
     *       self-closing start tag state), so that only attribute *names* are matched and not text or attribute
     *       values like 'data-onclick="..."', 'title="onclick ..."' or 'class="onboarding"'.
     *
     *       The tokenizer starts at *every* "<" + ASCII letter (also inside of attribute values, comments,
     *       "<textarea>", "<script>", ...), because what a "<" means depends on markup that is not parsed here,
     *       e.g. '<textarea><p title="</textarea><img onfoo=...>">'. So every possible start tag is checked.
     *
     *       Runtime: a scan stops at a "before attribute name" position that an earlier scan already reached (the
     *       rest of the tag is the same), and a start inside an already scanned tag name is skipped. If the scanned
     *       bytes or the number of found attributes still exceed a linear budget, all 'on...=' after whitespace,
     *       "/" or a quote are removed instead ("fail closed", see "_remove_event_handler_attributes_fail_closed()").
     * </p>
     *
     * @param string $str
     *
     * @return string
     */
    private function _remove_event_handler_attributes($str)
    {
        // quick check: an attribute name starts after whitespace, "/" or a quote (after a quoted value), and an event
        // handler attribute is "on" + ASCII letters + optional whitespace + "=" (without a value it does nothing)
        //
        // INFO: only "0" (no match) skips the scan; if PCRE fails ("false"), the scan runs ("fail closed"), it does
        //       not use PCRE itself
        if (
            \strpos($str, '<') === false
            ||
            \preg_match('#[\t\n\f\r /"\']on[a-z]++[\t\n\f\r ]*+=#i', $str) === 0
        ) {
            return $str;
        }

        $length = \strlen($str);
        $whitespace = " \t\n\f\r";
        $budget = 8 * $length + 4096;

        /** @var array<int, array{0: int, 1: int}> $ranges [start, end) offsets of the attributes */
        $ranges = [];

        // bitmap: "\1" at the positions where a scan was in the "before attribute name" state
        $visited = null;

        $tagNameEnd = -1;
        $pos = 0;
        while (($lt = \strpos($str, '<', $pos)) !== false) {
            $pos = $lt + 1;
            if ($pos >= $length) {
                break;
            }

            // "tag open state": only "<" + ASCII letter starts a start tag
            $byte = \ord($str[$pos]);
            if (!(($byte >= 0x41 && $byte <= 0x5A) || ($byte >= 0x61 && $byte <= 0x7A))) {
                continue;
            }

            // a start inside of an already scanned tag name has the same tag name end -> same attributes
            if ($pos < $tagNameEnd) {
                continue;
            }

            // "tag name state"
            $i = $pos + \strcspn($str, $whitespace . '/>', $pos);
            $tagNameEnd = $i;
            $budget -= $i - $pos;

            while ($i < $length) {
                if ($budget < 0 || \count($ranges) > 10000) {
                    return $this->_remove_event_handler_attributes_fail_closed($str);
                }

                // "before attribute name", "self-closing start tag" and "after attribute value (quoted)" state
                //
                // INFO: every scanned byte is charged against the budget (+ 1 per step for the constant work)
                $skipped = \strspn($str, $whitespace . '/', $i);
                $i += $skipped;
                $budget -= $skipped + 1;
                if ($i >= $length || $str[$i] === '>') {
                    break;
                }

                if ($visited === null) {
                    $visited = \str_repeat("\0", $length);
                } elseif ($visited[$i] !== "\0") {
                    // an earlier scan was here in the same state, so it already checked the rest of this tag
                    break;
                }
                $visited[$i] = "\1";

                // "attribute name state" (the first char can be "=")
                $nameStart = $i;
                $i += 1 + \strcspn($str, $whitespace . '/>=', $i + 1);
                $nameLength = $i - $nameStart;

                // "after attribute name state"
                $i += \strspn($str, $whitespace, $i);
                $budget -= $i - $nameStart;
                if ($i >= $length || $str[$i] !== '=') {
                    // no value: the next attribute, "/" or ">" (an event handler without a value does nothing)
                    continue;
                }

                // "before attribute value state"
                $equalsSign = $i;
                ++$i;
                $i += \strspn($str, $whitespace, $i);
                if ($i >= $length) {
                    $valueEnd = $length;
                } elseif ($str[$i] === '"' || $str[$i] === '\'') {
                    // "attribute value (double-quoted / single-quoted) state"
                    $closingQuote = \strpos($str, $str[$i], $i + 1);
                    $valueEnd = $closingQuote === false ? $length : $closingQuote + 1;
                } elseif ($str[$i] === '>') {
                    // missing value: the ">" ends the tag
                    $valueEnd = $i;
                } else {
                    // "attribute value (unquoted) state"
                    $valueEnd = $i + \strcspn($str, $whitespace . '>', $i);
                }
                $budget -= $valueEnd - $equalsSign;
                $i = $valueEnd;

                // INFO: every event handler attribute is "on" + ASCII letters; lookalikes like "on:click",
                //       "on_load" or "on-click" are never executed by a browser, so they are kept
                if (
                    $nameLength > 2
                    &&
                    \substr_compare($str, 'on', $nameStart, 2, true) === 0
                    &&
                    \strspn($str, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', $nameStart + 2, $nameLength - 2) === $nameLength - 2
                    &&
                    !isset($this->_allowed_on_event_attributes[\strtolower((string) \substr($str, $nameStart, $nameLength))])
                ) {
                    $ranges[] = [$nameStart, $valueEnd];
                }
            }
        }

        // INFO: if the budget was exceeded in the last scan, the scan is already done and the result is exact

        if ($ranges === []) {
            return $str;
        }

        // the scans of different starts can find overlapping attributes: remove the union of all ranges
        \usort(
            $ranges,
            static function ($a, $b) {
                return $a[0] <=> $b[0];
            }
        );

        $result = '';
        $offset = 0;
        foreach ($ranges as $range) {
            if ($range[1] <= $offset) {
                continue;
            }

            if ($range[0] >= $offset) {
                $result .= \substr($str, $offset, $range[0] - $offset) . $this->_replacement;
            }
            $offset = $range[1];
        }

        return $result . \substr($str, $offset);
    }

    /**
     * Conservative variant of "_remove_event_handler_attributes()" for inputs that exceed its runtime budget:
     * remove every "on" + ASCII letters + "=" + value after whitespace, "/" or a quote, also outside of tags.
     *
     * <p>
     * <br />
     * INFO: All quantifiers are possessive and the names end at a quote, so the regex runs in linear time. If
     *       PCRE still fails, "_failClosedNeutralize()" is used (the same terminal fallback as everywhere else).
     * </p>
     *
     * @param string $str
     *
     * @return string
     */
    private function _remove_event_handler_attributes_fail_closed($str)
    {
        $allowed = $this->_allowed_on_event_attributes;
        $replacement = $this->_replacement;

        $tmp = \preg_replace_callback(
            '#(?<=[\t\n\f\r /"\'])(on[a-z]++)[\t\n\f\r ]*+=[\t\n\f\r ]*+(?:"[^"]*+"?|\'[^\']*+\'?|[^\t\n\f\r >]*+)#i',
            static function ($matches) use ($allowed, $replacement) {
                return isset($allowed[\strtolower($matches[1])]) ? $matches[0] : $replacement;
            },
            $str
        );

        // INFO: if PCRE fails here, too, use the terminal fallback (no markup at all)
        return $tmp ?? $this->_failClosedNeutralize($str);
    }

    /**
     * Remove Evil HTML Attributes (like event handlers and style).
     *
     * It removes the evil attribute and either:
     *
     *  - Everything up until a space. For example, everything between the pipes:
     *
     * <code>
     *   <a |style=document.write('hello');alert('world');| class=link>
     * </code>
     *
     *  - Everything inside the quotes. For example, everything between the pipes:
     *
     * <code>
     *   <a |style="document.write('hello'); alert('world');"| class="link">
     * </code>
     *
     * @param string $str <p>The string to check.</p>
     *
     * @return string
     *                <p>The string with the evil attributes removed.</p>
     */
    private function _remove_evil_attributes($str)
    {
        if (
            \strpos($str, '<') === false
            ||
            \strpos($str, '=') === false
        ) {
            return $str;
        }

        if ($this->_cache_can_short_circuit_evil_attributes) {
            $hasPossibleEvilAttribute = false;
            foreach ($this->_cache_evil_attributes_quick_checks as $quickCheck) {
                if (\stripos($str, $quickCheck) !== false) {
                    $hasPossibleEvilAttribute = true;

                    break;
                }
            }

            if ($hasPossibleEvilAttribute === false) {
                return $str;
            }
        }

        // replace style-attribute, first (if needed)
        if (
            \stripos($str, 'style') !== false
            &&
            \in_array('style', $this->_evil_attributes_regex, true)
        ) {
            $iterations = 0;
            do {
                $this->_guardAgainstNonConvergingLoop($iterations, __METHOD__);
                $count = $temp_count = 0;

                $tmp = \preg_replace(
                    '/(<[^>]+)(?<!\p{L})(style\s*=\s*"(?:[^"]*?)"|style\s*=\s*\'(?:[^\']*?)\')/iu',
                    '$1' . $this->_replacement,
                    $str,
                    -1,
                    $temp_count
                );
                $str = $tmp ?? $this->_failClosedNeutralize($str);
                $count += $temp_count;
            } while ($count);
        }

        if (!$this->_cache_evil_attributes_regex_string) {
            $this->_cache_evil_attributes_regex_string = \implode('|', $this->_evil_attributes_regex);
            // INFO: the suffix stops at a ":" that starts a new "on..." name, otherwise a long run like
            //       ":onclick:onclick:onclick..." makes every name a match start whose suffix runs to the end
            //       of the run (quadratic backtracking / ReDoS); "onclick:onerror=" is still matched via "onerror"
            $this->_cache_evil_attributes_regex_string .= '|(?<![\w-])(?:' . \implode('|', $this->_never_allowed_on_events_afterwards) . ')(?:[\w-]|:(?!on))*+';
        }

        $iterations = 0;
        do {
            $this->_guardAgainstNonConvergingLoop($iterations, __METHOD__);
            $count = $temp_count = 0;

            // find occurrences of illegal attribute strings with and without quotes (" and ' are octal quotes)
            $strTmp = \preg_replace(
                '/(.*)((?:<[^>]+)(?<!\p{L}))(?:' . $this->_cache_evil_attributes_regex_string . ')(?:\s*=\s*)(?:\'(?:.*?)\'|"(?:.*?)")(.*)/ius',
                '$1$2' . $this->_replacement . '$3',
                $str,
                -1,
                $temp_count
            );
            if ($strTmp === null) {
                $temp_count = 0;
                $strTmp = \preg_replace(
                    '/(?:' . $this->_cache_evil_attributes_regex_string . ')(?:\s*=\s*)(?:\'(?:.*?)\'|"(?:.*?)")/ius',
                    $this->_replacement,
                    $str,
                    -1,
                    $temp_count
                );
            }
            if ($strTmp === null) {
                // both regex attempts failed (e.g. "pcre.backtrack_limit" exhausted): never fall
                // back to the untouched, still-dangerous input ("fail open"); destroy the
                // dangerous attributes with a bounded, non-regex scan instead ("fail closed")
                $strFailClosed = $this->_failClosedRemoveAttributesByName(
                    $str,
                    \array_merge($this->_evil_attributes_regex, $this->_never_allowed_on_events_afterwards)
                );
                $count += ($strFailClosed !== $str) ? 1 : 0;
                $str = $strFailClosed;
            } else {
                $str = $strTmp;
                $count += $temp_count;
            }

            $strTmp = \preg_replace(
                '/(.*?)(<[^>]+)(?<!\p{L})(?:' . $this->_cache_evil_attributes_regex_string . ')\s*=\s*(?:[^\s>]*)/ius',
                '$1$2' . $this->_replacement,
                $str,
                -1,
                $temp_count
            );
            if ($strTmp === null) {
                $temp_count = 0;
                $strTmp = \preg_replace(
                    '/(?<![\p{L}=])(?:' . $this->_cache_evil_attributes_regex_string . ')\s*=\s*(?:[^\s>]*)/ius',
                    $this->_replacement,
                    $str,
                    -1,
                    $temp_count
                );
            }
            if ($strTmp === null) {
                $strFailClosed = $this->_failClosedRemoveAttributesByName(
                    $str,
                    \array_merge($this->_evil_attributes_regex, $this->_never_allowed_on_events_afterwards)
                );
                $count += ($strFailClosed !== $str) ? 1 : 0;
                $str = $strFailClosed;
            } else {
                $str = $strTmp;
                $count += $temp_count;
            }
        } while ($count);

        return (string) $str;
    }

    /**
     * UTF-7 decoding function.
     *
     * @param string $str <p>HTML document for recode ASCII part of UTF-7 back to ASCII.</p>
     *
     * @return string
     */
    private function _repack_utf7($str)
    {
        static $REGEX_FOR_CONTENT = '#\+([\p{L}\d]+)-#iu';

        if (\strpos($str, '-') === false) {
            return $str;
        }

        return $this->_failClosedOnNull(\preg_replace_callback(
            $REGEX_FOR_CONTENT,
            [$this, '_repack_utf7_callback'],
            $str
        ), $str);
    }

    /**
     * Additional UTF-7 decoding function.
     *
     * @param string[] $strings <p>Array of strings for recode ASCII part of UTF-7 back to ASCII.</p>
     *
     * @return string
     */
    private function _repack_utf7_callback($strings)
    {
        $strTmp = \base64_decode($strings[1], true);

        if ($strTmp === false) {
            return $strings[0];
        }

        if (\rtrim(\base64_encode($strTmp), '=') !== \rtrim($strings[1], '=')) {
            return $strings[0];
        }

        $string = (string) \preg_replace_callback(
            '/^((?:\x00.)*?)((?:[^\x00].)+)/us',
            [$this, '_repack_utf7_callback_back'],
            $strTmp
        );

        return (string) \preg_replace(
            '/\x00(.)/us',
            '$1',
            $string
        );
    }

    /**
     * Additional UTF-7 encoding function.
     *
     * @param string[] $matches <p>Matches for recode ASCII part of UTF-7 back to ASCII.</p>
     *
     * @return string
     */
    private function _repack_utf7_callback_back($matches)
    {
        return $matches[1] . '+' . \rtrim(\base64_encode($matches[2]), '=') . '-';
    }

    /**
     * Sanitize naughty HTML elements.
     *
     * <p>
     * <br />
     *
     * If a tag containing any of the words in the list
     * below is found, the tag gets converted to entities.
     *
     * <br /><br />
     *
     * So this: <blink>
     * <br />
     * Becomes: &lt;blink&gt;
     * </p>
     *
     * @param string $str
     *
     * @return string
     */
    private function _sanitize_naughty_html($str)
    {
        // init
        $strEnd = '';

        $iterations = 0;
        do {
            $this->_guardAgainstNonConvergingLoop($iterations, __METHOD__);
            $original = $str;

            if (
                \strpos($str, '<') === false
                &&
                \strpos($str, '>') === false
            ) {
                return $str;
            }

            if (!$this->_cache__evil_html_tags_str) {
                // INFO: longest names first, otherwise e.g. a short name added via "addEvilHtmlTags(['s'])"
                //       would match "<style>" as "s" + "tyle" and the "skip some edge-cases"-check in
                //       "_sanitize_naughty_html_callback()" would keep the tag
                $evilHtmlTags = \array_values(\array_unique($this->_evil_html_tags));
                \usort(
                    $evilHtmlTags,
                    static function ($a, $b) {
                        return \strlen($b) <=> \strlen($a);
                    }
                );
                $this->_cache__evil_html_tags_str = \implode('|', $evilHtmlTags);
            }

            $str = $this->_failClosedOnNull(\preg_replace_callback(
                // INFO: "rest" must not consume the "<" of a following tag (e.g. "<header><style>"), otherwise
                //       that tag is skipped by this pass
                //
                // INFO: "prefix" -> XML namespace prefix (e.g. "<x:script>"), that is a real "script"-element on
                //       XHTML pages (application/xhtml+xml), if "x" is bound to the XHTML namespace
                '#<(?<start>/*\s*)(?<prefix>(?:[\p{L}_][\p{L}\p{N}_.-]*+:)?)(?<tagName>' . $this->_cache__evil_html_tags_str . ')(?<end>[^><]*)(?<rest>>*+(?:<(?![\p{L}/!?])>*+)*+)#ius',
                [$this, '_sanitize_naughty_html_callback'],
                $str
            ), $str);

            if (\strpos($str, '<') === false) {
                return $str;
            }

            if (
                $this->_xss_found
                &&
                \trim($str) === '<'
            ) {
                return '';
            }

            $str = $this->_failClosedOnNull(\preg_replace_callback(
                '#<(?!!--|!\[)((?<start>/*\s*)((?<tagName>[\p{L}:]+)(?=[^\p{L}]|$|)|.+)[^\s"\'\p{L}>/=]*[^>]*)(?<closeTag>>)?#iusS', // tags without comments
                function ($matches) {
                    if (
                        $this->_do_not_close_html_tags !== []
                        &&
                        isset($matches['tagName'])
                        &&
                        \in_array($matches['tagName'], $this->_do_not_close_html_tags, true)
                    ) {
                        return $matches[0];
                    }

                    return $this->_close_html_callback($matches);
                },
                $str
            ), $str);

            if ($str === $strEnd) {
                return (string) $str;
            }

            $strEnd = $str;
        } while ($original !== $str);

        return (string) $str;
    }

    /**
     * @param string[] $matches
     *
     * @return string
     */
    private function _close_html_callback($matches)
    {
        if (empty($matches['closeTag'])) {
            // allow e.g. "< $2.20" and e.g. "< 1 year" and e.g. "< 35kg Gross" and e.g. "< subject1"
            if (\preg_match('/^[ .,\d=%€$₢₣£₤₶ℳ₥₦₧₨රුரூ௹रू₹૱₩₪₸₫֏₭₺₼₮₯₰₷₱﷼₲₾₳₴₽₵₡¢¥円৳元៛₠¤฿؋]*$|^[ .,\d=%€$₢₣£₤₶ℳ₥₦₧₨රුரூ௹रू₹૱₩₪₸₫֏₭₺₼₮₯₰₷₱﷼₲₾₳₴₽₵₡¢¥円৳元៛₠¤฿؋]+[\p{L}\d\s]*$/u', $matches[1])) {
                return '<' . \str_replace(['>', '<'], ['&gt;', '&lt;'], $matches[1]);
            }

            return '&lt;' . \str_replace(['>', '<'], ['&gt;', '&lt;'], $matches[1]);
        }

        return '<' . \str_replace(['>', '<'], ['&gt;', '&lt;'], $matches[1]) . '>';
    }

    /**
     * Sanitize naughty HTML.
     *
     * <p>
     * <br />
     * Callback method for AntiXSS->sanitize_naughty_html() to remove naughty HTML elements.
     * </p>
     *
     * @param string[] $matches
     *
     * @return string
     */
    private function _sanitize_naughty_html_callback($matches)
    {
        // init
        $fullMatch = $matches[0];

        // A tag with an XML namespace prefix (e.g. "<x:script>") is only an XHTML element, if the local name
        // is exactly the (lowercase) element name: XML names are case-sensitive and end at a non-name char.
        // So e.g. "<o:Title>" (Word), "<x:Selected/>" or "<x:Header>" (Excel) are no evil tags.
        if (
            ($matches['prefix'] ?? '') !== ''
            &&
            (
                !\in_array($matches['tagName'], $this->_evil_html_tags, true)
                ||
                \preg_match('/^[\p{L}\p{N}_.:-]/u', $matches['end']) === 1
            )
        ) {
            return $fullMatch;
        }

        // skip some edge-cases
        /** @noinspection NotOptimalIfConditionsInspection */
        if (
            (
                \strpos($fullMatch, '=') === false
                &&
                \preg_match('/\s/', $fullMatch) === 0
                &&
                \strpos($fullMatch, ':') === false
                &&
                \strpos($fullMatch, '/') === false
                &&
                \strpos($fullMatch, '\\') === false
                &&
                \stripos($fullMatch, '<' . $matches['tagName'] . '>') !== 0
                &&
                \stripos($fullMatch, '</' . $matches['tagName'] . '>') !== 0
                &&
                \stripos($fullMatch, '<' . $matches['tagName'] . '<') !== 0
            )
            ||
            \preg_match('/<\/?' . $matches['tagName'] . '\p{L}+>/ius', $fullMatch) === 1
        ) {
            return $fullMatch;
        }

        return '&lt;' . $matches['start'] . ($matches['prefix'] ?? '') . $matches['tagName'] . $matches['end'] // encode opening brace
               // encode captured opening or closing brace to prevent recursive vectors
               . \str_replace(
                   [
                       '>',
                   ],
                   [
                       '&gt;',
                   ],
                   $matches['rest']
               );
    }

    /**
     * Sanitize naughty scripting elements
     *
     * <p>
     * <br />
     *
     * Similar to above, only instead of looking for
     * tags it looks for PHP and JavaScript commands
     * that are disallowed. Rather than removing the
     * code, it simply converts the parenthesis to entities
     * rendering the code un-executable.
     *
     * <br /><br />
     *
     * For example:  <pre>eval('some code')</pre>
     * <br />
     * Becomes:      <pre>eval&#40;'some code'&#41;</pre>
     * </p>
     *
     * @param string $str
     *
     * @return string
     */
    private function _sanitize_naughty_javascript($str)
    {
        if (\strpos($str, '(') !== false) {
            // Pass 1 – JS-specific keywords: match even when whitespace separates the keyword from "(".
            $found = false;
            foreach ($this->_naughty_javascript_patterns as $pattern) {
                if (\strpos($str, $pattern) !== false) {
                    $found = true;

                    break;
                }
            }

            if ($found === true) {
                $str = $this->_failClosedOnNull(\preg_replace(
                    '#(?<!\p{L})(' . \implode('|', $this->_naughty_javascript_patterns) . ')(\s*)\((.*)\)#uisU',
                    '\\1\\2&#40;\\3&#41;',
                    $str
                ), $str);
            }

            // Pass 2 – English-word keywords: only match when "(" follows immediately (no whitespace),
            // to avoid false positives such as "operating system (Linux)" or "file (attachment)".
            $found = false;
            foreach ($this->_naughty_javascript_patterns_strict as $pattern) {
                if (\strpos($str, $pattern) !== false) {
                    $found = true;

                    break;
                }
            }

            if ($found === true) {
                $str = $this->_failClosedOnNull(\preg_replace(
                    '#(?<!\p{L})(' . \implode('|', $this->_naughty_javascript_patterns_strict) . ')\((.*)\)#uisU',
                    '\\1&#40;\\2&#41;',
                    $str
                ), $str);
            }
        }

        return (string) $str;
    }

    /**
     * Add some strings to the "_evil_attributes"-array.
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function addEvilAttributes(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        // reset
        $this->_cache_evil_attributes_regex_string = '';

        $this->_evil_attributes_regex = \array_merge(
            $strings,
            $this->_evil_attributes_regex
        );

        $this->_rebuildEvilAttributesQuickChecksCache();

        return $this;
    }

    /**
     * Add some strings to the "_evil_html_tags"-array.
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function addEvilHtmlTags(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        // reset
        $this->_cache__evil_html_tags_str = '';

        $this->_evil_html_tags = \array_merge(
            $strings,
            $this->_evil_html_tags
        );

        return $this;
    }

    /**
     * Add some strings to the "_never_allowed_regex"-array.
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function addNeverAllowedRegex(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        $this->_never_allowed_regex = \array_merge(
            $strings,
            $this->_never_allowed_regex
        );

        $this->_rebuildNeverAllowedRegexCache();

        return $this;
    }

    /**
     * Remove some strings from the "_never_allowed_regex"-array.
     *
     * <p>
     * <br />
     * WARNING: Use this method only if you have a really good reason.
     * </p>
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function removeNeverAllowedRegex(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        // INFO: the regex is the key, the value is only the replacement (and the same for most of the regexes),
        //       so ['regex' => 'replacement'] (like for "addNeverAllowedRegex()") removes only "regex"
        //       and not every other regex with the same replacement
        foreach ($strings as $key => $value) {
            if (\is_string($key)) {
                unset($this->_never_allowed_regex[$key]);

                continue;
            }

            if (isset($this->_never_allowed_regex[$value])) {
                unset($this->_never_allowed_regex[$value]);

                continue;
            }

            // BC: a list of replacements
            $this->_never_allowed_regex = \array_filter(
                $this->_never_allowed_regex,
                static function ($replacement) use ($value) {
                    return $replacement !== $value;
                }
            );
        }

        $this->_rebuildNeverAllowedRegexCache();

        return $this;
    }

    /**
     * Add some strings to the "_never_allowed_on_events_afterwards"-array.
     *
     * <p>
     * <br />
     * INFO: You don't need this for new browser events: every attribute "on" + ASCII letters (e.g. "onclick", but
     *       also "ongesturestart" or a future event) is removed anyway. Use it for other names, or to disallow an
     *       event again, that was allowed via "removeNeverAllowedOnEventsAfterwards()".
     * </p>
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function addNeverAllowedOnEventsAfterwards(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        // reset
        $this->_cache_evil_attributes_regex_string = '';
        $this->_resetNeverAllowedOnEventsAfterwardsCache();

        $this->_never_allowed_on_events_afterwards = \array_merge(
            $strings,
            $this->_never_allowed_on_events_afterwards
        );

        foreach ($strings as $string) {
            unset($this->_allowed_on_event_attributes[\strtolower($string)]);
        }

        $this->_rebuildEvilAttributesQuickChecksCache();

        return $this;
    }

    /**
     * Add some strings to the "_never_allowed_str_afterwards"-array.
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function addNeverAllowedStrAfterwards(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        $this->_never_allowed_str_afterwards = \array_merge(
            $strings,
            $this->_never_allowed_str_afterwards
        );

        return $this;
    }

    /**
     * Add some strings to the "_do_not_close_html_tags"-array.
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function addDoNotCloseHtmlTags(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        $this->_do_not_close_html_tags = \array_merge(
            $strings,
            $this->_do_not_close_html_tags
        );

        return $this;
    }

    /**
     * Add some strings to the "_never_allowed_js_callback_regex"-array.
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function addNeverAllowedJsCallbackRegex(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        $this->_never_allowed_js_callback_regex = \array_merge(
            $strings,
            $this->_never_allowed_js_callback_regex
        );

        return $this;
    }
    
    /**
     * Add some strings to the "_never_allowed_call_strings"-array.
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function addNeverAllowedCallStrings(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        $this->_never_allowed_call_strings = \array_merge(
            $strings,
            $this->_never_allowed_call_strings
        );

        return $this;
    }

    /**
     * Remove some strings from the "_do_not_close_html_tags"-array.
     *
     * <p>
     * <br />
     * WARNING: Use this method only if you have a really good reason.
     * </p>
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function removeDoNotCloseHtmlTags(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        $this->_do_not_close_html_tags = \array_diff(
            $this->_do_not_close_html_tags,
            \array_intersect($strings, $this->_do_not_close_html_tags)
        );

        return $this;
    }

    /**
     * Add some strings to the "_naughty_javascript_patterns"-array.
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function addNaughtyJavascriptPatterns(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        $this->_naughty_javascript_patterns = \array_merge(
            $strings,
            $this->_naughty_javascript_patterns
        );

        return $this;
    }

    /**
     * Check if the "AntiXSS->xss_clean()"-method found an XSS attack in the last run.
     *
     * @return bool|null
     *                   <p>Will return null if the "xss_clean()" wasn't running at all.</p>
     */
    public function isXssFound()
    {
        return $this->_xss_found;
    }

    /**
     * Remove some strings from the "_evil_attributes"-array.
     *
     * <p>
     * <br />
     * WARNING: Use this method only if you have a really good reason.
     * </p>
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function removeEvilAttributes(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        // reset
        $this->_cache_evil_attributes_regex_string = '';

        $this->_evil_attributes_regex = \array_diff(
            $this->_evil_attributes_regex,
            \array_intersect($strings, $this->_evil_attributes_regex)
        );

        $this->_rebuildEvilAttributesQuickChecksCache();

        return $this;
    }

    /**
     * Remove some strings from the "_evil_html_tags"-array.
     *
     * <p>
     * <br />
     * WARNING: Use this method only if you have a really good reason.
     * </p>
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function removeEvilHtmlTags(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        // reset
        $this->_cache__evil_html_tags_str = '';

        $this->_evil_html_tags = \array_diff(
            $this->_evil_html_tags,
            \array_intersect($strings, $this->_evil_html_tags)
        );

        return $this;
    }

    /**
     * Remove some strings from the "_never_allowed_on_events_afterwards"-array.
     *
     * <p>
     * <br />
     * WARNING: Use this method only if you have a really good reason.
     * <br />
     * INFO: A removed event (e.g. "onAbort") is also allowed as an attribute ("onabort=..."), only names that
     *       are on the list can be allowed. All other "on" + ASCII letters attributes are always removed.
     * </p>
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function removeNeverAllowedOnEventsAfterwards(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        // reset
        $this->_cache_evil_attributes_regex_string = '';
        $this->_resetNeverAllowedOnEventsAfterwardsCache();

        $removed = \array_intersect($strings, $this->_never_allowed_on_events_afterwards);

        $this->_never_allowed_on_events_afterwards = \array_diff(
            $this->_never_allowed_on_events_afterwards,
            $removed
        );

        // INFO: also keep these event handler attributes in "_remove_event_handler_attributes()"
        foreach ($removed as $string) {
            $this->_allowed_on_event_attributes[\strtolower($string)] = true;
        }

        $this->_rebuildEvilAttributesQuickChecksCache();

        return $this;
    }

    /**
     * Remove some strings from the "_never_allowed_str_afterwards"-array.
     *
     * <p>
     * <br />
     * WARNING: Use this method only if you have a really good reason.
     * </p>
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function removeNeverAllowedStrAfterwards(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        $this->_never_allowed_str_afterwards = \array_diff(
            $this->_never_allowed_str_afterwards,
            \array_intersect($strings, $this->_never_allowed_str_afterwards)
        );

        return $this;
    }

    /**
     * Remove some strings from the "_never_allowed_call_strings"-array.
     *
     * <p>
     * <br />
     * WARNING: Use this method only if you have a really good reason.
     * </p>
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function removeNeverAllowedCallStrings(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        $this->_never_allowed_call_strings = \array_diff(
            $this->_never_allowed_call_strings,
            \array_intersect($strings, $this->_never_allowed_call_strings)
        );

        return $this;
    }

    /**
     * Remove some strings from the "_never_allowed_js_callback_regex"-array.
     *
     * <p>
     * <br />
     * WARNING: Use this method only if you have a really good reason.
     * </p>
     *
     * @param string[] $strings
     *
     * @return $this
     */
    public function removeNeverAllowedJsCallbackRegex(array $strings): self
    {
        if ($strings === []) {
            return $this;
        }

        $this->_never_allowed_js_callback_regex = \array_diff(
            $this->_never_allowed_js_callback_regex,
            \array_intersect($strings, $this->_never_allowed_js_callback_regex)
        );

        return $this;
    }

    /**
     * Set the replacement-string for not allowed strings.
     *
     * @param string $string
     *
     * @return $this
     */
    public function setReplacement($string): self
    {
        $defaultNeverAllowedRegex = $this->_getDefaultNeverAllowedRegex($this->_replacement);
        $customNeverAllowedRegex = \array_diff_key($this->_never_allowed_regex, $defaultNeverAllowedRegex);
        $removedNeverAllowedRegex = \array_diff_key($defaultNeverAllowedRegex, $this->_never_allowed_regex);

        $this->_replacement = (string) $string;

        $this->_initNeverAllowedStr();
        $this->_initNeverAllowedRegex();

        if ($removedNeverAllowedRegex !== []) {
            $this->_never_allowed_regex = \array_diff_key($this->_never_allowed_regex, $removedNeverAllowedRegex);
        }

        if ($customNeverAllowedRegex !== []) {
            $this->_never_allowed_regex = \array_merge(
                $customNeverAllowedRegex,
                $this->_never_allowed_regex
            );
        }

        if ($removedNeverAllowedRegex !== [] || $customNeverAllowedRegex !== []) {
            $this->_rebuildNeverAllowedRegexCache();
        }

        return $this;
    }

    /**
     * Set the option to preserve content inside "pre" and "code" tags.
     *
     * <p>
     * <br />
     * WARNING: Enable this only if you explicitly want literal code-like text in "pre" / "code" blocks to remain untouched.
     * </p>
     *
     * @param bool $bool
     *
     * @return $this
     */
    public function setKeepPreAndCodeTagContent($bool): self
    {
        $this->_keep_pre_and_code_tag_content = (bool) $bool;

        return $this;
    }

    /**
     * Set the option to stripe 4-Byte chars.
     *
     * <p>
     * <br />
     * INFO: use it if your DB (MySQL) can't use "utf8mb4" -> preventing stored XSS-attacks
     * </p>
     *
     * @param bool $bool
     *
     * @return $this
     */
    public function setStripe4byteChars($bool): self
    {
        $this->_stripe_4byte_chars = (bool) $bool;

        return $this;
    }

    /**
     * XSS Clean
     *
     * <p>
     * <br />
     * Sanitizes data so that "Cross Site Scripting" hacks can be
     * prevented. This method does a fair amount of work but
     * it is extremely thorough, designed to prevent even the
     * most obscure XSS attempts. But keep in mind that nothing
     * is ever 100% foolproof...
     * </p>
     *
     * <p>
     * <br />
     * <strong>Note:</strong> Should only be used to deal with data upon submission.
     *   It's not something that should be used for general
     *   runtime processing.
     * </p>
     *
     * @see http://channel.bitflux.ch/wiki/XSS_Prevention
     *    Based in part on some code and ideas from Bitflux.
     * @see http://ha.ckers.org/xss.html
     *    To help develop this script I used this great list of
     *    vulnerabilities along with a few other hacks I've
     *    harvested from examining vulnerabilities in other programs.
     *
     * @param string|string[] $str
     *                             <p>input data e.g. string or array of strings</p>
     *
     * @return string|string[]
     *
     * @phpstan-param string|string[] $str
     * @phpstan-return ($str is string ? string : string[])
     */
    public function xss_clean($str)
    {
        // reset
        $this->_xss_found = null;

        // check for an array of strings
        if (\is_array($str)) {
            foreach ($str as &$value) {
                /* @phpstan-ignore-next-line | _xss_found is maybe changed via "xss_clean" */
                if ($this->_xss_found === true) {
                    $alreadyFoundXss = true;
                } else {
                    $alreadyFoundXss = false;
                }
                
                $value = $this->xss_clean($value);

                /* @phpstan-ignore-next-line | _xss_found is maybe changed via "xss_clean" */
                if ($alreadyFoundXss === true) {
                    $this->_xss_found = true;
                }
            }

            return $str;
        }

        $old_str_backup = $str;

        // process
        $iterations = 0;
        do {
            $this->_guardAgainstNonConvergingLoop($iterations, __METHOD__);
            $old_str = $str;
            $str = $this->_do($str);
        } while ($old_str !== $str);

        // A raw ESC byte is removed by the cleaning above, but on pages decoded as ISO-2022-JP the browser
        // also drops its escape sequences ("ESC ( B", "ESC ( J", "ESC ( I", "ESC $ @", "ESC $ B"), so that e.g.
        // "<scr\x1B(Bipt>" becomes "<script>" there. So we must not return the original (unchecked) bytes in
        // this case. Other ESC sequences (e.g. ANSI colors "ESC [ 32 m") are shown as U+FFFD, so they are kept.
        if (
            \strpos((string) $old_str_backup, "\x1B") !== false
            &&
            \preg_match('/\x1B[($]/', (string) $old_str_backup) !== 0
        ) {
            $this->_xss_found = true;
        }

        // keep the old value, if there wasn't any XSS attack
        if ($this->isXssFound() !== true) {
            $str = $old_str_backup;
        }

        return $str;
    }
}
