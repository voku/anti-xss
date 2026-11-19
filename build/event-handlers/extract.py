#!/usr/bin/env python3
"""
Regenerate "tests/fixtures/browser-event-handlers.txt": every event handler name ("on" + event type) that a spec or a
browser engine knows, from pinned upstream revisions (reproducible).

This list is a *test resource*: "EventHandlerAttributeTest" checks that every name is removed by "xss_clean()",
also without the runtime list. The runtime filter removes every "on" + ASCII letters attribute, so a new name here
means new test coverage, not a missing runtime entry.

Usage (downloads ~1 MB, needs network access to registry.npmjs.org and raw.githubusercontent.com):

    python3 -I build/event-handlers/extract.py            # check: exit 1, if the fixture is not up to date
    python3 -I build/event-handlers/extract.py --write    # rewrite the fixture

To update the sources, change the pinned revisions / versions below and remove the "sha256" values; the script
prints the new hashes.
"""
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request

WEBKIT = 'd32db58b902c7cc8d8ef940524b752b514911680'
CHROMIUM = '2bcfe1515f03079a8b5cc6b4d503011649bd7bd2'
GECKO_DEV = '5836a062726f715fda621338a17b51aff30d0a8c'  # read-only mirror of mozilla-central
WEBREF_IDL = '3.87.0'
WEBREF_EVENTS = '1.28.0'

SOURCES = {
    'webkit_html': ('https://raw.githubusercontent.com/WebKit/WebKit/%s/Source/WebCore/html/HTMLAttributeNames.in' % WEBKIT, '99cc8b81a53bb2f88e057d6aa0e9168b8054bbb06760dfd76d19ee8a769f92b4'),
    'webkit_svg': ('https://raw.githubusercontent.com/WebKit/WebKit/%s/Source/WebCore/svg/svgattrs.in' % WEBKIT, '96d68d3ceb2fb4a6872c6f7df405b229acdecca9b2dda8bdc17d6b74a1b81709'),
    'webkit_events': ('https://raw.githubusercontent.com/WebKit/WebKit/%s/Source/WebCore/dom/EventNames.json' % WEBKIT, 'd291adcb9dd6f1d09a3e0989c21ca9afa7cb44f77846c720beccb71109105b4c'),
    'blink_html': ('https://raw.githubusercontent.com/chromium/chromium/%s/third_party/blink/renderer/core/html/html_attribute_names.json5' % CHROMIUM, 'fa3d3fd7f8a1ed967271dc4c22fb6f4761c916bce4528fafccdaa7e0a8a2359f'),
    'blink_svg': ('https://raw.githubusercontent.com/chromium/chromium/%s/third_party/blink/renderer/core/svg/svg_attribute_names.json5' % CHROMIUM, '5feef1efe9af0b3c0c08d50e0da90f5de3ee426b22684987160e43d3ea280bbd'),
    'blink_events': ('https://raw.githubusercontent.com/chromium/chromium/%s/third_party/blink/renderer/core/events/event_type_names.json5' % CHROMIUM, 'bd8756981c8eb95404d247517f543cc92430b072448b43e650fa666de06a500f'),
    'gecko_events': ('https://raw.githubusercontent.com/mozilla/gecko-dev/%s/dom/events/EventNameList.h' % GECKO_DEV, '36686fff986a8a5fdcf5deaf28e4d6dc8289a4075fd92d5b0894ace8336c2c10'),
    'webref_idl': ('https://registry.npmjs.org/@webref/idl/-/idl-%s.tgz' % WEBREF_IDL, 'd9161a8e123292ea56db15105583820f9d1f631b7b0c50a005e91023e745f446'),
    'webref_events': ('https://registry.npmjs.org/@webref/events/-/events-%s.tgz' % WEBREF_EVENTS, 'b2753a65b99ad6225ff2060f726e50f9ab5ad2b75a5b50cd49307d8529f6363a'),
}

FIXTURE = 'tests/fixtures/browser-event-handlers.txt'

# entries of "event_type_names.json5" that are no event names
BLINK_NON_EVENTS = {'core_export', 'event_type_names'}


def fetch(key):
    url, expected = SOURCES[key]
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if expected is not None and digest != expected:
        sys.exit('%s: sha256 %s != pinned %s (%s)' % (key, digest, expected, url))
    print('%-14s sha256=%s' % (key, digest), file=sys.stderr)
    return data


def tar_members(data, suffix):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith(suffix):
                yield member.name, tar.extractfile(member).read().decode('utf-8')


def main():
    names = {}
    # names that start with "on", but are not "on" + ASCII letters: the runtime rule of "_remove_event_handler_attributes()"
    # ignores them, so they are listed in the fixture, to make a new one (= a possibly wrong assumption) visible
    excluded = {}

    def add(source, name):
        if re.fullmatch(r'on[A-Za-z]+', name):
            names.setdefault(name.lower(), set()).add(source)
        elif re.fullmatch(r'on\S+', name):
            excluded.setdefault(name.lower(), set()).add(source)

    for _, idl in tar_members(fetch('webref_idl'), '.idl'):
        for m in re.finditer(r'attribute\s+(?:EventHandler|OnErrorEventHandler|OnBeforeUnloadEventHandler)\??\s+(on\w+)', idl):
            add('spec-idl', m.group(1))
    for _, text in tar_members(fetch('webref_events'), 'events.json'):
        for event in json.loads(text):
            add('spec-events', 'on' + event['type'])

    for key in ('webkit_html', 'webkit_svg'):
        for line in fetch(key).decode('utf-8').splitlines():
            if line.split():
                add('webkit-attr', line.split()[0])
    for event in json.loads(fetch('webkit_events').decode('utf-8')):
        add('webkit-event', 'on' + event)

    for key in ('blink_html', 'blink_svg'):
        for m in re.finditer(r'"(on[\w-]+)"', fetch(key).decode('utf-8')):
            add('blink-attr', m.group(1))
    for m in re.finditer(r'"([\w-]+)"', fetch('blink_events').decode('utf-8')):
        if m.group(1).lower() not in BLINK_NON_EVENTS:
            add('blink-event', 'on' + m.group(1))

    for m in re.finditer(r'^\s*\w*EVENT\((\w+),', fetch('gecko_events').decode('utf-8'), re.M):
        if m.group(1) != '_name':
            add('gecko-event', 'on' + m.group(1))

    header = '''# Event handler names ("on" + event type) known to browsers and specs (%d names).
# Every name in this file must be removed by "xss_clean()" (see "EventHandlerAttributeTest").
# Generated by "build/event-handlers/extract.py" (pinned upstream revisions, see there) - do not edit by hand.
#
# Sources (union, lowercased):
# - spec-idl:    WebIDL "EventHandler" attributes from all W3C / WHATWG specs (npm "@webref/idl" %s)
# - spec-events: event types defined in all W3C / WHATWG specs (npm "@webref/events" %s)
# - webkit:      Source/WebCore/html/HTMLAttributeNames.in, svg/svgattrs.in, dom/EventNames.json (WebKit %s)
# - blink:       core/html/html_attribute_names.json5, core/svg/svg_attribute_names.json5, core/events/event_type_names.json5 (Chromium %s)
# - gecko:       dom/events/EventNameList.h (mozilla/gecko-dev %s)
#
# Excluded (start with "on", but are not "on" + ASCII letters, so the runtime rule does not remove them; a new
# entry here means that the assumption "every event handler is 'on' + ASCII letters" must be checked again):
%s#
# Format: <name> <sources>
''' % (len(names), WEBREF_IDL, WEBREF_EVENTS, WEBKIT[:12], CHROMIUM[:12], GECKO_DEV[:12],
       ''.join('#   %s %s\n' % (name, ','.join(sorted({s.split(':')[0] for s in sources}))) for name, sources in sorted(excluded.items())) or '#   (none)\n')

    content = header + ''.join(
        '%s %s\n' % (name, ','.join(sorted({s.split(':')[0] for s in sources})))
        for name, sources in sorted(names.items())
    )

    if '--write' in sys.argv:
        with open(FIXTURE, 'w', encoding='utf-8') as f:
            f.write(content)
        print('wrote %s (%d names)' % (FIXTURE, len(names)), file=sys.stderr)
        return 0

    with open(FIXTURE, encoding='utf-8') as f:
        current = f.read()
    if current != content:
        old = {l.split(' ')[0] for l in current.splitlines() if l and not l.startswith('#')}
        print('fixture is not up to date: new names: %s, removed names: %s' % (
            sorted(set(names) - old), sorted(old - set(names))), file=sys.stderr)
        return 1
    print('fixture is up to date (%d names)' % len(names), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
