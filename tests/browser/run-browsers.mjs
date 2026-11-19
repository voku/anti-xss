// Run a generated browser fixture in Chromium, Firefox or WebKit (Playwright, dev-only - not a dependency of the
// library) and check the verdict that the fixture's own script writes into <body data-*>.
//
// Usage: node tests/browser/run-browsers.mjs <chromium|firefox|webkit> <fixture.html> <prefix> <pass|fail|detected>
//
//   prefix:   the dataset prefix of the fixture ("events" for event-handler-attributes.php, "ghsa" for the GHSA ones)
//   pass:     sanitized output - status "pass" and nothing executed
//   fail:     unsanitized negative control - status "fail" and the payload really executed in this engine
//   detected: unsanitized negative control with payloads that this engine does not execute (e.g. Chromium-only
//             events like "onvalidationstatuschange" in Firefox / WebKit) - status "fail", no execution required
import { chromium, firefox, webkit } from 'playwright';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const [engineName, file, prefix, expectation] = process.argv.slice(2);
const engines = { chromium, firefox, webkit };

if (!engines[engineName] || !file || !prefix || !['pass', 'fail', 'detected'].includes(expectation)) {
    console.error('Usage: node run-browsers.mjs <chromium|firefox|webkit> <fixture.html> <prefix> <pass|fail|detected>');
    process.exit(2);
}

const browser = await engines[engineName].launch();
try {
    const page = await browser.newPage();
    await page.goto(pathToFileURL(resolve(file)).href);

    const statusKey = prefix + 'Status';
    await page.waitForFunction((key) => document.body && document.body.dataset[key] !== undefined, statusKey, {
        timeout: 60000,
    });
    // let handlers that are triggered asynchronously (e.g. image errors, focus) run
    await page.waitForTimeout(1000);

    const dataset = await page.evaluate(() => Object.assign({}, document.body.dataset));
    const status = dataset[statusKey];
    const executed = dataset[prefix + 'Executed'] === 'true'
        || (await page.evaluate(() => window.__xssExecuted === true));

    const summary = Object.fromEntries(
        Object.entries(dataset)
            .filter(([key]) => key.startsWith(prefix))
            .map(([key, value]) => [key, value.length > 300 ? value.slice(0, 300) + '...' : value])
    );
    console.log(engineName + ' ' + browser.version() + ' ' + file + ': ' + JSON.stringify(summary));

    const ok = expectation === 'pass'
        ? status === 'pass' && !executed
        : status === 'fail' && (executed || expectation === 'detected');
    if (!ok) {
        console.error('::error::' + engineName + ': expected "' + expectation + '" for ' + file
            + ', got status "' + status + '", executed: ' + executed);
        process.exitCode = 1;
    }
} finally {
    await browser.close();
}
