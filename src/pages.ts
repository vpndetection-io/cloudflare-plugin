import { VERIFY_PATH } from './challenge.js';

const DOCS = 'https://docs.vpndetection.io/integrations/cloudflare';

// How a refusal names each signal, and whether it is something the visitor can turn off.
const LABELS: Record<string, { phrase: string; off: boolean }> = {
    vpn: { phrase: 'through a VPN', off: true },
    tor: { phrase: 'through Tor', off: true },
    pubproxy: { phrase: 'through a proxy', off: true },
    resproxy: { phrase: 'through a proxy', off: true },
    mobproxy: { phrase: 'through a proxy', off: true },
    dcproxy: { phrase: 'through a proxy', off: true },
    relay: { phrase: 'through a privacy relay such as iCloud Private Relay', off: true },
    hosting: { phrase: 'from a hosting or cloud network', off: false },
    smtp: { phrase: 'from a mail server', off: false },
};

/** The refusal: a page for a browser, a line of JSON for anything else. */
export function refusal(request: Request, ip: string | undefined, signals: string[], message?: string): Response {
    const text = message ?? defaultMessage(signals);
    if (!wantsHtml(request)) {
        return Response.json({ error: 'access denied' }, { status: 403, headers: noStore() });
    }
    const body = `<h1>Access denied</h1>
<p>${esc(text)}</p>
${details(request, ip)}`;
    return html(403, 'Access denied', body);
}

/**
 * The Turnstile check for a visitor who matched, which posts its token back to the Worker. `retryBack`
 * is the page to return to after a check that failed, which shows the check again.
 */
export function challengePage(
    request: Request, ip: string | undefined, siteKey: string, retryBack?: string,
): Response {
    const navigation = request.method === 'GET' || request.method === 'HEAD' || retryBack !== undefined;
    if (!wantsHtml(request) || !navigation) {
        return Response.json({ error: 'challenge required' }, { status: 403, headers: noStore() });
    }
    const url = new URL(request.url);
    const back = retryBack ?? `${url.pathname}${url.search}`;
    const retry = retryBack === undefined ? '' : '<p><strong>That check didn\'t pass. Try again.</strong></p>';
    const body = `<h1>Checking your connection</h1>
<p>Your connection comes through a VPN, a proxy or a similar network, so this site asks you to confirm
you're a person before you go on.</p>
${retry}
<form method="POST" action="${VERIFY_PATH}" id="check">
<input type="hidden" name="return" value="${esc(back)}">
<div class="cf-turnstile" data-sitekey="${esc(siteKey)}" data-callback="passed"></div>
<noscript><p>Turn on JavaScript to continue.</p></noscript>
</form>
${details(request, ip)}
<script>function passed() { document.getElementById('check').submit(); }</script>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`;
    return html(403, 'Checking your connection', body);
}

export interface SetupReport {
    problems: string[];
    plan?: string;
    keyError?: string;
    ip?: string;
    signals?: string[];
    outcome?: string;
}

/**
 * The page the Worker answers on its own workers.dev address and in local development, where no site
 * stands behind it: whether its key and settings work, and what it makes of the reader.
 */
export function setupPage(report: SetupReport): Response {
    const rows: string[] = [];
    if (report.problems.length > 0) {
        rows.push(`<h2>Settings</h2>
<p>These settings are wrong, so the Worker checks no one until they're fixed:</p>
<ul>${report.problems.map((p) => `<li><code>${esc(p)}</code></li>`).join('')}</ul>`);
    } else {
        const key = report.keyError === undefined
            ? `Accepted, on the ${esc(report.plan ?? 'unknown')} plan.`
            : `Not working: ${esc(report.keyError)}.`;
        const signals = report.signals === undefined || report.signals.length === 0
            ? 'nothing the Worker acts on'
            : esc(report.signals.join(', '));
        rows.push(`<h2>API key</h2><p>${key}</p>
<h2>Your connection</h2>
<p>Your address, <code>${esc(report.ip ?? 'unknown')}</code>, matched ${signals}, so on your site
the Worker would ${esc(report.outcome ?? 'let you through')}.</p>`);
    }
    const body = `<h1>VPNDetection is running</h1>
${rows.join('\n')}
<h2>Next</h2>
<p>This address has no site behind it. Add a route for your site under Settings &gt; Domains &amp; Routes, and the
Worker checks every visitor to it. <a href="${DOCS}">The guide</a> has every step.</p>`;
    return html(200, 'VPNDetection is running', body);
}

function defaultMessage(signals: string[]): string {
    if (signals.includes('unavailable')) {
        return 'This site couldn\'t check your connection just now. Try again in a minute.';
    }
    const labels = signals.map((s) => LABELS[s]).filter((l) => l !== undefined);
    if (labels.length === 0) {
        return 'This site doesn\'t accept connections from the network you\'re on.';
    }
    const off = labels.some((l) => l.off) ? ' Turn it off and reload the page.' : '';
    return `This site doesn't accept connections ${joinOr([...new Set(labels.map((l) => l.phrase))])}.${off}`;
}

function joinOr(items: string[]): string {
    if (items.length <= 1) {
        return items.join('');
    }
    return `${items.slice(0, -1).join(', ')} or ${items[items.length - 1]}`;
}

function details(request: Request, ip: string | undefined): string {
    const ray = request.headers.get('CF-Ray');
    const lines = [
        ip === undefined ? '' : `Your IP address: <code>${esc(ip)}</code>`,
        ray === null ? '' : `Ray ID: <code>${esc(ray)}</code>`,
    ].filter((l) => l !== '');
    return lines.length === 0 ? '' : `<p class="details">${lines.join('<br>')}</p>`;
}

function wantsHtml(request: Request): boolean {
    return (request.headers.get('Accept') ?? '').includes('text/html');
}

function noStore(): Record<string, string> {
    return { 'Cache-Control': 'no-store' };
}

function html(status: number, title: string, body: string): Response {
    const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(title)}</title>
<style>
:root { color-scheme: light dark; --fg: #1b1f24; --muted: #5b6470; --bg: #ffffff; --line: #d9dee4; }
@media (prefers-color-scheme: dark) { :root { --fg: #e6e9ed; --muted: #9aa4af; --bg: #14171b; --line: #2b3138; } }
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.55 system-ui, sans-serif; }
main { max-width: 34rem; margin: 12vh auto; padding: 0 16px; }
h1 { font-size: 1.6rem; line-height: 1.25; margin: 0 0 1rem; }
h2 { font-size: 1.05rem; margin: 1.5rem 0 0.4rem; }
code { font-size: 0.92em; }
.details { color: var(--muted); font-size: 0.9rem; border-top: 1px solid var(--line); padding-top: 1rem; }
</style>
</head>
<body><main>
${body}
</main></body>
</html>
`;
    return new Response(page, {
        status: status,
        headers: { 'Content-Type': 'text/html; charset=utf-8', ...noStore() },
    });
}

function esc(text: string): string {
    return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}
