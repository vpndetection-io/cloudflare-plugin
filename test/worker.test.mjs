// The built Worker in workerd, through Miniflare: every outbound request lands in a stub that plays the
// API, Turnstile and the site behind the Worker.
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, test } from 'node:test';

import { convertV4MiniflareOptions, Miniflare } from 'miniflare';

const API = 'https://api.vpndetection.io';
const SITE = 'https://example.com';
const SETUP = 'https://vpndetection.someone.workers.dev';
const KEY = 'test-key';
const VPN = '185.65.134.1';
const CLEAN = '81.2.69.142';
const CRAWLER = '66.249.66.1';
const RELAY = '172.225.46.64';
const BROWSER = { accept: 'text/html,application/xhtml+xml' };
const wrangler = await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
const compatibilityDate = /"compatibility_date":\s*"([^"]+)"/.exec(wrangler)[1];

// Answers as the API serves them: a paid plan's for a VPN server, and the free plan's, which has no
// is_hosting and no bot detail. Each other answer is the paid one with every flag off but its own.
const PAID = JSON.parse(await readFile(new URL('./fixtures/paid.json', import.meta.url), 'utf8'));
const FREE = JSON.parse(await readFile(new URL('./fixtures/free.json', import.meta.url), 'utf8'));
const NEUTRAL = Object.fromEntries(Object.entries(PAID).map(([k, v]) => {
    if (k.startsWith('is_')) {
        return [k, false];
    }
    return [k, Array.isArray(v) ? [] : (v !== null && typeof v === 'object' && !['location', 'asn', 'company',
        'abuse'].includes(k) ? {} : v)];
}));
const ANSWERS = {
    [VPN]: PAID,
    [CLEAN]: { ...NEUTRAL, ip: CLEAN, is_resproxy: true, resproxy: { provider: 'example', hits: 5 } },
    [CRAWLER]: {
        ...NEUTRAL, ip: CRAWLER, is_hosting: true, is_bot: true,
        bot: { provider: 'google', provider_name: 'Google', agents: ['Googlebot'], verified: true },
    },
    [RELAY]: { ...NEUTRAL, ip: RELAY, is_relay: true, is_hosting: true },
    '185.65.134.2': { ...PAID, ip: '185.65.134.2' },
    '45.33.32.156': FREE,
    '34.82.1.1': { ...FREE, ip: '34.82.1.1', is_bot: true },
};

let stub = freshStub();
function freshStub() {
    return { lookups: 0, apiStatus: 200, apiDelayMs: 0, plan: 'Starter', userAgents: [], origin: [] };
}

async function outbound(request) {
    const url = new URL(request.url);
    if (url.origin === API) {
        stub.userAgents.push(request.headers.get('User-Agent'));
        if (![`Bearer ${KEY}`, 'Bearer second-key'].includes(request.headers.get('Authorization'))) {
            return Response.json({ rc: 'BAD_API_KEY' }, { status: 401 });
        }
        if (url.pathname === '/api/v1/entitlement') {
            return Response.json({
                org_id: 'org_test',
                apikey: { id: 'key_test', allowed_cidrs: [] },
                plan: { key: 'starter', name: stub.plan, tier: 'paid' },
                usage: { requests: 12, quota: 100000, window_start: '2026-11-01T00:00:00Z',
                    window_end: '2026-12-01T00:00:00Z' },
            });
        }
        stub.lookups++;
        if (stub.apiDelayMs > 0) {
            await new Promise((resolve) => setTimeout(resolve, stub.apiDelayMs));
        }
        if (stub.apiStatus !== 200) {
            return Response.json({ rc: 'INTERNAL' }, { status: stub.apiStatus });
        }
        const ip = decodeURIComponent(url.pathname.slice(1));
        const answer = ANSWERS[ip];
        return answer === undefined ? Response.json({ rc: 'NOT_FOUND' }, { status: 404 }) : Response.json(answer);
    }
    if (url.href === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
        const form = new URLSearchParams(await request.text());
        const good = form.get('response') === 'good' && form.get('secret') === 'turnstile-secret';
        return Response.json({ success: good });
    }
    if (url.origin === SITE) {
        stub.origin.push({ path: url.pathname, headers: Object.fromEntries(request.headers) });
        return new Response(`origin ${url.pathname}`, { headers: { 'content-type': 'text/plain' } });
    }
    return new Response('unexpected request', { status: 599 });
}

const workers = [];
after(async () => {
    await Promise.all(workers.map((mf) => mf.dispose()));
});

async function worker(vars = {}, options = {}) {
    const mf = new Miniflare(convertV4MiniflareOptions({
        modules: true,
        scriptPath: new URL('../dist/index.js', import.meta.url).pathname,
        compatibilityDate: compatibilityDate,
        // A setting given as undefined is left out, as the Deploy button leaves every one but the key.
        bindings: Object.fromEntries(Object.entries({
            VPNDETECTION_API_KEY: KEY, BLOCK: 'vpn,tor', ACTION: 'block', ...vars,
        }).filter(([, value]) => value !== undefined)),
        outboundService: outbound,
        ...options,
    }));
    workers.push(mf);
    await mf.ready;
    return mf;
}

async function visit(mf, ip, path = '/', init = {}) {
    stub.origin = [];
    const response = await mf.dispatchFetch(`${SITE}${path}`, {
        ...init,
        headers: { 'CF-Connecting-IP': ip, ...BROWSER, ...(init.headers ?? {}) },
        redirect: 'manual',
    });
    return { response: response, body: await response.text(), origin: stub.origin.at(-1) };
}

function forwarded(origin) {
    const raw = origin?.headers['x-vpndetection'];
    return raw === undefined ? undefined : JSON.parse(raw);
}

describe('blocking', () => {
    test('a VPN visitor is refused with the block page, and never reaches the site', async () => {
        stub = freshStub();
        const mf = await worker();
        const { response, body, origin } = await visit(mf, VPN);
        assert.equal(response.status, 403);
        assert.match(body, /Access denied/);
        assert.match(body, /connections through a VPN/);
        assert.match(body, new RegExp(VPN.replaceAll('.', '\\.')));
        assert.equal(response.headers.get('cache-control'), 'no-store');
        assert.equal(origin, undefined);
    });

    test('with the API key its only binding, it refuses VPNs and lets everyone else through', async () => {
        stub = freshStub();
        const mf = await worker({ BLOCK: undefined, ACTION: undefined });
        const vpn = await visit(mf, VPN);
        assert.equal(vpn.response.status, 403);
        assert.equal(vpn.origin, undefined);
        const clean = await visit(mf, CLEAN, '/pricing');
        assert.equal(clean.response.status, 200);
        assert.equal(forwarded(clean.origin).matched, false);
    });

    test('anything but a browser gets JSON', async () => {
        stub = freshStub();
        const mf = await worker();
        const { response, body } = await visit(mf, VPN, '/api/orders', { headers: { accept: 'application/json' } });
        assert.equal(response.status, 403);
        assert.deepEqual(JSON.parse(body), { error: 'access denied' });
    });

    test('a clean visitor reaches the site with the answer in X-VPNDetection', async () => {
        stub = freshStub();
        const mf = await worker();
        const { response, body, origin } = await visit(mf, CLEAN, '/pricing');
        assert.equal(response.status, 200);
        assert.equal(body, 'origin /pricing');
        const rec = forwarded(origin);
        assert.equal(rec.ip, CLEAN);
        assert.equal(rec.matched, false);
        assert.deepEqual(rec.signals, []);
        assert.equal(rec.result.is_resproxy, true);
    });

    test('a non-ASCII value in the answer travels as JSON escapes', async () => {
        stub = freshStub();
        const mf = await worker({ ACTION: 'log' });
        const { origin } = await visit(mf, VPN);
        assert.match(origin.headers['x-vpndetection'], /"currency_symbol":"\\u20ac"/);
        assert.equal(forwarded(origin).result.location.currency_symbol, '€');
    });

    test('a copy of X-VPNDetection the visitor sent never reaches the site', async () => {
        stub = freshStub();
        const mf = await worker({ ACTION: 'log' });
        const forged = JSON.stringify({ matched: false, signals: [] });
        const { origin } = await visit(mf, VPN, '/', { headers: { 'X-VPNDetection': forged } });
        assert.equal(forwarded(origin).matched, true);
        const allowed = await worker({ ALLOW_PATHS: '/open/' });
        const second = await visit(allowed, VPN, '/open/page', { headers: { 'X-VPNDetection': forged } });
        assert.equal(second.origin.headers['x-vpndetection'], undefined);
    });

    test('FORWARD false sends no answer to the site', async () => {
        stub = freshStub();
        const mf = await worker({ FORWARD: 'false' });
        const { origin } = await visit(mf, CLEAN);
        assert.equal(origin.headers['x-vpndetection'], undefined);
    });

    test('ACTION log lets a match through, marked', async () => {
        stub = freshStub();
        const mf = await worker({ ACTION: 'log' });
        const { response, origin } = await visit(mf, VPN);
        assert.equal(response.status, 200);
        assert.deepEqual(forwarded(origin).signals, ['vpn']);
        assert.equal(forwarded(origin).matched, true);
    });

    test('BLOCK_MESSAGE replaces the sentence a blocked visitor reads', async () => {
        stub = freshStub();
        const mf = await worker({ BLOCK_MESSAGE: 'No VPNs <here>, please.' });
        const { body } = await visit(mf, VPN);
        assert.match(body, /No VPNs &#60;here&#62;, please\./);
    });
});

describe('signals', () => {
    test('residential proxy sightings count from PROXY_MIN_HITS, inclusive', async () => {
        stub = freshStub();
        const at = await worker({ BLOCK: 'resproxy', PROXY_MIN_HITS: '5' });
        assert.equal((await visit(at, CLEAN)).response.status, 403);
        const above = await worker({ BLOCK: 'resproxy', PROXY_MIN_HITS: '6' });
        assert.equal((await visit(above, CLEAN)).response.status, 200);
    });

    test('a verified bot is never refused, even on a hosting network', async () => {
        stub = freshStub();
        const mf = await worker({ BLOCK: 'hosting' });
        const { response, origin } = await visit(mf, CRAWLER);
        assert.equal(response.status, 200);
        assert.equal(forwarded(origin).exempt, 'verified-bot');
        assert.equal(forwarded(origin).matched, false);
    });

    test('a privacy relay is judged as a relay alone, not as hosting', async () => {
        stub = freshStub();
        const hosting = await worker({ BLOCK: 'hosting' });
        assert.equal((await visit(hosting, RELAY)).response.status, 200);
        const relay = await worker({ BLOCK: 'relay' });
        assert.equal((await visit(relay, RELAY)).response.status, 403);
    });

    test('on a free answer, hosting is the network type, sparing a known bot', async () => {
        stub = freshStub();
        const mf = await worker({ BLOCK: 'hosting' });
        assert.equal((await visit(mf, '45.33.32.156')).response.status, 403);
        assert.equal((await visit(mf, '34.82.1.1')).response.status, 200);
    });

    test('a refusal names what was found, and asks to turn off only what a visitor can', async () => {
        stub = freshStub();
        const mf = await worker({ BLOCK: 'vpn,hosting' });
        const vpn = await visit(mf, VPN);
        assert.match(vpn.body, /connections through a VPN or from a hosting or cloud network\. Turn it off/);
        const server = await visit(mf, '45.33.32.156');
        assert.match(server.body, /connections from a hosting or cloud network\.<\/p>/);
    });

    test('a signal the plan does not answer never matches', async () => {
        stub = freshStub();
        const mf = await worker({ BLOCK: 'resproxy' });
        assert.equal((await visit(mf, '45.33.32.156')).response.status, 200);
    });
});

describe('what is never checked', () => {
    test('ALLOW_IPS takes addresses and ranges, v4 and v6', async () => {
        stub = freshStub();
        const mf = await worker({ ALLOW_IPS: '10.0.0.1, 185.65.134.0/24, 2001:db8::/32' });
        const { response } = await visit(mf, VPN);
        assert.equal(response.status, 200);
        assert.equal(stub.lookups, 0);
    });

    test('ALLOW_PATHS, static files and preflights cost no lookup', async () => {
        stub = freshStub();
        const mf = await worker({ ALLOW_PATHS: '/webhooks/' });
        assert.equal((await visit(mf, VPN, '/webhooks/stripe', { method: 'POST', body: '{}' })).response.status, 200);
        assert.equal((await visit(mf, VPN, '/assets/site.css')).response.status, 200);
        assert.equal((await visit(mf, VPN, '/', { method: 'OPTIONS' })).response.status, 200);
        assert.equal(stub.lookups, 0);
    });
});

describe('failures', () => {
    test('an API error lets the visitor through, saying why', async () => {
        stub = freshStub();
        stub.apiStatus = 500;
        const mf = await worker();
        const { response, origin } = await visit(mf, VPN);
        assert.equal(response.status, 200);
        assert.equal(forwarded(origin).error, 'server_error');
    });

    test('a slow API lets the visitor through at TIMEOUT_MS', async () => {
        stub = freshStub();
        stub.apiDelayMs = 1500;
        const mf = await worker({ TIMEOUT_MS: '300' });
        const started = Date.now();
        const { response, origin } = await visit(mf, VPN);
        assert.equal(response.status, 200);
        assert.equal(forwarded(origin).error, 'network');
        assert.ok(Date.now() - started < 1400, `took ${Date.now() - started}ms`);
    });

    test('FAIL_CLOSED refuses while the API fails', async () => {
        stub = freshStub();
        stub.apiStatus = 500;
        const mf = await worker({ FAIL_CLOSED: 'true' });
        const { response, body } = await visit(mf, CLEAN);
        assert.equal(response.status, 403);
        assert.match(body, /couldn&#39;t check your connection/);
    });

    test('a key the API refuses fails open', async () => {
        stub = freshStub();
        const mf = await worker({ VPNDETECTION_API_KEY: 'wrong' });
        const { response, origin } = await visit(mf, VPN);
        assert.equal(response.status, 200);
        assert.equal(forwarded(origin).error, 'unauthorized');
    });

    test('settings that are wrong check no one, and strip the header', async () => {
        stub = freshStub();
        const mf = await worker({ BLOCK: 'vpn,everything', ACTION: 'challenge' });
        const forged = JSON.stringify({ matched: false });
        const { response, origin } = await visit(mf, VPN, '/', { headers: { 'X-VPNDetection': forged } });
        assert.equal(response.status, 200);
        assert.equal(origin.headers['x-vpndetection'], undefined);
        assert.equal(stub.lookups, 0);
    });
});

describe('caching', () => {
    test('concurrent visits from one address share one lookup', async () => {
        stub = freshStub();
        stub.apiDelayMs = 200;
        const mf = await worker();
        const visits = await Promise.all(Array.from({ length: 8 }, () => mf.dispatchFetch(`${SITE}/`, {
            headers: { 'CF-Connecting-IP': VPN, ...BROWSER },
        })));
        assert.deepEqual(visits.map((r) => r.status), Array(8).fill(403));
        await Promise.all(visits.map((r) => r.text()));
        assert.equal(stub.lookups, 1);
    });

    test('a fresh copy of the Worker answers from the data center cache', async () => {
        stub = freshStub();
        const dir = await mkdtemp(join(tmpdir(), 'cf-cache-'));
        try {
            const first = await worker({}, { resourcePersistencePath: dir });
            await visit(first, VPN);
            const second = await worker({}, { resourcePersistencePath: dir });
            assert.equal((await visit(second, VPN)).response.status, 403);
            assert.equal(stub.lookups, 1);
            const otherKey = await worker({ VPNDETECTION_API_KEY: 'second-key' }, { resourcePersistencePath: dir });
            await visit(otherKey, VPN);
            assert.equal(stub.lookups, 2, 'another key shares no answer');
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });

    test('each API request names the Worker and its version', async () => {
        stub = freshStub();
        const mf = await worker();
        await visit(mf, CLEAN);
        const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
        const version = pkg.version.replaceAll('.', '\\.');
        assert.match(stub.userAgents[0], new RegExp(`^vpndetection-cloudflare/${version}( |$)`));
    });
});

describe('challenge', () => {
    const CHALLENGE = {
        ACTION: 'challenge', TURNSTILE_SITE_KEY: 'site-key', TURNSTILE_SECRET_KEY: 'turnstile-secret',
    };

    async function solve(mf, ip, token, back = '/account?tab=1') {
        return mf.dispatchFetch(`${SITE}/__vpndetection/verify`, {
            method: 'POST',
            headers: { 'CF-Connecting-IP': ip, 'content-type': 'application/x-www-form-urlencoded', ...BROWSER },
            body: new URLSearchParams({ 'cf-turnstile-response': token, 'return': back }).toString(),
            redirect: 'manual',
        });
    }

    test('a match gets the Turnstile check, which posts back to the Worker', async () => {
        stub = freshStub();
        const mf = await worker(CHALLENGE);
        const { response, body, origin } = await visit(mf, VPN, '/account?tab=1');
        assert.equal(response.status, 403);
        assert.match(body, /data-sitekey="site-key"/);
        assert.match(body, /action="\/__vpndetection\/verify"/);
        assert.match(body, /name="return" value="\/account\?tab=1"/);
        assert.equal(origin, undefined);
    });

    test('a passed check returns the visitor with a pass bound to their address', async () => {
        stub = freshStub();
        const mf = await worker(CHALLENGE);
        const passed = await solve(mf, VPN, 'good');
        assert.equal(passed.status, 303);
        assert.equal(passed.headers.get('location'), '/account?tab=1');
        const cookie = passed.headers.get('set-cookie').split(';')[0];
        assert.match(passed.headers.get('set-cookie'), /HttpOnly; SameSite=Lax; Secure/);
        const back = await visit(mf, VPN, '/account', { headers: { cookie: cookie } });
        assert.equal(back.response.status, 200);
        assert.equal(forwarded(back.origin).challenge, 'passed');
        const elsewhere = await visit(mf, '185.65.134.2', '/account', { headers: { cookie: cookie } });
        assert.equal(elsewhere.response.status, 403, 'a pass is for the address it was earned on');
    });

    test('a failed check shows the check again, and a return path off the site goes home', async () => {
        stub = freshStub();
        const mf = await worker(CHALLENGE);
        const failed = await solve(mf, VPN, 'bad');
        assert.equal(failed.status, 403);
        assert.match(await failed.text(), /didn't pass/);
        const offsite = await solve(mf, VPN, 'good', '//evil.example/');
        assert.equal(offsite.headers.get('location'), '/');
    });

    test('a forged pass is refused', async () => {
        stub = freshStub();
        const mf = await worker(CHALLENGE);
        const forged = `__vpndetection_pass=${Math.floor(Date.now() / 1000) + 3600}.${'0'.repeat(64)}`;
        const { response } = await visit(mf, VPN, '/', { headers: { cookie: forged } });
        assert.equal(response.status, 403);
    });
});

describe('setup page', () => {
    test('on workers.dev the Worker says whether its key works and what it makes of the reader', async () => {
        stub = freshStub();
        const mf = await worker();
        const response = await mf.dispatchFetch(`${SETUP}/`, { headers: { 'CF-Connecting-IP': VPN, ...BROWSER } });
        const body = await response.text();
        assert.equal(response.status, 200);
        assert.match(body, /Accepted, on the Starter plan\./);
        assert.match(body, /matched vpn, so on your site\s+the Worker would refuse you/);
    });

    test('it names every setting that is wrong', async () => {
        stub = freshStub();
        const mf = await worker({ BLOCK: 'vpn,everything', PROXY_MIN_HITS: 'lots' });
        const body = await (await mf.dispatchFetch(`${SETUP}/`, { headers: BROWSER })).text();
        assert.match(body, /BLOCK names &#34;everything&#34;/);
        assert.match(body, /PROXY_MIN_HITS is &#34;lots&#34;/);
    });
});
