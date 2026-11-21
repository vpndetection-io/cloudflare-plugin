// The built Worker in workerd, through Miniflare: every outbound request lands in a stub that plays the
// API and the site behind the Worker.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { after, test } from 'node:test';

import { convertV4MiniflareOptions, Miniflare } from 'miniflare';

const API = 'https://api.vpndetection.io';
const SITE = 'https://example.com';
const KEY = 'test-key';
const VISITOR = '45.33.32.156';
const wrangler = await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
const compatibilityDate = /"compatibility_date":\s*"([^"]+)"/.exec(wrangler)[1];

// An answer as the API serves one.
const ANSWER = {
    ip: VISITOR, is_vpn: false, is_bogon: false, is_tor: false, is_relay: false, is_bot: false, is_anycast: false,
    is_carrier: false, is_satellite: false, is_ssh: true, is_smtp: false, is_web: true, is_dns_resolver: false,
    is_bittorrent: false, tor: {}, relay: {}, hostname: 'scanme.nmap.org',
    location: {
        continent: 'NA', continent_name: 'North America', country: 'US', country_name: 'United States',
        timezone: 'America/Los_Angeles', currency_code: 'USD', currency_name: 'Dollar', currency_symbol: '$',
        flag_emoji: '🇺🇸', flag_unicode: 'U+1F1FA U+1F1F8',
    },
    asn: { asn: 63949, name: 'Akamai Connected Cloud', domain: 'linode.com', type: 'hosting', prefix: '45.33.32.0/19' },
    company: { name: 'Linode', domain: 'linode.com' },
    abuse: { email: 'abuse@linode.com' },
};

const stub = { lookups: 0, origin: [] };

async function outbound(request) {
    const url = new URL(request.url);
    if (url.origin === API) {
        stub.lookups++;
        if (request.headers.get('Authorization') !== `Bearer ${KEY}`) {
            return Response.json({ rc: 'BAD_API_KEY' }, { status: 401 });
        }
        return Response.json(ANSWER);
    }
    if (url.origin === SITE) {
        stub.origin.push(Object.fromEntries(request.headers));
        return new Response(`origin ${url.pathname}`);
    }
    return new Response('unexpected request', { status: 599 });
}

const workers = [];
after(async () => {
    await Promise.all(workers.map((mf) => mf.dispose()));
});

async function worker(vars = {}) {
    const mf = new Miniflare(convertV4MiniflareOptions({
        modules: true,
        scriptPath: new URL('../dist/index.js', import.meta.url).pathname,
        compatibilityDate: compatibilityDate,
        bindings: { VPNDETECTION_API_KEY: KEY, ...vars },
        outboundService: outbound,
    }));
    workers.push(mf);
    await mf.ready;
    return mf;
}

async function visit(mf, headers = {}) {
    stub.origin = [];
    const response = await mf.dispatchFetch(`${SITE}/page`, { headers: { 'CF-Connecting-IP': VISITOR, ...headers } });
    return { status: response.status, body: await response.text(), origin: stub.origin.at(-1) };
}

test('the visitor reaches the site with the answer in X-VPNDetection', async () => {
    const mf = await worker();
    const { status, body, origin } = await visit(mf);
    assert.equal(status, 200);
    assert.equal(body, 'origin /page');
    const record = JSON.parse(origin['x-vpndetection']);
    assert.equal(record.ip, VISITOR);
    assert.equal(record.result.asn.type, 'hosting');
    assert.match(origin['x-vpndetection'], /"flag_emoji":"\\ud83c\\uddfa\\ud83c\\uddf8"/);
});

test('a copy of the header the visitor sent never reaches the site', async () => {
    const mf = await worker({ FORWARD: 'false' });
    const { origin } = await visit(mf, { 'X-VPNDetection': '{"result":{"is_tor":false}}' });
    assert.equal(origin['x-vpndetection'], undefined);
});

test('a key the API refuses lets the visitor through, saying why', async () => {
    const mf = await worker({ VPNDETECTION_API_KEY: 'wrong' });
    const { status, origin } = await visit(mf);
    assert.equal(status, 200);
    assert.equal(JSON.parse(origin['x-vpndetection']).error, 'unauthorized');
});
