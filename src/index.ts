import { VPNDetection, VPNDetectionError } from 'vpndetection';
import { createCore, type Core, type Lookup } from 'vpndetection/middleware';

import pkg from '../package.json' with { type: 'json' };

import { edgeCachedFetch } from './cache.js';
import { hasPass, verify, VERIFY_PATH } from './challenge.js';
import { inRanges, parseEnv, type Env, type Settings } from './config.js';
import { challengePage, refusal, setupPage } from './pages.js';
import { judge, type Verdict } from './rules.js';

/** The request header each answer reaches your site on. */
const RECORD_HEADER = 'X-VPNDetection';

// What a page loads by the dozen. A visitor refused the page gets nothing from these alone.
const STATIC = /\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|mp4|webm|mp3)$/i;

const USER_AGENT = `vpndetection-cloudflare/${pkg.version}`;

/** What reaches your site in {@link RECORD_HEADER}, as JSON. */
export interface ForwardedRecord {
    ip?: string;
    /** Whether the visitor matched what the Worker acts on. On `log` that is all it did. */
    matched: boolean;
    signals: string[];
    /** `passed` once the visitor passed the Turnstile check. */
    challenge?: 'passed';
    /** Why a visitor who would have matched was let through. */
    exempt?: string;
    /** Why the lookup failed, when it did: the visitor was let through unless `FAIL_CLOSED` is true. */
    error?: string;
    /** The API's answer, as served. */
    result?: unknown;
}

export default {
    // A failure of the Worker's own never takes the site down: the visitor goes on to it.
    fetch: async (request, env) => {
        try {
            return await handle(request, env);
        } catch (err) {
            console.error('[vpndetection] letting a request through after an error:', err);
            return forward(request, undefined);
        }
    },
} satisfies ExportedHandler<Env>;

async function handle(request: Request, env: Env): Promise<Response> {
    const runtime = runtimeFor(env);
    const url = new URL(request.url);
    if (isSetupHost(url.hostname)) {
        return setup(request, runtime);
    }
    if (!runtime.ok) {
        runtime.warn(`checking no one, until these settings are fixed: ${runtime.problems.join('; ')}`);
        return forward(request, undefined);
    }
    const { settings, core, warn } = runtime;
    const ip = clientIp(request);
    const turnstile = settings.action === 'challenge' ? settings.turnstile : undefined;
    const verifying = url.pathname === VERIFY_PATH && request.method === 'POST';
    if (turnstile !== undefined && verifying && ip !== undefined) {
        const outcome = await verify(request, ip, turnstile.secretKey);
        return outcome.passed ? outcome.response : challengePage(request, ip, turnstile.siteKey, outcome.back);
    }
    if (unchecked(request, url, ip, settings)) {
        return forward(request, undefined);
    }
    const lookup = await evaluate(core, request, settings.timeoutMs);
    const verdict = judge(lookup, settings, warn);
    const forwarding = settings.forward;
    if (!verdict.matched) {
        return forward(request, forwarding ? record(lookup, verdict) : undefined);
    }
    console.log(JSON.stringify({
        vpndetection: settings.action, ip: lookup.ip, signals: verdict.signals, path: url.pathname,
    }));
    if (settings.action === 'log') {
        return forward(request, forwarding ? record(lookup, verdict) : undefined);
    }
    if (turnstile !== undefined) {
        if (ip !== undefined && await hasPass(request, ip, turnstile.secretKey)) {
            return forward(request, forwarding ? record(lookup, verdict, 'passed') : undefined);
        }
        return challengePage(request, lookup.ip, turnstile.siteKey);
    }
    return refusal(request, lookup.ip, verdict.signals, settings.blockMessage);
}

type Runtime =
    | { ok: true; settings: Settings; client: VPNDetection; core: Core<Request>; warn: (message: string) => void }
    | { ok: false; problems: string[]; warn: (message: string) => void };

const ENV_NAMES: (keyof Env)[] = [
    'VPNDETECTION_API_KEY', 'VPNDETECTION_BASE_URL', 'BLOCK', 'ACTION', 'PROXY_MIN_HITS', 'ALLOW_IPS',
    'ALLOW_PATHS', 'BLOCK_MESSAGE', 'TURNSTILE_SITE_KEY', 'TURNSTILE_SECRET_KEY', 'FAIL_CLOSED', 'FORWARD',
    'TIMEOUT_MS', 'CACHE_TTL',
];

let memo: { key: string; runtime: Runtime } | undefined;

// One client per copy of the Worker, kept while its settings stay the same: its cache lives in it.
function runtimeFor(env: Env): Runtime {
    const key = JSON.stringify(ENV_NAMES.map((name) => env[name] ?? null));
    if (memo?.key === key) {
        return memo.runtime;
    }
    const warn = onceEach((message) => console.warn(`[vpndetection] ${message}`));
    const parsed = parseEnv(env);
    let runtime: Runtime;
    if (!parsed.ok) {
        runtime = { ok: false, problems: parsed.problems, warn: warn };
    } else {
        const settings = parsed.settings;
        const client = new VPNDetection({
            apiKey: settings.apiKey,
            baseUrl: settings.baseUrl,
            cache: settings.cacheTtl === 0 ? false : { ttlMs: settings.cacheTtl * 1000 },
            fetch: tagged(edgeCachedFetch(settings.apiKey, settings.cacheTtl)),
            retries: 0,
            timeoutMs: settings.timeoutMs,
        });
        const core = createCore<Request>({
            client: client, timeoutMs: settings.timeoutMs, retries: 0, onWarn: warn,
        }, clientIp);
        runtime = { ok: true, settings: settings, client: client, core: core, warn: warn };
    }
    memo = { key: key, runtime: runtime };
    return runtime;
}

/**
 * Classify the visitor, bounded here too: a lookup another request started can be awaited by this one,
 * and must not hold it past the deadline if that request goes away.
 */
async function evaluate(core: Core<Request>, request: Request, timeoutMs: number): Promise<Lookup> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<Lookup>((resolve) => {
        timer = setTimeout(() => resolve({
            ip: clientIp(request),
            error: new VPNDetectionError('network', `no answer within ${timeoutMs}ms`),
            blocked: false,
        }), timeoutMs + 250);
    });
    try {
        return (await Promise.race([core.evaluate(request), late])) ?? { blocked: false };
    } finally {
        if (timer !== undefined) {
            clearTimeout(timer);
        }
    }
}

async function setup(request: Request, runtime: Runtime): Promise<Response> {
    if (!runtime.ok) {
        return setupPage({ problems: runtime.problems });
    }
    const { settings, client, core, warn } = runtime;
    const [plan, lookup] = await Promise.all([
        client.myEntitlement({ timeoutMs: settings.timeoutMs, retries: 0 }).then(
            (entitlement) => ({ name: entitlement.plan.name }),
            (err: unknown) => ({ error: describe(err) }),
        ),
        evaluate(core, request, settings.timeoutMs),
    ]);
    const verdict = judge(lookup, settings, warn);
    return setupPage({
        problems: [],
        plan: 'name' in plan ? plan.name : undefined,
        keyError: 'error' in plan ? plan.error : undefined,
        ip: lookup.ip,
        signals: verdict.signals,
        outcome: outcome(verdict, settings),
    });
}

function outcome(verdict: Verdict, settings: Settings): string {
    if (verdict.exempt === 'verified-bot') {
        return 'let you through, as a verified bot';
    }
    if (!verdict.matched) {
        return 'let you through';
    }
    switch (settings.action) {
    case 'block':
        return 'refuse you';
    case 'challenge':
        return 'ask you to pass a Turnstile check';
    case 'log':
        return 'let you through and log it';
    }
}

function describe(err: unknown): string {
    if (err instanceof VPNDetectionError) {
        switch (err.kind) {
        case 'unauthorized':
        case 'forbidden':
            return 'the API refused the key';
        case 'network':
            return 'the API could not be reached';
        default:
            return err.message;
        }
    }
    return String(err);
}

function unchecked(request: Request, url: URL, ip: string | undefined, settings: Settings): boolean {
    return request.method === 'OPTIONS'
        || STATIC.test(url.pathname)
        || settings.allowPaths.some((prefix) => url.pathname.startsWith(prefix))
        || (ip !== undefined && inRanges(ip, settings.allowIps));
}

function record(lookup: Lookup, verdict: Verdict, challenge?: 'passed'): ForwardedRecord {
    return {
        ...(lookup.ip === undefined ? {} : { ip: lookup.ip }),
        matched: verdict.matched,
        signals: verdict.signals,
        ...(challenge === undefined ? {} : { challenge: challenge }),
        ...(verdict.exempt === undefined ? {} : { exempt: verdict.exempt }),
        ...(lookup.error === undefined ? {} : { error: lookup.error.kind }),
        ...(lookup.result === undefined ? {} : { result: lookup.result.raw }),
    };
}

/**
 * On to your site, carrying the answer. **Any copy of the header the visitor sent is deleted first**,
 * which is what lets your site trust it: otherwise a visitor could say what they liked about themselves.
 */
function forward(request: Request, rec: ForwardedRecord | undefined): Promise<Response> {
    const headers = new Headers(request.headers);
    headers.delete(RECORD_HEADER);
    if (rec !== undefined) {
        headers.set(RECORD_HEADER, asciiJson(rec));
    }
    return fetch(new Request(request, { headers: headers }));
}

// A header value is bytes, so a city or a company named in another script travels as JSON's own escapes.
function asciiJson(value: ForwardedRecord): string {
    const json = JSON.stringify(value);
    let out = '';
    for (let i = 0; i < json.length; i++) {
        const code = json.charCodeAt(i);
        out += code > 0x7e ? `\\u${code.toString(16).padStart(4, '0')}` : json.charAt(i);
    }
    return out;
}

// The edge sets CF-Connecting-IP itself, replacing any a visitor sends.
function clientIp(request: Request): string | undefined {
    const ip = request.headers.get('CF-Connecting-IP')?.trim();
    return ip === undefined || ip === '' ? undefined : ip;
}

// Its own workers.dev address and local development, where no site stands behind the Worker.
function isSetupHost(hostname: string): boolean {
    return hostname.endsWith('.workers.dev') || ['localhost', '127.0.0.1', '[::1]'].includes(hostname);
}

// Each API request names this Worker and its version ahead of the SDK's own.
function tagged(inner: typeof fetch): typeof fetch {
    return (input, init) => {
        const request = new Request(input, init);
        const sdk = request.headers.get('User-Agent');
        request.headers.set('User-Agent', sdk === null ? USER_AGENT : `${USER_AGENT} ${sdk}`);
        return inner(request);
    };
}

// A misconfiguration is the same on every request: said once per copy of the Worker, not once per request.
function onceEach(sink: (message: string) => void): (message: string) => void {
    const seen = new Set<string>();
    return (message) => {
        if (!seen.has(message)) {
            seen.add(message);
            sink(message);
        }
    };
}
