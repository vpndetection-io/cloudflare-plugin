import { Address4, Address6 } from 'ip-address';
import * as z from 'zod/mini';

/** What the Worker can act on: each is one member of a lookup answer. */
export const SIGNALS = [
    'vpn', 'tor', 'pubproxy', 'resproxy', 'mobproxy', 'dcproxy', 'hosting', 'relay', 'smtp',
] as const;
export type Signal = (typeof SIGNALS)[number];

export const ACTIONS = ['block', 'challenge', 'log'] as const;
export type Action = (typeof ACTIONS)[number];

/** The bindings wrangler.jsonc and the Worker's secrets give it, every one a string. */
export interface Env {
    VPNDETECTION_API_KEY?: string;
    VPNDETECTION_BASE_URL?: string;
    BLOCK?: string;
    ACTION?: string;
    PROXY_MIN_HITS?: string;
    ALLOW_IPS?: string;
    ALLOW_PATHS?: string;
    BLOCK_MESSAGE?: string;
    TURNSTILE_SITE_KEY?: string;
    TURNSTILE_SECRET_KEY?: string;
    FAIL_CLOSED?: string;
    FORWARD?: string;
    TIMEOUT_MS?: string;
    CACHE_TTL?: string;
}

export interface Settings {
    apiKey: string;
    baseUrl?: string;
    block: Signal[];
    action: Action;
    proxyMinHits: number;
    allowIps: (Address4 | Address6)[];
    allowPaths: string[];
    blockMessage?: string;
    turnstile?: { siteKey: string; secretKey: string };
    failClosed: boolean;
    forward: boolean;
    timeoutMs: number;
    cacheTtl: number;
}

export type Parsed = { ok: true; settings: Settings } | { ok: false; problems: string[] };

const schema = z.object({
    VPNDETECTION_API_KEY: field((v, fail) => (v === '' ? fail('is not set: add it as a secret') : v)),
    VPNDETECTION_BASE_URL: field((v, fail) => {
        if (v === '') {
            return undefined;
        }
        return /^https?:\/\/[^/\s]+/.test(v) ? v : fail(`is "${v}", not an http or https URL`);
    }),
    BLOCK: field((v, fail) => split(v).map((e) => {
        const signal = SIGNALS.find((s) => s === e.toLowerCase());
        return signal ?? fail(`names "${e}", which is none of ${SIGNALS.join(', ')}`);
    }), 'vpn,tor'),
    ACTION: field((v, fail) => {
        const action = ACTIONS.find((a) => a === (v.toLowerCase() || 'block'));
        return action ?? fail(`is "${v}", not ${ACTIONS.join(', ')}`);
    }),
    PROXY_MIN_HITS: whole(1, 1, 1000),
    ALLOW_IPS: field((v, fail) => split(v).map((e) => {
        return parseAddress(e) ?? fail(`names "${e}", which is not an address or a range`);
    })),
    ALLOW_PATHS: field((v, fail) => split(v).map((e) => {
        return e.startsWith('/') ? e : fail(`names "${e}", which does not start with a slash`);
    })),
    BLOCK_MESSAGE: field((v) => (v === '' ? undefined : v)),
    TURNSTILE_SITE_KEY: field((v) => (v === '' ? undefined : v)),
    TURNSTILE_SECRET_KEY: field((v) => (v === '' ? undefined : v)),
    FAIL_CLOSED: flag(false),
    FORWARD: flag(true),
    TIMEOUT_MS: whole(2500, 100, 30_000),
    CACHE_TTL: whole(3600, 0, 86_400),
});

/** The settings an environment holds, or every problem with them, each named by its binding. */
export function parseEnv(env: Env): Parsed {
    const parsed = schema.safeParse(env);
    if (!parsed.success) {
        return {
            ok: false,
            problems: parsed.error.issues.map((issue) => `${String(issue.path[0] ?? '')} ${issue.message}`),
        };
    }
    const v = parsed.data;
    let turnstile: Settings['turnstile'];
    if (v.ACTION === 'challenge') {
        if (v.TURNSTILE_SITE_KEY === undefined || v.TURNSTILE_SECRET_KEY === undefined) {
            return {
                ok: false,
                problems: [
                    'ACTION is challenge, which needs TURNSTILE_SITE_KEY and the TURNSTILE_SECRET_KEY secret',
                ],
            };
        }
        turnstile = { siteKey: v.TURNSTILE_SITE_KEY, secretKey: v.TURNSTILE_SECRET_KEY };
    }
    return {
        ok: true,
        settings: {
            apiKey: v.VPNDETECTION_API_KEY,
            baseUrl: v.VPNDETECTION_BASE_URL,
            block: [...new Set(v.BLOCK)],
            action: v.ACTION,
            proxyMinHits: v.PROXY_MIN_HITS,
            allowIps: v.ALLOW_IPS,
            allowPaths: v.ALLOW_PATHS,
            blockMessage: v.BLOCK_MESSAGE,
            turnstile: turnstile,
            failClosed: v.FAIL_CLOSED,
            forward: v.FORWARD,
            timeoutMs: v.TIMEOUT_MS,
            cacheTtl: v.CACHE_TTL,
        },
    };
}

/** Whether an address is one of the ranges, or addresses, given. */
export function inRanges(ip: string, ranges: (Address4 | Address6)[]): boolean {
    if (ranges.length === 0) {
        return false;
    }
    const address = parseAddress(ip);
    if (address === undefined) {
        return false;
    }
    return ranges.some((range) => {
        if (range instanceof Address4) {
            return address instanceof Address4 && address.isInSubnet(range);
        }
        return address instanceof Address6 && address.isInSubnet(range);
    });
}

// An IPv4-mapped IPv6 address is judged as the IPv4 address it carries.
function parseAddress(text: string): Address4 | Address6 | undefined {
    if (Address4.isValid(text)) {
        return new Address4(text);
    }
    if (Address6.isValid(text)) {
        const v6 = new Address6(text);
        return v6.is4() ? v6.to4() : v6;
    }
    return undefined;
}

// One binding: its text, trimmed, parsed by `parse`, which reports a problem through `fail`. A binding
// that is not set at all reads as `unset`: the Deploy button sets none of them.
function field<T>(parse: (value: string, fail: (message: string) => never) => T, unset = '') {
    return z.pipe(z.optional(z.string()), z.transform((raw: string | undefined, ctx) => {
        const fail = (message: string): never => {
            ctx.issues.push({ code: 'custom', input: raw, message: message });
            return z.NEVER;
        };
        return parse((raw ?? unset).trim(), fail);
    }));
}

function flag(fallback: boolean) {
    return field((v, fail) => {
        const lower = v.toLowerCase();
        if (lower === '') {
            return fallback;
        }
        return lower === 'true' || lower === 'false' ? lower === 'true' : fail(`is "${v}", not true or false`);
    });
}

function whole(fallback: number, min: number, max: number) {
    return field((v, fail) => {
        if (v === '') {
            return fallback;
        }
        const n = Number(v);
        return Number.isInteger(n) && n >= min && n <= max
            ? n
            : fail(`is "${v}", not a whole number from ${min} to ${max}`);
    });
}

function split(text: string): string[] {
    return text.split(/[\s,]+/).map((e) => e.trim()).filter((e) => e !== '');
}
