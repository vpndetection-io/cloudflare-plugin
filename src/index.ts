import { VPNDetection } from 'vpndetection';
import { createCore, type Core, type Lookup } from 'vpndetection/middleware';

/** The request header each answer reaches your site on. */
const RECORD_HEADER = 'X-VPNDetection';

/** The bindings wrangler.jsonc and the Worker's secrets give it. */
interface Env {
    VPNDETECTION_API_KEY?: string;
    VPNDETECTION_BASE_URL?: string;
    FORWARD?: string;
}

export default {
    fetch: async (request, env) => {
        const core = coreFor(env);
        const lookup = core === undefined ? undefined : await core.evaluate(request);
        return forward(request, env.FORWARD?.trim() === 'false' ? undefined : lookup);
    },
} satisfies ExportedHandler<Env>;

let memo: { key: string; core: Core<Request> | undefined } | undefined;

// One client per copy of the Worker, kept while its settings stay the same: its cache lives in it.
function coreFor(env: Env): Core<Request> | undefined {
    const apiKey = env.VPNDETECTION_API_KEY?.trim() ?? '';
    const baseUrl = env.VPNDETECTION_BASE_URL?.trim() || undefined;
    const key = JSON.stringify([apiKey, baseUrl ?? null]);
    if (memo?.key === key) {
        return memo.core;
    }
    let core: Core<Request> | undefined;
    if (apiKey === '') {
        console.warn('[vpndetection] VPNDETECTION_API_KEY is not set, so the Worker checks no one');
    } else {
        const client = new VPNDetection({ apiKey: apiKey, baseUrl: baseUrl, retries: 0, timeoutMs: 2500 });
        core = createCore<Request>({ client: client }, clientIp);
    }
    memo = { key: key, core: core };
    return core;
}

/**
 * On to your site, carrying the answer. **Any copy of the header the visitor sent is deleted first**,
 * which is what lets your site trust it.
 */
function forward(request: Request, lookup: Lookup | undefined): Promise<Response> {
    const headers = new Headers(request.headers);
    headers.delete(RECORD_HEADER);
    if (lookup !== undefined) {
        headers.set(RECORD_HEADER, asciiJson({
            ip: lookup.ip,
            error: lookup.error?.kind,
            result: lookup.result?.raw,
        }));
    }
    return fetch(new Request(request, { headers: headers }));
}

// A header value is bytes, so a city or a company named in another script travels as JSON's own escapes.
function asciiJson(value: unknown): string {
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
