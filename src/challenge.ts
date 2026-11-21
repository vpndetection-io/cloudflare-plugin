import * as z from 'zod/mini';

/** Where the challenge page posts its Turnstile token. */
export const VERIFY_PATH = '/__vpndetection/verify';

const COOKIE = '__vpndetection_pass';
const PASS_LIFE_S = 24 * 60 * 60;
const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

const siteverifyAnswer = z.object({ success: z.boolean() });

/**
 * Whether the request carries a pass this Worker signed for this address and host, still in date. A
 * pass is bound to the address, since the verdict it overrides is the address's.
 */
export async function hasPass(request: Request, ip: string, secret: string): Promise<boolean> {
    const value = cookie(request, COOKIE);
    const match = /^(\d+)\.([0-9a-f]{64})$/.exec(value ?? '');
    if (match === null) {
        return false;
    }
    const expires = Number(match[1]);
    if (expires * 1000 < Date.now()) {
        return false;
    }
    const host = new URL(request.url).hostname;
    const signature = new Uint8Array(match[2]!.match(/../g)!.map((h) => parseInt(h, 16)));
    return crypto.subtle.verify('HMAC', await key(secret), signature, passText(expires, ip, host));
}

/**
 * Check a submitted Turnstile token with Cloudflare and answer with the pass and a redirect back to the
 * page the visitor asked for, or, when Cloudflare refuses it, with that page's path for another try.
 */
export async function verify(
    request: Request, ip: string, secret: string,
): Promise<{ passed: true; response: Response } | { passed: false; back: string }> {
    let form: FormData;
    try {
        form = await request.formData();
    } catch {
        return { passed: false, back: '/' };
    }
    const back = backTo(form.get('return'));
    const token = form.get('cf-turnstile-response');
    if (typeof token !== 'string' || token === '') {
        return { passed: false, back: back };
    }
    const body = new URLSearchParams({ secret: secret, response: token, remoteip: ip });
    let passed = false;
    try {
        const answer = await fetch(SITEVERIFY, { method: 'POST', body: body });
        const parsed = siteverifyAnswer.safeParse(await answer.json());
        passed = parsed.success && parsed.data.success;
    } catch {
        passed = false;
    }
    if (!passed) {
        return { passed: false, back: back };
    }
    const url = new URL(request.url);
    const expires = Math.floor(Date.now() / 1000) + PASS_LIFE_S;
    const signature = await crypto.subtle.sign('HMAC', await key(secret), passText(expires, ip, url.hostname));
    const hex = [...new Uint8Array(signature)].map((b) => b.toString(16).padStart(2, '0')).join('');
    const secure = url.protocol === 'https:' ? '; Secure' : '';
    const attributes = `Path=/; Max-Age=${PASS_LIFE_S}; HttpOnly; SameSite=Lax${secure}`;
    const response = new Response(null, {
        status: 303,
        headers: {
            'Location': back,
            'Set-Cookie': `${COOKIE}=${expires}.${hex}; ${attributes}`,
            'Cache-Control': 'no-store',
        },
    });
    return { passed: true, response: response };
}

// Only a path on this site, so the form cannot be used to send a visitor elsewhere.
function backTo(value: ReturnType<FormData['get']>): string {
    if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) {
        return '/';
    }
    return value;
}

function passText(expires: number, ip: string, host: string): Uint8Array {
    return new TextEncoder().encode(`pass ${expires} ${ip} ${host}`);
}

let keyFor: { secret: string; key: CryptoKey } | undefined;

// The Turnstile secret signs the pass too, so the Worker needs no secret of its own for it. The key is
// kept once made, never as a promise another request could be left waiting on.
async function key(secret: string): Promise<CryptoKey> {
    if (keyFor?.secret === secret) {
        return keyFor.key;
    }
    const made = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(`${COOKIE} ${secret}`), { name: 'HMAC', hash: 'SHA-256' }, false,
        ['sign', 'verify'],
    );
    keyFor = { secret: secret, key: made };
    return made;
}

function cookie(request: Request, name: string): string | undefined {
    for (const part of (request.headers.get('Cookie') ?? '').split(';')) {
        const at = part.indexOf('=');
        if (at > 0 && part.slice(0, at).trim() === name) {
            return part.slice(at + 1).trim();
        }
    }
    return undefined;
}
