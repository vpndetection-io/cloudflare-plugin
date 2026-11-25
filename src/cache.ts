// An answer marked so stays a minute at most, as the SDK's own cache keeps it: the plan behind it can change.
const SHORT_LIFE_S = 60;

// A lookup's path is the address alone.
const LOOKUP_PATH = /^\/[0-9A-Fa-f:.]+$/;

/**
 * A `fetch` for the SDK client that keeps each lookup's answer in the data center's cache, which every
 * copy of the Worker there shares, for `ttlS` seconds. The client's own cache sits in front of it and
 * holds one copy's answers, sharing one request among concurrent misses for an address. Keyed by the
 * API key too, so two Workers on one zone with different keys never share an answer.
 */
export function edgeCachedFetch(apiKey: string, ttlS: number): typeof fetch {
    let keyTag: string | undefined;
    return async (input, init) => {
        const request = new Request(input, init);
        const url = new URL(request.url);
        if (ttlS === 0 || request.method !== 'GET' || !LOOKUP_PATH.test(url.pathname)) {
            return fetch(request);
        }
        keyTag ??= await digest(`${url.origin} ${apiKey}`);
        url.searchParams.set('k', keyTag);
        const cacheKey = new Request(url.toString());
        const cache = caches.default;
        const hit = await cache.match(cacheKey);
        if (hit !== undefined) {
            return hit;
        }
        const response = await fetch(request);
        if (response.status !== 200) {
            return response;
        }
        const body = await response.text();
        const headers = new Headers(response.headers);
        headers.set('Cache-Control', `max-age=${lifeSeconds(body, ttlS)}`);
        headers.delete('Set-Cookie');
        await cache.put(cacheKey, new Response(body, { status: 200, headers: headers }));
        return new Response(body, { status: 200, headers: response.headers });
    };
}

function lifeSeconds(body: string, ttlS: number): number {
    try {
        const answer = JSON.parse(body) as { trial_expired?: unknown; cap_reached?: unknown };
        if (answer.trial_expired === true || answer.cap_reached === true) {
            return Math.min(ttlS, SHORT_LIFE_S);
        }
    } catch {
        return Math.min(ttlS, SHORT_LIFE_S);
    }
    return ttlS;
}

export async function digest(text: string): Promise<string> {
    const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return [...new Uint8Array(bytes).slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
