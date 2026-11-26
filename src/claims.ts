import { MAX_AGENTS_PER_ADDRESS, namesCrawler } from 'vpndetection/middleware';

import { digest } from './cache.js';
import type { Claim } from './rules.js';

/**
 * The least time an address's crawler agents are kept: the hour the SDK's core keeps them in each copy of
 * the Worker, sending none past its own bound. Kept as long here, it never drops an agent the Worker sends.
 */
const AGENTS_TTL_S = 3600;

/** What one request's `User-Agent` comes to while `BLOCK` names `spoofed`. */
export interface Planned {
    /** The agent the lookup carries, absent for a browser and past the address's bound. */
    agent?: string;
    /** What the rules judge, absent for a browser. */
    claim?: Claim;
    /** The agent's digest, kept with its address once the lookup is answered. */
    tag?: string;
}

/** The crawler agents each address was looked up with, kept beside the answers in the data center. */
export interface Claims {
    plan(ip: string | undefined, userAgent: string | undefined): Promise<Planned>;
    note(ip: string | undefined, planned: Planned, verdict: string | undefined): Promise<void>;
}

interface Seen {
    agents: string[];
    spoofed: boolean;
}

/**
 * Only a crawler's agent rides a lookup, and one address is looked up with at most
 * {@link MAX_AGENTS_PER_ADDRESS} of them for `ttlS` seconds, an hour at least. Past that, a claim is judged
 * spoofed where one of the address's earlier ones was.
 */
export function crawlerClaims(apiKey: string, baseUrl: string, ttlS: number): Claims {
    const keptS = Math.max(ttlS, AGENTS_TTL_S);
    let keyTag: string | undefined;
    const keyOf = async (ip: string): Promise<Request> => {
        keyTag ??= await digest(`${baseUrl} ${apiKey}`);
        return new Request(`${baseUrl}/__agents/${encodeURIComponent(ip)}?k=${keyTag}`);
    };
    return {
        plan: async (ip, userAgent) => {
            if (userAgent === undefined || !namesCrawler(userAgent)) {
                return {};
            }
            if (ip === undefined) {
                return { agent: userAgent, claim: { sent: true, spoofedBefore: false } };
            }
            const tag = await digest(userAgent);
            const seen = await read(await keyOf(ip));
            if (seen.agents.includes(tag) || seen.agents.length < MAX_AGENTS_PER_ADDRESS) {
                return { agent: userAgent, tag: tag, claim: { sent: true, spoofedBefore: seen.spoofed } };
            }
            return { claim: { sent: false, spoofedBefore: seen.spoofed } };
        },
        note: async (ip, planned, verdict) => {
            if (ip === undefined || planned.tag === undefined) {
                return;
            }
            const key = await keyOf(ip);
            const seen = await read(key);
            const known = seen.agents.includes(planned.tag);
            const spoofed = seen.spoofed || verdict === 'spoofed';
            if (known && spoofed === seen.spoofed) {
                return;
            }
            const agents = known ? seen.agents : [...seen.agents, planned.tag];
            const next: Seen = { agents: agents, spoofed: spoofed };
            await caches.default.put(key, new Response(JSON.stringify(next), {
                headers: { 'Content-Type': 'application/json', 'Cache-Control': `max-age=${keptS}` },
            }));
        },
    };
}

async function read(key: Request): Promise<Seen> {
    const hit = await caches.default.match(key);
    if (hit === undefined) {
        return { agents: [], spoofed: false };
    }
    try {
        const seen = await hit.json<Partial<Seen>>();
        return {
            agents: Array.isArray(seen.agents) ? seen.agents.filter((a) => typeof a === 'string') : [],
            spoofed: seen.spoofed === true,
        };
    } catch {
        return { agents: [], spoofed: false };
    }
}
