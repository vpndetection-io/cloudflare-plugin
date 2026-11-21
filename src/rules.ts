import type { Result } from 'vpndetection';
import { matchesCondition, missingMembers, type BlockCondition, type Lookup } from 'vpndetection/middleware';
import * as z from 'zod/mini';

import type { Settings, Signal } from './config.js';

/** What the rules made of one request's lookup. */
export interface Verdict {
    /** Whether the visitor matched what the Worker acts on. */
    matched: boolean;
    /** The signals that matched, or `unavailable` when the lookup failed and the Worker fails closed. */
    signals: string[];
    /** Why a visitor that would have matched was let through. */
    exempt?: 'verified-bot';
}

// Read off the answer as served: the SDK names a member only once it is re-pinned to a spec that has it.
const botAnswer = z.object({
    is_bot: z.optional(z.boolean()),
    bot: z.nullish(z.object({ verified: z.optional(z.boolean()) })),
});

/**
 * Judge one lookup against the settings. A verified bot, one whose operator vouches for the address, is
 * never refused: search engines' crawlers run on hosting networks.
 */
export function judge(lookup: Lookup, settings: Settings, warn: (message: string) => void): Verdict {
    const result = lookup.result;
    if (result === undefined) {
        return settings.failClosed
            ? { matched: true, signals: ['unavailable'] }
            : { matched: false, signals: [] };
    }
    const bot = botAnswer.safeParse(result.raw);
    const isBot = bot.success && bot.data.is_bot === true;
    const signals: string[] = [];
    for (const signal of settings.block) {
        const term = termFor(signal, result, isBot, settings.proxyMinHits);
        if (term === null) {
            continue;
        }
        const gaps = missingMembers(term, result);
        if (gaps.length > 0) {
            warn(`BLOCK names ${signal}, which your plan does not answer (${gaps.join(', ')}), `
                + 'so it never matches');
            continue;
        }
        if (matchesCondition(term, result)) {
            signals.push(signal);
        }
    }
    if (signals.length > 0 && bot.success && bot.data.bot?.verified === true) {
        return { matched: false, signals: [], exempt: 'verified-bot' };
    }
    return { matched: signals.length > 0, signals: signals };
}

/**
 * One signal's condition for this answer, or null where it cannot apply. A free answer has no
 * `is_hosting`, so hosting is read off the type of the network the address belongs to there, sparing
 * an address a bot is known to use, since only a paid answer says whether its operator vouches for
 * it. A relay is judged as a relay alone: iCloud Private Relay and company gateways run on hosting
 * networks.
 */
function termFor(signal: Signal, result: Result, isBot: boolean, minHits: number): BlockCondition | null {
    switch (signal) {
    case 'vpn':
        return { isVpn: true };
    case 'tor':
        return { isTor: true };
    case 'relay':
        return { isRelay: true };
    case 'pubproxy':
        return { isPubproxy: true };
    case 'smtp':
        return { isSmtp: true };
    case 'resproxy':
        return minHits > 1 ? { isResproxy: true, resproxy: { hits: { gte: minHits } } } : { isResproxy: true };
    case 'mobproxy':
        return minHits > 1 ? { isMobproxy: true, mobproxy: { hits: { gte: minHits } } } : { isMobproxy: true };
    case 'dcproxy':
        return minHits > 1 ? { isDcproxy: true, dcproxy: { hits: { gte: minHits } } } : { isDcproxy: true };
    case 'hosting':
        if (result.isRelay === true) {
            return null;
        }
        if (result.isHosting === undefined && result.asn !== undefined) {
            return isBot ? null : { asn: { type: 'hosting' } };
        }
        return { isHosting: true };
    }
}
