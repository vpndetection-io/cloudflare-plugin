# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="28"/>](https://vpndetection.io/) VPNDetection Cloudflare Worker

[![release](https://img.shields.io/github/v/release/vpndetection-io/cloudflare-plugin)](CHANGELOG.md)
[![license](https://img.shields.io/github/license/vpndetection-io/cloudflare-plugin)](LICENSE)

The official [VPNDetection](https://vpndetection.io) Worker for Cloudflare blocks VPNs, proxies and Tor at Cloudflare's edge, on any plan, before a request reaches your site.

Cloudflare's own lists of VPN and anonymizer addresses come with its Enterprise plan alone. This Worker checks each visitor's address with the VPNDetection API on the Free, Pro and Business plans too, and blocks the request, asks for a Turnstile check, or passes it on marked. It works in front of any site behind Cloudflare, whatever runs it.

## Getting Started

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/vpndetection-io/cloudflare-plugin)

1. Create an API key in the [VPNDetection console](https://app.vpndetection.io). An account is free, and so is the plan it starts on.
2. Click **Deploy to Cloudflare** above. Cloudflare copies this repository into your GitHub or GitLab account, asks for your API key, and deploys the Worker.
3. Open the Worker's `workers.dev` address, which the deploy shows. The page there says whether your key works and what the Worker makes of your own connection.
4. Put the Worker in front of your site. In the Cloudflare dashboard, open **Workers & Pages**, select **vpndetection**, then **Settings** > **Domains & Routes** > **Add** > **Route**. Pick your zone, enter `example.com/*` with your own domain, and select **Add route**; a site on subdomains too takes a second route, `*.example.com/*`. The Worker sees only traffic whose DNS record is proxied through Cloudflare, the orange cloud.
5. Set each route to **Fail open**, so your site still loads as if the Worker weren't there if your account ever runs past the Workers free plan's 100,000 requests a day.

From then on every visitor to that route is checked. Out of the box the Worker refuses VPNs and Tor and lets everyone else through.

## Settings

Every setting has a default, so the deploy asks only for your API key. To change one, add it as a variable of type **Text** under **Workers & Pages** > **vpndetection** > **Settings** > **Variables and Secrets**. `wrangler.jsonc` sets `keep_vars`, so later deploys from your copy keep it. You can also set it under `vars` in `wrangler.jsonc` in your copy of the repository and push, since Cloudflare deploys every push. For routes: while `wrangler.jsonc` names no `routes`, a deploy leaves the ones you added in the dashboard as they are, and once it names some, each deploy sets exactly those.

| Variable | Default | What it does |
| --- | --- | --- |
| `BLOCK` | `vpn,tor` | What the Worker acts on, from the signals below, comma-separated |
| `ACTION` | `block` | `block` refuses a visitor who matches, `challenge` asks them for a Turnstile check, and `log` lets them through marked |
| `PROXY_MIN_HITS` | `1` | How many times an address must have been seen in a residential, mobile or datacenter proxy pool before those signals count |
| `ALLOW_IPS` | | Addresses and ranges never checked, such as `203.0.113.7, 2001:db8::/32` |
| `ALLOW_PATHS` | | Path prefixes never checked, such as `/webhooks/, /robots.txt` |
| `BLOCK_MESSAGE` | | The sentence a refused visitor reads, in place of one naming what was found |
| `TURNSTILE_SITE_KEY` | | Your Turnstile widget's site key, for `challenge` |
| `FAIL_CLOSED` | `false` | `true` refuses visitors while the API can't be reached |
| `FORWARD` | `true` | Whether each answer reaches your site in the `X-VPNDetection` header |
| `TIMEOUT_MS` | `2500` | How long a lookup may hold a request before the Worker gives up on it |
| `CACHE_TTL` | `3600` | How long an answer is kept, in seconds |

Your API key is the secret `VPNDETECTION_API_KEY`. The deploy asks for it, and you can change it under **Settings** > **Variables and Secrets** in the dashboard, or with `npx wrangler secret put VPNDETECTION_API_KEY`.

## Signals

| Signal | Matches | Plan |
| --- | --- | --- |
| `vpn` | Commercial and self-hosted VPN servers | Every plan |
| `tor` | Tor exit and relay nodes | Every plan |
| `relay` | iCloud Private Relay and company web gateways, mostly ordinary people | Every plan |
| `hosting` | Servers at hosting and cloud providers, where bots and scripts run | Every plan, judged by the network an address belongs to on the free plan |
| `pubproxy` | Open proxies anyone can connect through | A paid plan |
| `resproxy` | Home connections rented out as proxies | A paid plan |
| `mobproxy` | Phone connections rented out as proxies, whose addresses carriers share with ordinary customers | A paid plan |
| `dcproxy` | Proxies running in datacenters | A paid plan |
| `smtp` | Addresses that run a mail server, which home and mobile connections can't | A paid plan |

A free account also tries every signal for a while; after that, a signal the [free plan](https://vpndetection.io/pricing) doesn't answer never matches, and the Worker logs that once. A privacy relay is judged as a relay alone, even where it runs on a hosting network.

**Search engines' crawlers are never refused.** On a paid plan, an address whose bot operator vouches for it, such as Googlebot's, passes whatever it matched. On the free plan, `hosting` spares any address a known bot uses, since only a paid answer tells a verified crawler from one pretending.

## Challenge instead of block

A Turnstile check lets a person on a VPN in after proving they're a person, and stops scripts.

1. In the Cloudflare dashboard, open **Turnstile** > **Add widget**, name it, add your site's hostname, and keep the **Managed** mode.
2. Set `TURNSTILE_SITE_KEY` to the widget's site key and `ACTION` to `challenge`, as [Settings](#settings) says.
3. Add the widget's secret key as the secret `TURNSTILE_SECRET_KEY`, under **Settings** > **Variables and Secrets** or with `npx wrangler secret put TURNSTILE_SECRET_KEY`.

A visitor who matches then sees the check. Passing it sets a cookie that lets that visitor's address through for 24 hours. A request that isn't a page load, such as an API call, is refused with `403` until then.

## The answer at your site

With `FORWARD` on, every request the Worker checks reaches your site with the answer in the `X-VPNDetection` header, as JSON. The Worker deletes any copy of the header a visitor sends, so your site can trust it.

```json
{"ip":"185.65.134.1","matched":true,"signals":["vpn"],"result":{"ip":"185.65.134.1","is_vpn":true,"vpn":{"provider_name":"Mullvad"}}}
```

`matched` says whether the visitor matched `BLOCK`, which with `ACTION` set to `log` is all that happened. `signals` names what matched, `challenge` is `passed` once the visitor passed the Turnstile check, `exempt` is `verified-bot` for a crawler let through, `error` says why a lookup failed, and `result` is the API's answer as served. A request the Worker didn't check, such as one to an allowed path, carries no header.

```php
$lookup = json_decode($_SERVER['HTTP_X_VPNDETECTION'] ?? 'null', true);
if ($lookup && $lookup['matched']) {
    // flag the order for review
}
```

## Costs and failures

The Worker looks each address up at most once an hour in each Cloudflare data center, and every copy of the Worker there shares the answer. Requests for static files (`.css`, `.js`, images and fonts) and `OPTIONS` requests are passed on without a lookup. Every request on the route still counts against your Workers plan. To keep a path off the Worker altogether, such as `example.com/assets/*`, add a route for it with no Worker: the most specific route wins.

If the API doesn't answer within `TIMEOUT_MS`, or answers with an error, the visitor is let through and the header says why, unless `FAIL_CLOSED` is `true`. A setting that's wrong stops the Worker checking anyone until it's fixed, and the page at its `workers.dev` address names the setting. Each refusal, challenge and logged match is a line in the Worker's logs, under **Workers & Pages** > **vpndetection** > **Logs**.

## Updating

Your copy of the repository doesn't follow this one. To take a newer release, pull it into your copy and push:

```bash
git remote add upstream https://github.com/vpndetection-io/cloudflare-plugin.git
git pull upstream main
git push
```

## Deploying without the button

```bash
git clone https://github.com/vpndetection-io/cloudflare-plugin.git vpndetection-cloudflare
cd vpndetection-cloudflare
npm install
npx wrangler secret put VPNDETECTION_API_KEY
npx wrangler deploy
```

Then add the route as in steps 4 and 5, or uncomment `routes` in `wrangler.jsonc` before you deploy. `npm test` runs the Worker in Cloudflare's own runtime, and `npm run dev` serves it locally, where it shows the same page as on `workers.dev`.

## What it sends

The Worker calls the VPNDetection API at `https://api.vpndetection.io` with your API key and the visitor's IP address, at most once an hour per address in each Cloudflare data center. With `ACTION` set to `challenge`, it sends a Turnstile token and the visitor's address to Cloudflare's Turnstile service when a visitor submits the check.

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="64"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
