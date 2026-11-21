# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="28"/>](https://vpndetection.io/) VPNDetection Cloudflare Worker

[![release](https://img.shields.io/github/v/release/vpndetection-io/cloudflare-plugin)](CHANGELOG.md)
[![license](https://img.shields.io/github/license/vpndetection-io/cloudflare-plugin)](LICENSE)

The official [VPNDetection](https://vpndetection.io) Worker for Cloudflare looks up every visitor at Cloudflare's edge, on any plan, and passes the answer to your site.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/vpndetection-io/cloudflare-plugin)

## Getting Started

1. Create an API key in the [VPNDetection console](https://app.vpndetection.io).
2. Click **Deploy to Cloudflare** above. Cloudflare copies this repository into your GitHub or GitLab account, asks for your API key, and deploys the Worker.
3. In the Cloudflare dashboard, open **Workers & Pages**, select **vpndetection**, then **Settings** > **Domains & Routes** > **Add** > **Route**. Pick your zone, enter `example.com/*` with your own domain, and select **Add route**.

Every request on the route then reaches your site with the answer in the `X-VPNDetection` header, as JSON. The Worker deletes any copy of the header a visitor sends, so your site can trust it.

## What it sends

The Worker calls the VPNDetection API at `https://api.vpndetection.io` with your API key and the visitor's IP address.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="64"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
