# SSRF and Open Redirect

**Root cause (SSRF):** the server makes a network request to a destination the attacker influences, letting them reach internal services, cloud metadata, or use the server as a proxy. **Open redirect:** a redirect target taken from input without restriction.

## What the sink looks like
- Outbound HTTP/URL fetchers: HTTP client libraries, `file_get_contents(url)`, `curl`, image/avatar fetchers, link previews/unfurlers, webhooks, URL import, RSS/feeds, OAuth/OpenID discovery, PDF/HTML renderers, XML parsers fetching external resources, SSO metadata fetchers, image optimizers (e.g. Next.js remote image config).
- Redirects: `redirect(request.args['next'])`, `Location` header from input, `res.redirect`, framework redirect helpers.

## Safe vs unsafe
- Safe: destination chosen from a fixed allowlist of hosts; URL parsed with a real parser, scheme restricted, host compared exactly; DNS resolved and the resulting IP checked against blocked ranges (loopback, link-local/metadata, private ranges, IPv6 equivalents) with the *connection pinned to the checked IP*; redirects not followed or re-validated at each hop.
- Unsafe: substring or `startswith`/`endswith` host checks; blocklists of `localhost`/`127.0.0.1` only; validating the hostname string but resolving later (DNS rebinding); allowing redirects; accepting other schemes (`file`, `gopher`, `ftp`); trusting URL parsing differences between the validator and the HTTP client.
- Redirect safe forms: relative paths only, or exact allowlist; unsafe: prefix checks (`https://trusted.com.evil.tld`), scheme-relative `//host`, backslash tricks, userinfo `@`.

## Reachability and impact
Response returned to the attacker (full read) vs blind (side effect or timing) changes impact enormously. Deployment context matters: cloud metadata endpoints, internal admin panels, unauthenticated internal services. Open redirects are usually low alone; valuable in OAuth/SSO flows (token leakage) or as part of a chain.

## Review questions
- Is the whole URL controlled, or only a path/query on a fixed host?
- What validation exists, and is it applied to the final request destination after resolution and after each redirect?
- What does the client library do by default (follow redirects, allowed schemes)?
- Is the fetched content returned, parsed, or stored? Can it be influenced to reveal responses?
- For redirects: where is the redirect used (login `next`, logout, OAuth `redirect_uri`, link tracking)?

## False-positive traps
Fixed host with attacker-controlled path only; strict allowlist actually enforced; request made client-side not server-side; feature requires admin and scope excludes it.

## Variant ideas
Webhook testers, import-from-URL, avatar by URL, OEmbed/unfurl, SSO/OIDC metadata, XML/SVG external references, PDF generators, proxy/relay endpoints, image resize endpoints, `Host`-header-derived URLs (password reset poisoning).
