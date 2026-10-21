# Acquiring and Normalizing Code

Only do this for assets in scope. Record how you obtained the code and which version it corresponds to.

## Public repositories
Check the organization's GitHub/GitLab/Bitbucket for the product, SDKs, internal tools and microservices that share auth or utility code. Compare the repo tag with the deployed version (version strings in assets, headers, changelogs). Code on `main` may not be what is deployed; a bug fixed on `main` can still be live, and a bug on an unreleased branch is not.

## Released packages
Plugins and libraries: download the exact released archive for the deployed version (the plugin directory's version archive, package registry tarball, release asset) rather than `main`. Diff it against the repo tag to spot differences.

## JavaScript bundles and source maps
- Check the end of each bundle for a `sourceMappingURL` comment; fetch the `.map` only if the asset is in scope and the program allows it. A source map's `sources` and `sourcesContent` fields contain the original files.
- Without maps: beautify (`prettier` or `js-beautify`) before reading. Do not run static analysis on minified code; results are noise.
- Look in bundles for: hidden API paths (`/internal/`, `/admin/`, `/api/v`), tokens or keys, client-side-only authorization checks, `postMessage` handlers, `innerHTML`/`dangerouslySetInnerHTML` sinks, feature flags that gate sensitive UI.

## Mobile apps
Android: `jadx -d out/ app.apk` produces readable Java/Kotlin. iOS: apps are encrypted on device; bundled frameworks and class dumps still reveal API structure. For web audits, you mostly want the API endpoints, auth flow and hard-coded secrets.

## Exposed repositories
Exposed `.git` directories or config files are reportable on their own in many programs. Reconstructing them (for example with `git-dumper`) is an active request to a live target: do it only with explicit scope permission and a logged approval.

## Normalizing
Create a working copy; leave the original untouched. Note generated or vendored directories in the skip-list. For monorepos, list packages and mark which are in scope.
