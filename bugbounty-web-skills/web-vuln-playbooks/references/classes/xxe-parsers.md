# XXE and Parser Abuse

**Root cause:** a parser processes attacker-supplied documents with dangerous features enabled (external entities, DTDs, external references, unsafe constructors, expansion), enabling file read, SSRF, or resource exhaustion.

## What to look for
- XML: parsers handling uploads, SOAP/SAML/SVG/DOCX/XLSX/OOXML, RSS/Atom, sitemaps, configuration imports; external entity resolution or DTD processing enabled; XInclude; XSLT with user stylesheets; parsers that fetch external schemas.
- SAML/SSO: signature wrapping, parser differentials, accepting unsigned assertions.
- YAML/other: unsafe loaders (see deserialization card); CSV injection when exports open in spreadsheets (formula prefixes); archive bombs; image/PDF libraries parsing hostile input; regular expressions with catastrophic backtracking on attacker-controlled strings (ReDoS; usually low severity and often excluded).
- Billion-laughs style entity expansion and decompression bombs where DoS is in scope.

## Safe vs unsafe
Safe: disallow DTDs and external entities explicitly (parser-specific flags), use data-only formats where possible, validate and bound sizes. Defaults differ by language and version; verify against the actual library and version in the repo rather than assuming. Some modern runtimes disable external entities by default, some libraries do not.

## Review questions
- Which parser and version; which flags are set; is a custom resolver installed?
- Does the output return to the attacker, or is it blind (out-of-band)?
- Which file types go to which parser (SVG, DOCX, XLSX are XML inside)?

## False-positive traps
Parser configured safely (flags verified); input only from trusted internal sources; the feature admin-only and excluded.

## Variant ideas
Document/image conversion pipelines, import/restore features, SSO metadata, XML-RPC and SOAP endpoints, spreadsheet import/export, feed fetchers.
