# Path Traversal, File Read/Write, Uploads, Archives

**Root cause:** attacker data selects or names a filesystem path, or controls file contents and location, so files outside the intended area are read, overwritten, or executed.

## What the sink looks like
Open/read/write/delete/copy/move/include with a variable path; `sendFile`/`send_file`/download endpoints; template or include loaders choosing a file by name; upload handlers saving the client's filename; archive extraction (zip/tar) writing entries by their embedded names; image/document processors that read paths or URLs; log or backup viewers.

## Safe vs unsafe
- Safe: map an identifier to a server-side path (database lookup, enum); canonicalize (`realpath`) the final path and verify it stays inside the base directory *after* resolution; strip to basename only when directory components are never legitimate; store uploads outside the web root or in a location that never executes, with a generated name.
- Unsafe: blocklisting `../` once (non-recursive) or only in one encoding; prefix checks without canonicalization (`/uploads` matching `/uploads_evil`); joining paths where the second segment can be absolute (path-join functions in several languages discard the base when the second argument is absolute); checking the extension of the *submitted* name but saving under another; checking `Content-Type` or magic bytes only; trusting archive entry names.

## Upload specifics
- Execution: can an uploaded file be served and executed (script extensions, double extensions, handler config, `.htaccess`/web.config uploads, case and trailing-dot or alternate-extension tricks depending on the server)?
- Content: SVG and HTML served from the app's origin run script; polyglot files; image libraries and document converters parse attacker data.
- Metadata: filename in `Content-Disposition`, stored XSS via filename, ZIP with symlinks.
- Limits: size, count, decompression bombs.

## Archives
Per-entry path check after joining and resolving; reject absolute paths and `..`; handle symlinks and hardlinks; limit size and entry count. Newer language versions add extraction filters; confirm they are actually used.

## Reachability and impact
Arbitrary file read of configuration/keys; arbitrary write to code/config/web root leads to code execution; delete/overwrite integrity impact. Check which user the process runs as and what the base directory contains.

## Review questions
- Which part of the path does the attacker control (directory, basename, extension)?
- What is the check, when is it done relative to canonicalization, and does it use the same string as the open call?
- Is there a fixed extension appended and does the runtime version make that bypassable?
- Where does the upload land, how is it named, and how is it served?

## False-positive traps
Value is an ID resolved to a path server-side; canonical check present and correct; files served through a handler with strict MIME and `Content-Disposition: attachment` from a sandbox domain; admin-only and excluded.

## Variant ideas
Download/export/backup/thumbnail endpoints, language/theme/template loaders, import features, plugin/theme installers, avatar and attachment handlers, log viewers, document converters.
