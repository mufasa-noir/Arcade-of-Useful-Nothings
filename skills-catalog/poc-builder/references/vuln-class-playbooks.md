# Vuln-class playbooks

Quick-reference for Stage 1 (what does "success" mean for this bug class) and Stage 3 (what's actually worth exploring in parallel for this bug class). Not exhaustive — treat as a starting point and extend per-finding.

## Memory corruption: UAF / double-free / TOCTOU races

- **Success usually means**: controlled crash (specific signal/fault), or proof of control over execution (hijacked pointer/vtable, redirected control flow), or a reliably reproducible state corruption with observable effect.
- **Parameters that matter**: timing offset between the "free"/revoke and the "use"/reclaim; thread/process interleaving; allocator state (heap grooming, allocation size/count before the trigger); number of concurrent racer threads; retry count and backoff between attempts.
- **Typical split**: timing-sensitive race pattern — either many concurrent timing offsets, or synchronized complementary roles (one sub-agent frees, another reclaims/uses).
- **Tools**: ASan/MSan builds for reliable crash signal during development, gdb/lldb, rr for deterministic replay once a crash is found, ptrace-based race harnesses.

## Other binary / pwn (stack/heap overflow, format string, type confusion, ROP/JOP)

- **Success usually means**: proof of instruction pointer control (crash at a controlled address), or full RCE (shell/command execution), depending on what the finding claims.
- **Parameters that matter**: offset to saved return address / controlled pointer, bad-byte set (what bytes the input can't contain), available gadgets (ASLR/PIE/stack-canary/NX status), payload encoding.
- **Typical split**: parameter sweep for offset-finding and bad-byte discovery; independent verification once a working offset is found (does it still work from a clean process start, with ASLR enabled, etc.).

## Web (SQLi, XSS, SSRF, deserialization, auth bypass/IDOR, SSTI, path traversal)

- **Success usually means**: for injection bugs, a side-channel or direct-output proof (boolean/time-based response difference, reflected payload execution, retrieved out-of-scope data); for auth/IDOR, successful access to a resource that should be denied; for SSRF, proof of a request reaching an internal/unintended target.
- **Parameters that matter**: injection point (param/header/cookie/body field), encoding/escaping variant, auth context (which role/session), target endpoint variants.
- **Typical split**: parameter sweep across encodings/injection points/auth contexts; multi-component chain if the bug needs an attacker-controlled listener (e.g. blind SSRF/XXE callback, stored XSS triggered later).

## Hardware / embedded (UART/JTAG/SWD access, firmware extraction, glitching, bootloader bypass, side-channel)

- **Success usually means**: proof of unauthorized access (shell via debug interface, dumped firmware/secret, bypassed secure boot check), or a successful glitch (skipped check, corrupted but useful output).
- **Parameters that matter**: glitch timing/width/voltage (for fault injection), baud rate and pinout (for UART/JTAG), target firmware version/build, physical setup repeatability.
- **Typical split**: timing-sensitive race pattern for glitching (many parameter combinations of timing + voltage/width, tried across repeated attempts); this is the bug class where documented repro procedure (not a script) is often the right deliverable, since physical setup can't be "run" by an agent.

## Crypto (weak RNG, padding oracle, nonce/IV reuse, length-extension, downgrade)

- **Success usually means**: recovered plaintext/key material, forged valid signature/MAC, or proven distinguisher (statistical bias beyond chance).
- **Parameters that matter**: oracle query budget, which error/timing signal leaks the information, sample size needed for statistical confidence.
- **Typical split**: parameter sweep for oracle-signal discovery; independent verification is important here since crypto PoCs are easy to convince yourself work on insufficient samples.

## Logic / business-logic / client-side bypass

- **Success usually means**: reaching a state the application's rules should have prevented (skipped payment step, elevated privilege, bypassed rate limit).
- **Parameters that matter**: the exact sequence/ordering of requests or actions, which checks are client-side vs server-side, race conditions between steps (these bugs are often *also* timing-sensitive — check the race pattern above).
- **Typical split**: often doesn't need much parallelism — usually a single sequential path once found. Multi-component chain if the bypass requires a second actor (e.g. racing two simultaneous requests).

## Mobile (Android/iOS)

If the finding is Android-specific and goes deeper than building a single PoC (manifest exposure, WebView/JS bridge, IPC/deep-link, native lib), prefer Deon's dedicated `android-apk-skills` set for the analysis pipeline — this skill's playbook here is for producing one targeted PoC once the bug is already identified, not for the broader bug-hunting pass.
