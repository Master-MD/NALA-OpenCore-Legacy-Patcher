# Security Policy (`sHeriFF` + `NCSP v2.5`)

## Hardened Design Guarantees
- **100% Pure Safe Rust (`#![forbid(unsafe_code)]`)** with **0 external crates** (`std`-only).
- **Zero-Python / Zero-Node.js / Zero-Telemetry** runtime footprint.
- **Dry-Run-First Safety Lock:** Root-volume patching and EFI writes are strictly read-only planning by default. Destructive/privileged steps require explicit 2-step confirmation (`--confirm-step2`) and an atomic NCSP v2.5 pre-change snapshot + `rollback.sh`.
- **5-Layer HTTP & CLI Shield (`SEC-01..SEC-05`):**
  - `SEC-01`: Strict SSRF block (loopback, RFC1918, link-local, metadata endpoints blocked for outbound payload fetches).
  - `SEC-02`: XSS / HTML / CSS-breakout sanitization on all dynamic responses.
  - `SEC-03`: Path-traversal (`..`, NUL) & shell-injection rejection (strict argument-array execution, never `sh -c` on untrusted input).
  - `SEC-04`: 10 MiB hard HTTP request body cap (`HTTP 413`) + per-client token-bucket rate limiting.
  - `SEC-05`: Hardened HTTP headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`, `Referrer-Policy: no-referrer`, `X-NALA-Version`).
- **Cryptographic Payload Pinning:** All upstream `dortania/OpenCore-Legacy-Patcher` (`3.x`), `PatcherSupportPkg` (`2.0.5+`), and `OpenCorePkg` (`1.0.6+`) binary payloads are verified via Pure Rust FIPS 180-4 SHA-256 before staging.
- **Zero-PII Gate:** Built-in `nala-oclp-rs audit-pii .` verifies zero personal identifiers, private IPs, or secrets in code and manifests.
