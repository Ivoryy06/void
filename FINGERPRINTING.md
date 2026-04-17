# Fingerprinting Resistance — Current State & Verification

## What's Implemented

### JavaScript Layer (Tor Browser Alignment)
- ✅ Canvas fingerprinting: blank data (matches TB exactly)
- ✅ AudioContext: zero-filled frequency data
- ✅ WebRTC: fully blocked
- ✅ Screen dimensions: fixed to 1920×1080 (TB defaults)
- ✅ Window letterboxing: 1000×800 (TB standard size)
- ✅ Navigator properties: match TB/Firefox 115 ESR on Windows
- ✅ Timezone: forced UTC at both JS and engine level
- ✅ performance.now(): clamped to 100ms resolution
- ✅ setTimeout/setInterval: 4ms minimum (TB behavior)
- ✅ SharedArrayBuffer/Atomics: blocked (Spectre mitigation)
- ✅ Font enumeration: only generic families allowed
- ✅ Layout rects: quantized to 1px (removes sub-pixel font metrics)
- ✅ visualViewport: spoofed to letterboxed dimensions
- ✅ window.matchMedia: uses letterboxed dimensions
- ✅ window.name: cleared on every load

### Engine Layer (WebKit2GTK Settings)
- ✅ User-Agent: exact TB string (Firefox 115 ESR)
- ✅ Hardware acceleration: disabled (no GPU fingerprinting)
- ✅ WebGL: disabled
- ✅ DNS prefetching: disabled
- ✅ Storage APIs: disabled (localStorage, sessionStorage, IndexedDB, WebSQL)
- ✅ Page cache: disabled
- ✅ Media stream: disabled
- ✅ WebRTC: disabled at engine level
- ✅ Hyperlink auditing (`<a ping>`): disabled
- ✅ Smooth scrolling: disabled (TB doesn't use it)
- ✅ Back/forward gestures: disabled
- ✅ Font stack: normalized to generic families
- ✅ Accept-Language: locked to `en-US,en`
- ✅ Timezone override: UTC at engine level
- ✅ Process isolation: per-site processes (cross-site navigation swap)
- ✅ Sandbox: renderer processes sandboxed
- ✅ ITP (Intelligent Tracking Prevention): enabled
- ✅ Cookies: never accepted
- ✅ TLS errors: fail hard (no bypass prompts)

### Network Layer
- ✅ HTTPS-only: all `http://` redirected to `https://`
- ✅ Tor circuit isolation: per-domain SOCKS5 credentials
- ✅ Strict Tor mode: runtime kill switch blocks requests if Tor drops
- ✅ Request headers: match TB (Accept, Accept-Language, Accept-Encoding)
- ✅ Header removal: X-Forwarded-For, Via, TE, Origin stripped
- ✅ Referrer policy: no-referrer via meta tag

### Identity Isolation
- ✅ Ephemeral contexts: no disk persistence
- ✅ New Identity: clears all in-memory state (TLS sessions, HSTS, memory cache)
- ✅ Per-identity Tor circuits: fresh circuit per New Identity
- ✅ Signal handlers: Tor child killed on SIGTERM/SIGINT/panic

## What's NOT Controllable at This Layer

### TLS/Protocol Fingerprinting (libsoup3/GnuTLS)
WebKit2GTK uses libsoup3 for HTTP and GnuTLS for TLS. These are not exposed through Rust bindings:

- ❌ **TLS cipher suite ordering**: GnuTLS default order, not Firefox's
- ❌ **TLS extensions**: ALPN, SNI, session tickets — GnuTLS behavior
- ❌ **HTTP/2 frame ordering**: libsoup3 implementation differs from Firefox
- ❌ **Connection pooling**: libsoup3 manages this internally
- ❌ **Keep-alive behavior**: libsoup3 default, not Firefox's

**Mitigation options:**
1. **Patch libsoup3/GnuTLS** to match Firefox TLS fingerprint (requires C code)
2. **Use a local HTTPS proxy** (e.g., mitmproxy) configured to match Firefox's TLS behavior
3. **Accept the gap** — Tor Browser itself has minor TLS differences from vanilla Firefox

### Header Ordering
libsoup3 controls the order in which headers are sent. We can set header *values* via `headers.replace()`, but not their *order*.

- ❌ **Header ordering**: libsoup3 default, not Firefox's exact order

**Mitigation:** This is a weak signal. Most fingerprinting focuses on header *presence* and *values*, not order.

### HTTP/2 Behavior
libsoup3 supports HTTP/2 by default. We cannot disable it or control frame ordering from WebKit2GTK bindings.

- ❌ **HTTP/2 vs HTTP/1.1 selection**: libsoup3 negotiates via ALPN
- ❌ **HTTP/2 frame ordering**: libsoup3 implementation

**Potential mitigation:** Force HTTP/1.1 via soup3's `set_force_http1()` on the session object — but this requires accessing the soup session, which WebKit2GTK doesn't expose directly.

## Verification Checklist

Run void against these test suites and compare results to Tor Browser:

### JavaScript Fingerprinting
- [ ] [coveryourtracks.eff.org](https://coveryourtracks.eff.org)
- [ ] [browserleaks.com/canvas](https://browserleaks.com/canvas)
- [ ] [browserleaks.com/webgl](https://browserleaks.com/webgl)
- [ ] [browserleaks.com/webrtc](https://browserleaks.com/webrtc)
- [ ] [browserleaks.com/fonts](https://browserleaks.com/fonts)
- [ ] [browserleaks.com/javascript](https://browserleaks.com/javascript)

### Network/TLS Fingerprinting
- [ ] [browserleaks.com/ssl](https://browserleaks.com/ssl)
- [ ] [browserleaks.com/ip](https://browserleaks.com/ip) (verify Tor exit IP)
- [ ] [tls.peet.ws/api/all](https://tls.peet.ws/api/all) (TLS fingerprint)
- [ ] [www.ssllabs.com/ssltest/viewMyClient.html](https://www.ssllabs.com/ssltest/viewMyClient.html)

### Timing/Behavior
- [ ] [browserleaks.com/performance](https://browserleaks.com/performance)
- [ ] Verify `performance.now()` is clamped to 100ms
- [ ] Verify `setTimeout(fn, 0)` actually waits 4ms

### Headers
- [ ] Capture request headers via a local proxy (e.g., `mitmproxy`)
- [ ] Compare header presence, values, and order to Tor Browser

### Tor Circuit Isolation
- [ ] Visit two different domains, verify different exit IPs (check via [check.torproject.org](https://check.torproject.org))
- [ ] Click "New Identity", verify exit IP changes

## Known Gaps vs. Tor Browser

1. **TLS fingerprint**: GnuTLS vs NSS (Firefox's TLS library)
   - Different cipher suite ordering
   - Different extension ordering
   - Different session ticket behavior

2. **HTTP/2 behavior**: libsoup3 vs Firefox's HTTP/2 stack
   - Different frame ordering
   - Different priority handling

3. **Header ordering**: libsoup3 vs Firefox
   - Minor difference, low signal

4. **Rendering engine**: WebKit vs Gecko
   - Different layout engine (but letterboxing + quantization mitigate this)
   - Different font rendering (quantized to 1px)

## Recommendations for L2 (Automated Detection Resistance)

1. **Run verification tests** — compare void vs TB on all test suites above
2. **Capture TLS fingerprints** — use `tls.peet.ws` or `ja3er.com` to compare
3. **If TLS gap is critical:**
   - Option A: Patch libsoup3/GnuTLS to match Firefox (hard)
   - Option B: Run a local HTTPS proxy that normalizes TLS to Firefox (easier)
   - Option C: Accept the gap — TB itself differs slightly from vanilla Firefox
4. **Focus on behavioral consistency** — ensure no timing anomalies, no unusual API responses
5. **Avoid over-rigidity** — don't make the environment *too* perfect (e.g., all values exactly fixed)

## Current Status

**L1 (Manual Detection Resistance):** ✅ Achieved
- JavaScript fingerprinting mitigated
- Network isolation working
- Tor integration solid

**L2 (Automated Detection Resistance):** ⚠️ Partial
- JS layer matches TB closely
- TLS/HTTP2 layer differs (libsoup3/GnuTLS vs Firefox/NSS)
- Verification needed to quantify gap

**Next Steps:**
1. Run verification tests
2. Measure TLS fingerprint gap
3. Decide if gap is acceptable or requires proxy/patch
