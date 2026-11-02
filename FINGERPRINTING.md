# Fingerprinting resistance

What void actually does, what it can't do, and how to check it.

This file describes void 0.2.0. If code and this document disagree, the code wins — and an issue is welcome.

## JavaScript layer

Injected at document start into every frame, before page scripts run.

### Canvas

- `getImageData`, `toDataURL` and `toBlob` return a copy with deterministic 1-LSB noise added.
- The original canvas is never modified, so drawing apps keep working.
- Noise is stable for the life of the page, so repeated reads don't reveal a changing fingerprint.
- Images larger than 4 megapixels skip the noisy copy to avoid stalls.

This is not Tor Browser's exact behaviour (TB blocks readback or prompts), but it removes the hardware/driver-unique signal without breaking canvas rendering.

### Audio

- `getFloatFrequencyData`, `getByteFrequencyData`, `getFloatTimeDomainData` and `getByteTimeDomainData` are zero-filled.

### WebRTC and capture

- `RTCPeerConnection`, the prefixed variants, `RTCDataChannel`, `RTCSessionDescription` and `RTCIceCandidate` are removed.
- `navigator.mediaDevices` is removed.
- WebRTC and media streams are also disabled in WebKit settings.

### Screen and window

- `screen.width/height` → 1920×1080, `availWidth/availHeight` → 1920×1040.
- `colorDepth` and `pixelDepth` → 24.
- `devicePixelRatio` → 1.
- `outerWidth/outerHeight` and `innerWidth/innerHeight` → 1000×800.
- `screenX`, `screenY` → 0.
- `screen.orientation` → landscape-primary, angle 0.
- The GTK layout really does keep the WebView at 1000×800, with empty space around it, so the spoofed numbers match the rendered viewport.

### Navigator

Values match Firefox 115 ESR on Windows, which is what the User-Agent claims:

| Property | Value |
| --- | --- |
| `hardwareConcurrency` | 2 |
| `platform` | `Win32` |
| `oscpu` | `Windows NT 10.0; Win64; x64` |
| `language` / `languages` | `en-US` / `en-US, en` |
| `vendor` | empty |
| `product` / `productSub` | `Gecko` / `20100101` |
| `appName` / `appCodeName` | `Netscape` / `Mozilla` |
| `appVersion` | `5.0 (Windows)` |
| `maxTouchPoints` | 0 |
| `webdriver` | false |
| `doNotTrack` | `1` |
| `plugins` / `mimeTypes` | empty |
| `buildID` | `20181001000000` |

`userAgent` is not patched in JavaScript; the engine sends the matching Firefox 115 string, so HTTP headers and `navigator.userAgent` agree.

### Time

- Timezone is forced to UTC by the WebKit context (`time_zone_override`).
- No `Date` or `Intl` monkey-patching. Broken date shims are a bigger tell than UTC itself.
- `performance.now()` is rounded down to 100 ms, matching Tor Browser's reduced timer precision.
- `setTimeout` and `setInterval` have a 4 ms floor.

### Storage and shared memory

- `SharedArrayBuffer` and `Atomics` are removed (Spectre timing mitigation).
- `window.name` is cleared on document start.
- DOM storage is available but ephemeral and per tab; IndexedDB and WebSQL are off.
- Third-party cookies are rejected; first-party cookies live only in memory.

### Fonts

- The engine font stack is pinned to `serif`, `sans-serif` and `monospace`.
- `document.fonts.check` is left alone. Patching it breaks sites and is trivially detectable.
- Layout rectangles are left alone. Rounding them breaks real layout code; generic fonts already remove the font-metric signal.

## Engine layer (WebKit2GTK)

- User-Agent: Firefox 115 ESR on Windows.
- Hardware acceleration off, WebGL off, accelerated 2D canvas off.
- WebRTC, media streams, encrypted media, fullscreen off.
- DNS prefetching off, page cache off, offline app cache off.
- Hyperlink auditing (`<a ping>`) off.
- Smooth scrolling and back/forward gestures off.
- Top-level navigation to `data:` URLs off.
- File access from file URLs off; universal access from file URLs off.
- JavaScript can't open windows automatically or read the clipboard.
- Modal dialogs allowed (sites depend on them), developer extras off.
- Site-specific quirks on, so the Firefox UA doesn't break ordinary sites.
- TLS errors fail hard; there is no bypass prompt.
- Renderer process isolation and sandbox on, with process swap on cross-site navigation.
- ITP (Intelligent Tracking Prevention) on.
- Accepted languages: `en-US, en`.
- Downloads cancelled on start.

## Network layer

- Top-level `http://` navigations are upgraded to `https://` in the navigation policy.
- Clicked links and submitted forms are upgraded in JavaScript.
- Localhost, `.localhost`, `.local`, `.onion`, `.i2p` and private IPs are left on HTTP.
- Known tracker hosts are blocked at navigation time and by script-level wrappers for `fetch`, XHR, `sendBeacon`, WebSocket, EventSource and subresource `src`/`href`.
- Referrer policy is set to `no-referrer` with a meta tag.
- Tor mode adds a runtime kill switch: if Tor is unreachable, network navigations are ignored and a local page explains why.
- Every tab has its own network context and its own SOCKS credentials, so Tor isolates tabs into separate circuits.

## What is still visible

These gaps are structural and are not fixed by JavaScript:

1. **TLS fingerprint.** libsoup3/GnuTLS vs Firefox's Necko/NSS. Cipher suite order, extensions, session tickets, ALPN details and HTTP/2 frame ordering differ. `tls.peet.ws` will show it.
2. **HTTP/2 behaviour and header order.** libsoup3 decides these; the Rust bindings don't expose them.
3. **Engine rendering.** WebKit vs Gecko. Letterboxing and generic fonts reduce the signal but do not remove it.
4. **Some subresource loads.** WebKit2GTK 2.0.1 has no content-filter API and no `send-request` hook, and `resource-load-started` cannot safely cancel a single request without killing the page. Script wrappers catch most tracker traffic; engine-internal loads may slip through.
5. **Canvas.** Noise is a mitigation. A fingerprinter can average many samples; Tor Browser's stronger approach is to block or prompt, which void does not do.
6. **SOCKS credentials.** If Tor is configured without `IsolateSOCKSAuth`, the per-tab circuit separation collapses.

Mitigations for the TLS gap, if it matters to you:

- Patch libsoup3/GnuTLS (large, fragile).
- Put a local HTTPS proxy in front that normalises TLS to Firefox's profile.
- Accept it, and use Tor Browser for high-risk work.

## Verification checklist

JavaScript surface:

- [ ] `https://coveryourtracks.eff.org`
- [ ] `https://browserleaks.com/canvas` — canvas hash should differ from a normal browser
- [ ] `https://browserleaks.com/webgl` — WebGL unavailable
- [ ] `https://browserleaks.com/webrtc` — no local IP leak
- [ ] `https://browserleaks.com/javascript` — navigator/screen values match the table above
- [ ] `https://browserleaks.com/fonts` — only generic families resolve

Network:

- [ ] `https://check.torproject.org` — Tor exit node
- [ ] Open two tabs to different sites, check exit IPs differ
- [ ] Click **new id**, check the exit IP changes
- [ ] `https://tls.peet.ws/api/all` — compare TLS/HTTP2 with Tor Browser
- [ ] `https://www.ssllabs.com/ssltest/viewMyClient.html`

Behaviour:

- [ ] `performance.now()` moves in 100 ms steps
- [ ] `setTimeout(fn, 0)` waits at least 4 ms
- [ ] `navigator.plugins.length === 0`
- [ ] `RTCPeerConnection === undefined`
- [ ] Two tabs cannot see each other's cookies

## Status

- **Manual fingerprint resistance:** good for JavaScript-visible surfaces.
- **Automated / TLS-level resistance:** partial. The engine libraries differ from Firefox and that is visible on the wire.

made by Ivoryy06 ♡
