# void

A small, quiet browser for Linux. Every tab is its own throwaway session, every request can go through Tor, and the fingerprinting surface is trimmed down to something close to Tor Browser's.

Built on GTK3 + WebKit2GTK. No accounts, no sync, no telemetry, no disk cache.

made by [Ivoryy06](https://github.com/Ivoryy06) ♡

## What it does

- **Ephemeral by default** — each tab gets a fresh in-memory data store. Close the tab or the window and the cookies, cache, history, storage and TLS state are gone. Nothing is written to disk except a tiny config file.
- **Tor mode** — `void --tor` routes everything through `127.0.0.1:9050`. If Tor is not reachable, void refuses to load pages instead of silently going direct.
- **Fresh circuit per tab** — every tab uses its own SOCKS credentials, so Tor isolates them into separate circuits.
- **New Identity** — one click closes every tab, starts a new identity epoch and opens a clean tab with new circuits.
- **HTTPS-first** — top-level HTTP navigations are upgraded to HTTPS, and in-page link clicks and form posts are upgraded too. Localhost, `.local`, `.onion` and private ranges are left alone so development and hidden services still work.
- **Tracker blocking** — known ad/analytics hosts are dropped before navigation, with a page-level guard for fetches, XHR, beacons, sockets and subresource elements.
- **Locked-down permissions** — camera, microphone, notifications, geolocation, clipboard, pointer lock, file pickers, HTTP auth and downloads are all denied without a prompt.
- **Fingerprint normalisation** — canvas noise, fixed screen/window/navigator values, WebRTC and WebGL off, UTC, coarse timers. Details in [FINGERPRINTING.md](FINGERPRINTING.md).
- **Security levels** — Standard / Safer / Safest, applied to every tab, remembered in config.
- **Strict web settings** — no WebGL, no WebRTC, no DNS prefetch, no page cache, no media capture, no encrypted media, no fullscreen, no clipboard access, no automatic popups, no file:// access.
- **Letterboxed layout** — the page view stays at 1000×800 (Tor Browser's default) and the rest of the window is empty space.

## What it does *not* touch

void is self-contained on purpose:

- It never changes your default browser, desktop MIME handlers or `xdg-settings`.
- It never changes system or GNOME proxy settings. The proxy is applied only to void's own WebKit network sessions.
- It never reads or writes other browsers' profiles.
- It only writes `~/.config/void/settings.json` (mode `0600`) and nothing else.
- Tor is spawned only with `--tor`, runs as a child of void, and is killed when void exits — including on `SIGKILL`, via `PR_SET_PDEATHSIG`. If you already run Tor, void uses it and leaves it alone.

## Install

You need Rust, GTK3, WebKit2GTK 4.1 and (for Tor mode) Tor.

```bash
# Debian / Ubuntu
sudo apt install build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev tor

# Fedora
sudo dnf install gcc pkg-config gtk3-devel webkit2gtk4.1-devel libsoup3-devel tor

# Arch
sudo pacman -S base-devel gtk3 webkit2gtk-4.1 libsoup3 tor
```

Then:

```bash
git clone https://github.com/Ivoryy06/void.git
cd void
cargo build --release
./install.sh
```

`install.sh` puts the binary in `~/.local/bin/void`, adds a desktop entry and icon, and does not register void as a default browser.

If you skip the installer:

```bash
cargo run --release -- --tor
```

## Usage

```bash
void                       # direct connection
void --tor                 # strict Tor; blocks everything if Tor is down
void --proxy socks5://127.0.0.1:1080
void --direct              # ignore config and ALL_PROXY
void https://example.com   # open a page on start
```

### Shortcuts

| Keys | Action |
| --- | --- |
| `Ctrl+T` | new isolated tab |
| `Ctrl+W` | close tab |
| `Ctrl+L` | focus address bar |
| `Ctrl+R` | reload |
| `Ctrl+H` | home |
| `Ctrl+N` | new identity |
| `Ctrl+Q` | quit |

### Config

`~/.config/void/settings.json`:

```json
{
  "theme": "dark",
  "home": "https://search.brave.com/",
  "proxy": null,
  "security": 0
}
```

- `theme`: `"dark"` or `"light"`
- `home`: must be an `http` or `https` URL
- `proxy`: optional `socks5://`, `socks5h://`, `http://` or `https://` URI
- `security`: `0` Standard, `1` Safer, `2` Safest

Proxy credentials are never shown in the UI — the status bar only displays the host.

## How it is put together

```
src/main.rs      whole browser: config, Tor, injected JS, WebKit setup, GTK UI
Cargo.toml
install.sh
assets/void.svg
```

The injected scripts are the interesting part:

- `NET_SCRIPT` runs at document start in every frame. It upgrades HTTP, blocks known tracker hosts at the fetch/XHR/beacon/socket/element level, and adds a `no-referrer` meta tag.
- `FINGERPRINT_SCRIPT` runs after that. It adds stable 1-LSB canvas noise, zeroes audio analysers, removes WebRTC and media capture, fixes screen/window/navigator values to Firefox 115 ESR on Windows, and clamps timers.

Engine-side settings live in `make_webview`; network isolation lives in `make_webcontext`; navigation policy and permission denials live in `attach_hooks`.

## Known limits

These are real, and worth knowing before trusting void with anything sensitive:

1. **TLS and HTTP/2 fingerprints are WebKit's, not Firefox's.** WebKit2GTK uses libsoup3 + GnuTLS, so cipher order, TLS extensions, HTTP/2 frame behaviour and header order differ from Tor Browser (which uses Necko + NSS). A determined fingerprinter can tell.
2. **Some subresource requests cannot be cancelled through the WebKit2GTK 2.0 API.** Navigation and script-level requests are blocked; a few engine-internal loads may still go out. The tracker list is a mitigation, not a guarantee.
3. **Per-tab circuit isolation depends on Tor honouring SOCKS username isolation.** Tor has `IsolateSOCKSAuth` on by default; if your Tor config disables it, tabs share circuits.
4. **WebKit is not Tor Browser.** Different rendering engine, different patch level. Use Tor Browser for high-risk work.
5. **Downloads and file uploads are blocked.** That is deliberate, but it means some sites won't fully work.

## Verification

Quick checks after building:

```bash
void --tor
```

Then visit:

- `https://check.torproject.org` — exit node and Tor status
- `https://coveryourtracks.eff.org` — canvas / fingerprint surface
- `https://browserleaks.com/canvas`
- `https://browserleaks.com/webrtc` — should report blocked
- `https://browserleaks.com/javascript`
- `https://tls.peet.ws/api/all` — compare TLS fingerprint against Tor Browser

Open two tabs to different sites and confirm different exit IPs; click **new id** and confirm the exit IP changes again.

## License

MIT — see [LICENSE](LICENSE).

made by Ivoryy06 ♡
