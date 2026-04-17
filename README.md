# void

A privacy-focused web browser built on WebKit2GTK with Tor integration and comprehensive fingerprinting resistance. Designed to provide Tor Browser-level anonymity with a minimal, native GTK interface.

## Features

- **Strict Tor integration** — All traffic routed through Tor with runtime kill switch
- **Per-domain circuit isolation** — Each domain uses a separate Tor circuit
- **Comprehensive fingerprinting resistance** — JavaScript and engine-level protections matching Tor Browser
- **Ephemeral sessions** — No disk persistence; all data cleared on exit
- **New Identity** — Complete context reset with fresh Tor circuits
- **HTTPS-only** — Automatic HTTP→HTTPS upgrade
- **Security levels** — Standard/Safer/Safest modes (Tor Browser-style)
- **Clean shutdown** — Tor process killed on exit/crash/signal

## Installation

### Prerequisites

**System dependencies:**
```bash
# Debian/Ubuntu
sudo apt install build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev tor

# Fedora
sudo dnf install gcc pkg-config gtk3-devel webkit2gtk4.1-devel libsoup3-devel tor

# Arch
sudo pacman -S base-devel gtk3 webkit2gtk-4.1 libsoup3 tor
```

**Rust toolchain:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Build from Source

```bash
git clone https://github.com/yourusername/void.git
cd void
cargo build --release
```

The binary will be at `target/release/void`.

### Quick Install Script

```bash
./install.sh
```

This will:
1. Check system dependencies
2. Build the release binary
3. Install to `~/.local/bin/void`
4. Create a desktop entry at `~/.local/share/applications/void.desktop`

## Usage

### Basic Usage

```bash
# Direct connection (no proxy)
void

# Tor mode (strict — exits if Tor unavailable)
void --tor

# Custom proxy
void --proxy socks5://127.0.0.1:9050

# Tor mode (alternative flag name)
void --tor-strict
```

### Environment Variables

```bash
# Proxy via environment variable
ALL_PROXY=socks5://127.0.0.1:9050 void

# Or lowercase variant
all_proxy=socks5://127.0.0.1:9050 void
```

### Configuration

Config file: `~/.config/void/settings.json`

```json
{
  "theme": "dark",
  "home": "https://search.brave.com",
  "proxy": "socks5://127.0.0.1:9050"
}
```

**Options:**
- `theme`: `"dark"` or `"light"`
- `home`: Default homepage URL
- `proxy`: Default proxy URI (overridden by `--proxy` flag)

## Architecture

### Project Structure

```
void/
├── src/
│   └── main.rs              # Main application code (~700 lines)
├── Cargo.toml               # Rust dependencies
├── Cargo.lock               # Dependency lock file
├── FINGERPRINTING.md        # Fingerprinting resistance documentation
├── README.md                # This file
├── install.sh               # Installation script
└── .gitignore               # Git ignore rules
```

### How It Works

#### 1. Tor Integration

**Startup:**
- Checks if Tor is running on `127.0.0.1:9050`
- If not, spawns `tor` binary and waits up to 5 seconds
- Exits if Tor unavailable (strict mode — no fallback)

**Circuit Isolation:**
- Each domain gets unique SOCKS5 credentials: `socks5://{domain}:void@127.0.0.1:9050`
- Tor treats each credential pair as a separate circuit
- Different domains → different exit nodes → no correlation

**Runtime Kill Switch:**
- Before each navigation, checks if Tor is reachable
- If Tor drops, blocks request and shows error page
- No silent fallback to direct connection

**Clean Shutdown:**
- Tor child process stored in global `Mutex<Option<Child>>`
- Killed on window close, SIGTERM, SIGINT, and Rust panics
- Prevents orphaned Tor processes

#### 2. Fingerprinting Resistance

**JavaScript Layer** (`FINGERPRINT_SCRIPT`):
- Injected into every frame at document start
- Canvas: returns blank data (matches Tor Browser)
- AudioContext: zero-filled frequency buffers
- WebRTC: fully blocked
- Screen: fixed to 1920×1080
- Window: letterboxed to 1000×800 (Tor Browser standard)
- Navigator: spoofed to Firefox 115 ESR on Windows
- Timezone: forced UTC
- `performance.now()`: clamped to 20ms resolution
- `setTimeout`/`setInterval`: minimum 4ms
- SharedArrayBuffer/Atomics: blocked
- Font enumeration: only generic families
- Layout rects: quantized to 1px (removes sub-pixel metrics)

**Engine Layer** (WebKit2GTK settings):
- User-Agent: Tor Browser's exact string
- Hardware acceleration: disabled
- WebGL: disabled
- Storage APIs: disabled (localStorage, IndexedDB, etc.)
- WebRTC: disabled at engine level
- Hyperlink auditing: disabled
- Process isolation: per-site renderer processes
- Sandbox: renderer processes sandboxed
- ITP: enabled (storage partitioning)

**Network Layer:**
- HTTPS-only: all HTTP redirected to HTTPS
- Headers: match Tor Browser (Accept, Accept-Language, Accept-Encoding)
- Header removal: X-Forwarded-For, Via, TE, Origin
- Referrer: no-referrer policy

#### 3. Identity Isolation

**Ephemeral Context:**
- `WebsiteDataManager::new_ephemeral()` — no disk persistence
- Cookies: never accepted
- Credentials: never stored
- Cache: memory-only, cleared on exit

**New Identity:**
1. Clears all in-memory state: `WebsiteDataTypes::ALL`
   - Memory cache
   - HSTS cache
   - Session storage
   - TLS session data
2. Destroys old WebView and WebContext
3. Creates fresh ephemeral context
4. Loads home page with new Tor circuits

#### 4. Security Levels

**Standard:**
- JavaScript: enabled
- Media: enabled

**Safer:**
- JavaScript: disabled
- Media: enabled
- MediaSource: disabled

**Safest:**
- JavaScript: disabled
- Media: disabled
- MediaSource: disabled

Levels preserved across New Identity resets.

### Code Organization

**`main.rs` structure:**

```rust
// Constants
const SPOOFED_UA: &str = "...";           // Tor Browser UA
const TOR_SOCKS: &str = "...";            // Tor SOCKS5 address
const FINGERPRINT_SCRIPT: &str = "...";   // JS injection

// Configuration
struct Config { theme, home, proxy }
fn load_config() / save_config()

// Tor management
static TOR_CHILD: Mutex<Option<Child>>
fn tor_running() / spawn_tor() / kill_tor()
fn tor_isolated_proxy(domain) -> String

// WebKit setup
fn make_webcontext(proxy_uri) -> (WebsiteDataManager, WebContext)
fn make_webview(ctx) -> WebView
fn attach_policy_hooks(wv, data_mgr, is_tor, strict_tor)

// UI
fn build_ui(app: &Application)
fn main()
```

**Key data structures:**

- `Arc<RefCell<Arc<WebsiteDataManager>>>` — Allows New Identity to swap and clear old manager
- `Arc<RefCell<WebView>>` — Allows New Identity to swap WebView
- `static Mutex<Option<Child>>` — Global Tor child for signal handlers

### Dependencies

**Core:**
- `gtk` (0.18) — GTK+ 3 bindings
- `webkit2gtk` (2.0) — WebKit2GTK bindings with v2_40 features
- `glib` / `gio` (0.18) — GLib/GIO bindings

**Networking:**
- `soup3` (0.5) — libsoup3 bindings (HTTP stack)

**Utilities:**
- `serde` / `serde_json` — Config serialization
- `dirs` — XDG directory paths
- `urlencoding` — URL encoding for SOCKS5 credentials
- `libc` — Signal handling (SIGTERM/SIGINT)

## Verification

See [`FINGERPRINTING.md`](FINGERPRINTING.md) for:
- Complete list of implemented protections
- Known gaps (TLS fingerprint, HTTP/2 behavior)
- Verification checklist with test suite URLs
- Comparison to Tor Browser

**Quick verification:**
```bash
# Run void with Tor
void --tor

# Visit these test suites:
# - https://coveryourtracks.eff.org
# - https://browserleaks.com/canvas
# - https://browserleaks.com/webrtc
# - https://check.torproject.org
```

## Known Limitations

1. **TLS fingerprint:** WebKit2GTK uses GnuTLS, not Firefox's NSS library
   - Different cipher suite ordering
   - Different TLS extension behavior
   - Detectable by advanced fingerprinting

2. **HTTP/2 behavior:** libsoup3 implementation differs from Firefox
   - Different frame ordering
   - Different priority handling

3. **Header ordering:** libsoup3 controls header order, not exposed via bindings

4. **Rendering engine:** WebKit vs Gecko
   - Mitigated by letterboxing and layout quantization
   - Still detectable by advanced techniques

See [`FINGERPRINTING.md`](FINGERPRINTING.md) for mitigation options.

## Security Considerations

**Threat Model:**

✅ **Protects against:**
- JavaScript fingerprinting (canvas, WebRTC, fonts, etc.)
- Network-level correlation (via Tor circuit isolation)
- Disk-based tracking (ephemeral sessions)
- Timing attacks (performance.now clamping, setTimeout flooring)

⚠️ **Partial protection:**
- TLS fingerprinting (GnuTLS vs NSS difference)
- HTTP/2 fingerprinting (libsoup3 vs Firefox difference)

❌ **Does NOT protect against:**
- Malicious exit nodes (use HTTPS)
- Browser exploits (keep WebKit updated)
- User behavior correlation (use Tor Browser for high-risk activities)

**Recommendations:**

- Use `--tor` flag for all privacy-sensitive browsing
- Click "New Identity" between unrelated browsing sessions
- Use Tor Browser for high-risk activities (journalism, activism, etc.)
- Keep system packages updated (webkit2gtk, tor)

## Development

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run directly
cargo run -- --tor

# Run tests (if any)
cargo test
```

### Code Style

- Follow Rust standard style (`rustfmt`)
- Keep functions focused and documented
- Prefer explicit over implicit
- Comment non-obvious behavior

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly (especially fingerprinting tests)
5. Submit a pull request

## License

[Your chosen license here]

## Acknowledgments

- **Tor Project** — For Tor Browser's fingerprinting resistance research
- **WebKit** — For the rendering engine
- **GTK Project** — For the UI toolkit

## Disclaimer

This browser is experimental. While it implements many Tor Browser protections, it has not undergone the same level of security review. For high-risk activities, use the official Tor Browser.

The TLS and HTTP/2 fingerprints differ from Firefox due to underlying library differences (GnuTLS/libsoup3 vs NSS/Necko). Advanced fingerprinting systems may detect this.

Use at your own risk.
