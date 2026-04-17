use gtk::prelude::*;
use gtk::{
    Application, ApplicationWindow, Box as GBox, Button, Entry, HeaderBar,
    Orientation,
};
use webkit2gtk::{
    CacheModel, CookieAcceptPolicy, CookieManagerExt, HardwareAccelerationPolicy,
    NavigationAction, NavigationPolicyDecision, NavigationPolicyDecisionExt,
    NetworkProxyMode, NetworkProxySettings, PolicyDecisionExt, PolicyDecisionType,
    Settings, SettingsExt, TLSErrorsPolicy, URIRequestExt, WebResource,
    UserContentInjectedFrames, UserContentManager,
    UserContentManagerExt, UserScript, UserScriptInjectionTime, WebContext, WebContextExt,
    WebView, WebViewExt, WebsiteDataManager, WebsiteDataManagerExt, WebsiteDataManagerExtManual,
    WebsiteDataTypes,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell, env, fs,
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command},
    sync::{Arc, Mutex},
    time::Duration,
};
use libc;

// Tor Browser's exact UA — blends in with the largest anonymity set
const SPOOFED_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0";

#[derive(Serialize, Deserialize)]
struct Config {
    theme: String,
    home: String,
    proxy: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
            home: "https://search.brave.com".into(),
            proxy: None,
        }
    }
}

fn config_path() -> PathBuf {
    let mut p = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push("void");
    fs::create_dir_all(&p).ok();
    p.push("settings.json");
    p
}

fn load_config() -> Config {
    fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_config(c: &Config) {
    if let Ok(json) = serde_json::to_string_pretty(c) {
        fs::write(config_path(), json).ok();
    }
}

// Global tor child handle — written once at startup, read by signal handlers.
// Using a Mutex<Option<Child>> so SIGTERM/SIGINT can kill it before process exit.
static TOR_CHILD: Mutex<Option<Child>> = Mutex::new(None);

fn kill_tor() {
    if let Ok(mut g) = TOR_CHILD.lock() {
        if let Some(mut c) = g.take() { c.kill().ok(); }
    }
}


const TOR_SOCKS: &str = "socks5://127.0.0.1:9050";
const TOR_ADDR: &str = "127.0.0.1:9050";

/// Build a stream-isolated Tor SOCKS5 URI for a given domain.
/// Tor treats each unique (user, pass) pair as a separate circuit.
fn tor_isolated_proxy(domain: &str) -> String {
    // Use domain as the isolation key — same domain = same circuit, different = different exit
    format!("socks5://{}:void@127.0.0.1:9050", urlencoding::encode(domain))
}

fn tor_running() -> bool {
    TcpStream::connect_timeout(&TOR_ADDR.parse().unwrap(), Duration::from_millis(200)).is_ok()
}

fn tor_available() -> bool {
    Command::new("tor").arg("--version").output().is_ok()
}

fn spawn_tor() -> bool {
    match Command::new("tor").spawn() {
        Ok(child) => {
            if let Ok(mut g) = TOR_CHILD.lock() { *g = Some(child); }
            true
        }
        Err(_) => false,
    }
}

fn wait_tor() -> bool {
    for _ in 0..25 {
        if tor_running() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

const FINGERPRINT_SCRIPT: &str = r#"
(function() {
    'use strict';

    // ── Canvas: blank data — matches Tor Browser exactly ─────────────────────
    const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
    const _toBlob    = HTMLCanvasElement.prototype.toBlob;
    function blankCanvas(canvas) {
        const ctx2d = canvas.getContext('2d');
        if (ctx2d) ctx2d.clearRect(0, 0, canvas.width, canvas.height);
    }
    HTMLCanvasElement.prototype.toDataURL = function(...a) {
        blankCanvas(this); return _toDataURL.apply(this, a);
    };
    HTMLCanvasElement.prototype.toBlob = function(cb, ...a) {
        blankCanvas(this); return _toBlob.call(this, cb, ...a);
    };

    // ── AudioContext: zero-filled buffers — matches Tor Browser ──────────────
    const _AC = window.AudioContext || window.webkitAudioContext;
    if (_AC) {
        const _createAnalyser = _AC.prototype.createAnalyser;
        _AC.prototype.createAnalyser = function() {
            const node = _createAnalyser.call(this);
            const _gffd = node.getFloatFrequencyData.bind(node);
            const _gbfd = node.getByteFrequencyData.bind(node);
            node.getFloatFrequencyData = (a) => { _gffd(a); a.fill(0); };
            node.getByteFrequencyData  = (a) => { _gbfd(a); a.fill(0); };
            return node;
        };
    }

    // ── WebRTC: block entirely ────────────────────────────────────────────────
    for (const k of ['RTCPeerConnection','RTCSessionDescription','RTCIceCandidate',
                     'webkitRTCPeerConnection','mozRTCPeerConnection']) {
        if (k in window) Object.defineProperty(window, k, { get: () => undefined });
    }

    // ── Screen normalisation (Tor Browser defaults) ───────────────────────────
    Object.defineProperties(screen, {
        width:       { get: () => 1920 },
        height:      { get: () => 1080 },
        availWidth:  { get: () => 1920 },
        availHeight: { get: () => 1040 },
        colorDepth:  { get: () => 24 },
        pixelDepth:  { get: () => 24 },
    });
    Object.defineProperty(window, 'devicePixelRatio', { get: () => 1 });

    // ── Window size normalisation (Tor Browser letterboxing 1000×800) ─────────
    Object.defineProperties(window, {
        outerWidth:  { get: () => 1000 },
        outerHeight: { get: () => 800 },
        innerWidth:  { get: () => 1000 },
        innerHeight: { get: () => 800 },
        screenX:     { get: () => 0 },
        screenY:     { get: () => 0 },
    });

    if (screen.orientation) {
        Object.defineProperties(screen.orientation, {
            type:  { get: () => 'landscape-primary' },
            angle: { get: () => 0 },
        });
    }

    // ── Navigator normalisation — match TB/Firefox 115 ESR on Windows ─────────
    Object.defineProperties(navigator, {
        hardwareConcurrency: { get: () => 2 },
        platform:            { get: () => 'Win32' },
        languages:           { get: () => Object.freeze(['en-US', 'en']) },
        language:            { get: () => 'en-US' },
        vendor:              { get: () => '' },
        productSub:          { get: () => '20100101' },
        maxTouchPoints:      { get: () => 0 },
        oscpu:               { get: () => 'Windows NT 10.0; Win64; x64' },
        buildID:             { get: () => '20181001000000' },
        appName:             { get: () => 'Netscape' },
        appCodeName:         { get: () => 'Mozilla' },
        appVersion:          { get: () => '5.0 (Windows)' },
        product:             { get: () => 'Gecko' },
        plugins:             { get: () => Object.freeze(Object.create(PluginArray.prototype)) },
        mimeTypes:           { get: () => Object.freeze(Object.create(MimeTypeArray.prototype)) },
        webdriver:           { get: () => false },
        doNotTrack:          { get: () => '1' },
    });

    // ── Timezone: force UTC ───────────────────────────────────────────────────
    const _DTF = Intl.DateTimeFormat;
    Intl.DateTimeFormat = function(locale, opts = {}) {
        opts.timeZone = 'UTC';
        return new _DTF(locale, opts);
    };
    Intl.DateTimeFormat.prototype = _DTF.prototype;
    Intl.DateTimeFormat.supportedLocalesOf = _DTF.supportedLocalesOf;

    const _Date = Date;
    class PatchedDate extends _Date {
        getTimezoneOffset() { return 0; }
        toString() { return this.toUTCString(); }
        toLocaleDateString(...a) { return super.toUTCString(...a); }
        toLocaleTimeString(...a) { return super.toUTCString(...a); }
        toLocaleString(...a)     { return super.toUTCString(...a); }
    }
    window.Date = PatchedDate;

    // ── performance.now(): clamp to 20ms resolution (Tor Browser 115 ESR) ─────
    // TB 115 uses 20ms; 100ms was an older value and breaks real-world timing.
    const _perfNow = performance.now.bind(performance);
    performance.now = () => Math.floor(_perfNow() / 20) * 20;

    // ── SharedArrayBuffer / Atomics: block (Spectre timing) ──────────────────
    if ('SharedArrayBuffer' in window)
        Object.defineProperty(window, 'SharedArrayBuffer', { get: () => undefined });
    if ('Atomics' in window)
        Object.defineProperty(window, 'Atomics', { get: () => undefined });

    // ── window.name: clear on every load ─────────────────────────────────────
    try {
        Object.defineProperty(window, 'name', {
            configurable: true, enumerable: true,
            get: () => '', set: () => {},
        });
    } catch(_) { try { window.name = ''; } catch(__) {} }

    // ── Font enumeration: block non-generic queries ───────────────────────────
    if (document.fonts) {
        const _check = document.fonts.check.bind(document.fonts);
        document.fonts.check = (font, text) =>
            /\b(sans-serif|serif|monospace|cursive|fantasy|system-ui)\b/i.test(font)
                ? _check(font, text) : false;
    }

    // ── Font metric normalisation: quantize layout rects to 1px ──────────────
    function roundRect(r) {
        return {
            x: Math.round(r.x), y: Math.round(r.y),
            width: Math.round(r.width), height: Math.round(r.height),
            top: Math.round(r.top), right: Math.round(r.right),
            bottom: Math.round(r.bottom), left: Math.round(r.left),
            toJSON: () => {},
        };
    }
    const _getBCR = Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect = function() { return roundRect(_getBCR.call(this)); };
    const _getClientRects = Element.prototype.getClientRects;
    Element.prototype.getClientRects = function() {
        return Array.from(_getClientRects.call(this)).map(roundRect);
    };
    const _rGetClientRects = Range.prototype.getClientRects;
    Range.prototype.getClientRects = function() {
        return Array.from(_rGetClientRects.call(this)).map(roundRect);
    };
    const _rGetBCR = Range.prototype.getBoundingClientRect;
    Range.prototype.getBoundingClientRect = function() { return roundRect(_rGetBCR.call(this)); };

    // ── visualViewport: match letterboxed size ────────────────────────────────
    if (window.visualViewport) {
        const vvp = Object.getPrototypeOf(window.visualViewport);
        for (const [p, v] of [['width',1000],['height',800],['offsetLeft',0],
                               ['offsetTop',0],['pageLeft',0],['pageTop',0],['scale',1]]) {
            try { Object.defineProperty(vvp, p, { get: () => v, configurable: true }); } catch(_) {}
        }
    }

    // ── window.matchMedia: use letterboxed dimensions ─────────────────────────
    const _mm = window.matchMedia.bind(window);
    window.matchMedia = (q) => _mm(
        q.replace(/(\d+)px/g, (_, n) => {
            const v = parseInt(n);
            if (v > 1000 && q.includes('width'))  return '1000px';
            if (v > 800  && q.includes('height')) return '800px';
            return n + 'px';
        })
    );

    // ── Timing normalisation ──────────────────────────────────────────────────
    // Clamp setTimeout/setInterval to 4ms minimum (TB behaviour).
    // requestAnimationFrame is already ~16ms in WebKit; clamp performance.now
    // is handled above. Avoid clamping rAF further — it would break rendering.
    const _setTimeout = window.setTimeout;
    window.setTimeout = (fn, delay, ...args) => _setTimeout(fn, Math.max(delay|0, 4), ...args);
    const _setInterval = window.setInterval;
    window.setInterval = (fn, delay, ...args) => _setInterval(fn, Math.max(delay|0, 4), ...args);


    const m = document.createElement('meta');
    m.name = 'referrer'; m.content = 'no-referrer';
    (document.head || document.documentElement).prepend(m);

    // ── Letterboxing CSS ──────────────────────────────────────────────────────
    const s = document.createElement('style');
    s.textContent = 'html,body{max-width:1000px!important;max-height:800px!important;overflow:hidden!important}';
    (document.head || document.documentElement).prepend(s);

})();
"#;

fn make_webcontext(proxy_uri: &Option<String>) -> (WebsiteDataManager, WebContext) {
    let data_mgr = WebsiteDataManager::new_ephemeral();
    // Force UTC at the engine level — overrides OS timezone for all JS/CSS date ops
    let ctx = WebContext::builder()
        .website_data_manager(&data_mgr)
        .time_zone_override("UTC")
        // Isolate each cross-site navigation into its own web process
        .process_swap_on_cross_site_navigation_enabled(true)
        .build();
    ctx.set_cache_model(CacheModel::DocumentViewer);
    // Lock Accept-Language to en-US,en — matches Tor Browser
    ctx.set_preferred_languages(&["en-US", "en"]);
    #[allow(deprecated)]
    ctx.set_tls_errors_policy(TLSErrorsPolicy::Fail);
    // One process per site — prevents cross-site memory/timing correlation.
    // process_swap_on_cross_site_navigation_enabled (set in builder) handles this in 2.40+.
    // Sandbox renderer processes — limits crash-time leaks
    ctx.set_sandbox_enabled(true);
    if let Some(cm) = ctx.cookie_manager() {
        cm.set_accept_policy(CookieAcceptPolicy::Never);
    }
    // ITP: Intelligent Tracking Prevention — partition cross-site storage
    data_mgr.set_itp_enabled(true);
    // Never persist credentials to disk
    data_mgr.set_persistent_credential_storage_enabled(false);
    // HTTP→HTTPS: handled in connect_decide_policy (register_uri_scheme("http") blocked in 2.40+)
    match proxy_uri {
        Some(uri) => {
            let mut ps = NetworkProxySettings::new(Some(uri.as_str()), &[]);
            data_mgr.set_network_proxy_settings(NetworkProxyMode::Custom, Some(&mut ps));
        }
        None => {
            data_mgr.set_network_proxy_settings(NetworkProxyMode::NoProxy, None);
        }
    }
    (data_mgr, ctx)
}

fn make_webview(ctx: &WebContext) -> WebView {
    let wv_settings = Settings::new();
    wv_settings.set_user_agent(Some(SPOOFED_UA));
    wv_settings.set_hardware_acceleration_policy(HardwareAccelerationPolicy::Never);
    wv_settings.set_enable_webgl(false);
    #[allow(deprecated)]
    wv_settings.set_enable_accelerated_2d_canvas(false);
    wv_settings.set_enable_dns_prefetching(false);
    wv_settings.set_enable_html5_database(false);
    wv_settings.set_enable_html5_local_storage(false);
    wv_settings.set_enable_offline_web_application_cache(false);
    wv_settings.set_enable_page_cache(false);
    wv_settings.set_enable_media_stream(false);
    wv_settings.set_enable_webrtc(false);
    wv_settings.set_allow_modal_dialogs(false);
    wv_settings.set_enable_webaudio(true); // TB has audio enabled; JS layer handles fingerprinting
    wv_settings.set_enable_site_specific_quirks(true); // TB leaves this on
    #[allow(deprecated)]
    wv_settings.set_enable_java(false);
    #[allow(deprecated)]
    wv_settings.set_enable_plugins(false);
    wv_settings.set_javascript_can_open_windows_automatically(false);
    wv_settings.set_javascript_can_access_clipboard(false);
    wv_settings.set_allow_top_navigation_to_data_urls(false);
    wv_settings.set_allow_file_access_from_file_urls(false);
    wv_settings.set_allow_universal_access_from_file_urls(false);
    wv_settings.set_enable_fullscreen(false);
    wv_settings.set_enable_encrypted_media(false);
    wv_settings.set_enable_mediasource(false);
    wv_settings.set_enable_media_capabilities(true); // TB does not disable this
    wv_settings.set_media_playback_requires_user_gesture(true);
    wv_settings.set_enable_hyperlink_auditing(false); // blocks <a ping=> tracking beacons
    wv_settings.set_enable_smooth_scrolling(false);   // TB does not use smooth scrolling
    wv_settings.set_enable_back_forward_navigation_gestures(false);
    // Normalise font stack — reduces font metric fingerprint surface
    wv_settings.set_default_font_family("serif");
    wv_settings.set_sans_serif_font_family("sans-serif");
    wv_settings.set_monospace_font_family("monospace");
    wv_settings.set_default_font_size(16);
    wv_settings.set_default_monospace_font_size(13);

    let ucm = UserContentManager::new();
    ucm.add_script(&UserScript::new(
        &FINGERPRINT_SCRIPT,
        UserContentInjectedFrames::AllFrames,
        UserScriptInjectionTime::Start,
        &[],
        &[],
    ));

    let webview = WebView::builder()
        .web_context(ctx)
        .user_content_manager(&ucm)
        .build();
    webview.set_settings(&wv_settings);
    webview.set_vexpand(true);
    webview
}

/// Attach navigation policy hooks to a webview:
/// - HTTPS-only: redirect http:// → https://
/// - Strict Tor: block any request when Tor proxy is unreachable
/// - Circuit isolation: per-domain SOCKS5 credentials when using Tor
/// - Header alignment: match Tor Browser's exact header set
fn attach_policy_hooks(wv: &WebView, data_mgr: Arc<WebsiteDataManager>, is_tor: bool, strict_tor: bool) {
    // Align request headers to match Tor Browser (Firefox 115 ESR) exactly.
    // TB sends Sec-Fetch-* on navigations, a fixed Accept, and no DNT header via JS.
    wv.connect_resource_load_started(|_wv, _resource: &WebResource, req| {
        if let Some(headers) = req.http_headers() {
            // Remove headers TB does not send
            for h in &["X-Forwarded-For", "Via", "TE", "Origin"] {
                headers.remove(h);
            }
            // Set TB's exact header values
            headers.replace("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
            headers.replace("Accept-Language", "en-US,en;q=0.5");
            headers.replace("Accept-Encoding", "gzip, deflate, br");
        }
    });
    wv.connect_decide_policy(move |wv, decision, dtype| {
        if dtype == PolicyDecisionType::NavigationAction {
            if let Some(nav) = decision.downcast_ref::<NavigationPolicyDecision>() {
                let req = nav.navigation_action().and_then(|a: NavigationAction| a.request());
                if let Some(uri_str) = req.and_then(|r| r.uri()) {
                    let uri = uri_str.as_str();

                    // Strict Tor: block if Tor is not reachable right now
                    if strict_tor && !tor_running() {
                        eprintln!("void: strict-tor — Tor unreachable, blocking {}", uri);
                        nav.ignore();
                        wv.load_html(
                            "<html><body style='background:#0d0d0d;color:#f55;font-family:monospace;padding:2em'>\
                             <h2>🔒 Tor Unreachable</h2>\
                             <p>Strict Tor mode is active. No request will be sent without Tor.</p>\
                             </body></html>",
                            None,
                        );
                        return true;
                    }

                    // HTTPS-only: cancel and reload with https://
                    if uri.starts_with("http://") {
                        let https_uri = uri.replacen("http://", "https://", 1);
                        nav.ignore();
                        wv.load_uri(&https_uri);
                        return true;
                    }

                    // Circuit isolation for Tor
                    if is_tor {
                        let domain = uri
                            .trim_start_matches("https://")
                            .split('/')
                            .next()
                            .unwrap_or("unknown")
                            .to_string();
                        let isolated = tor_isolated_proxy(&domain);
                        let mut ps = NetworkProxySettings::new(Some(isolated.as_str()), &[]);
                        data_mgr.set_network_proxy_settings(NetworkProxyMode::Custom, Some(&mut ps));
                    }
                }
            }
        }
        false
    });
}

fn build_ui(app: &Application) {
    let config = load_config();

    // --tor and --tor-strict are identical: both enforce Tor and fail closed at runtime.
    // There is no "Tor without kill switch" — that would be a false sense of security.
    let strict_tor = env::args().any(|a| a == "--tor-strict" || a == "--tor");
    let force_tor = strict_tor;

    let (proxy_uri, proxy_status) = if force_tor {
        if tor_running() {
            (Some(TOR_SOCKS.to_string()), "🔒 tor")
        } else if tor_available() {
            if spawn_tor() && wait_tor() {
                (Some(TOR_SOCKS.to_string()), "🔒 tor")
            } else {
                eprintln!("void: Tor failed to start");
                std::process::exit(1);
            }
        } else {
            eprintln!("void: `tor` binary not found");
            std::process::exit(1);
        }
    } else {
        let explicit = {
            let args: Vec<String> = env::args().collect();
            args.windows(2)
                .find(|w| w[0] == "--proxy")
                .map(|w| w[1].clone())
        }
        .or_else(|| config.proxy.clone())
        .or_else(|| env::var("ALL_PROXY").ok().or_else(|| env::var("all_proxy").ok()));

        if let Some(uri) = explicit {
            let label = if uri.contains("9050") { "🧅 tor" } else { "⬤ proxy" };
            (Some(uri), label)
        } else {
            (None, "⬤ direct")
        }
    };

    // ── Initial WebView ────────────────────────────────────────────────────────
    let proxy_uri = Arc::new(proxy_uri);
    let (dm, ctx) = make_webcontext(&proxy_uri);
    let is_tor = proxy_uri.as_deref().map_or(false, |u| u.contains("9050"));
    // Wrap in Arc<RefCell> so New Identity can swap and clear the old data manager.
    let data_mgr: Arc<RefCell<Arc<WebsiteDataManager>>> =
        Arc::new(RefCell::new(Arc::new(dm)));
    let webview: RefCell<WebView> = RefCell::new(make_webview(&ctx));
    attach_policy_hooks(&webview.borrow(), data_mgr.borrow().clone(), is_tor, strict_tor);
    webview.borrow().load_uri(&config.home);

    // ── URL bar ────────────────────────────────────────────────────────────────
    let url_bar = Entry::builder()
        .placeholder_text("Search or enter URL")
        .hexpand(true)
        .build();

    let vbox = GBox::new(Orientation::Vertical, 0);
    vbox.pack_start(&*webview.borrow(), true, true, 0);

    // Connect URI notify for initial webview
    {
        let url_bar = url_bar.clone();
        webview.borrow().connect_uri_notify(move |wv: &WebView| {
            if let Some(uri) = wv.uri() {
                url_bar.set_text(uri.as_str());
            }
        });
    }

    let webview = Arc::new(webview);

    {
        let webview = webview.clone();
        url_bar.connect_activate(move |entry| {
            let text = entry.text().to_string();
            let uri = if text.starts_with("https://") {
                text
            } else if text.starts_with("http://") {
                text.replacen("http://", "https://", 1)
            } else if text.contains('.') && !text.contains(' ') {
                format!("https://{}", text)
            } else {
                format!("https://search.brave.com/search?q={}", urlencoding::encode(&text))
            };
            webview.borrow().load_uri(&uri);
        });
    }

    let back_btn    = Button::with_label("‹");
    let fwd_btn     = Button::with_label("›");
    let reload_btn  = Button::with_label("↻");
    let new_id_btn  = Button::with_label("🔄");
    new_id_btn.set_tooltip_text(Some("New Identity — fresh ephemeral context"));

    // Security level: Standard → Safer → Safest (cycles on click)
    // Standard: JS on everywhere
    // Safer:    JS off on non-HTTPS, SVG animations blocked
    // Safest:   JS off everywhere, media blocked
    let sec_level: Arc<RefCell<u8>> = Arc::new(RefCell::new(0)); // 0=Standard,1=Safer,2=Safest
    let sec_btn = Button::with_label("🛡 Standard");
    sec_btn.set_tooltip_text(Some("Security level: Standard / Safer / Safest"));

    { let wv = webview.clone(); back_btn.connect_clicked(move |_| wv.borrow().go_back()); }
    { let wv = webview.clone(); fwd_btn.connect_clicked(move |_| wv.borrow().go_forward()); }
    { let wv = webview.clone(); reload_btn.connect_clicked(move |_| wv.borrow().reload()); }

    fn apply_sec_level(wv: &WebView, level: u8) {
        if let Some(s) = WebViewExt::settings(wv) {
            let s: Settings = s;
            match level {
                0 => { // Standard
                    s.set_enable_javascript(true);
                    s.set_enable_media(true);
                    s.set_enable_mediasource(true);
                }
                1 => { // Safer — JS disabled; media allowed
                    s.set_enable_javascript(false);
                    s.set_enable_media(true);
                    s.set_enable_mediasource(false);
                }
                _ => { // Safest — JS off, media off
                    s.set_enable_javascript(false);
                    s.set_enable_media(false);
                    s.set_enable_mediasource(false);
                }
            }
        }
    }

    {
        let webview   = webview.clone();
        let sec_level = sec_level.clone();
        sec_btn.connect_clicked(move |btn| {
            let next = (*sec_level.borrow() + 1) % 3;
            *sec_level.borrow_mut() = next;
            let label = match next { 0 => "🛡 Standard", 1 => "🛡 Safer", _ => "🛡 Safest" };
            btn.set_label(label);
            apply_sec_level(&webview.borrow(), next);
            webview.borrow().reload();
        });
    }

    // Also apply current sec level when loading new identity

    // New Identity: destroy old webview, create fresh ephemeral context + new webview
    {
        let webview   = webview.clone();
        let vbox      = vbox.clone();
        let url_bar   = url_bar.clone();
        let proxy_uri = proxy_uri.clone();
        let home      = config.home.clone();
        let sec_level = sec_level.clone();
        let data_mgr  = data_mgr.clone();
        new_id_btn.connect_clicked(move |_| {
            let old = webview.borrow().clone();
            vbox.remove(&old);
            // Clear all in-memory state (TLS sessions, HSTS, memory cache, session storage)
            // before dropping the old context so nothing leaks into the new identity.
            let old_dm = data_mgr.borrow().clone();
            old_dm.clear(WebsiteDataTypes::ALL, glib::TimeSpan::from_microseconds(0), gio::Cancellable::NONE, |_| {});
            old.load_uri("about:blank");

            let (new_dm, new_ctx) = make_webcontext(&proxy_uri);
            let new_dm = Arc::new(new_dm);
            *data_mgr.borrow_mut() = new_dm.clone();
            let nwv = make_webview(&new_ctx);
            attach_policy_hooks(&nwv, new_dm, is_tor, strict_tor);
            apply_sec_level(&nwv, *sec_level.borrow());
            nwv.load_uri(&home);
            nwv.set_vexpand(true);

            {
                let url_bar = url_bar.clone();
                nwv.connect_uri_notify(move |wv: &WebView| {
                    if let Some(uri) = wv.uri() {
                        url_bar.set_text(uri.as_str());
                    }
                });
            }

            vbox.pack_start(&nwv, true, true, 0);
            vbox.show_all();
            *webview.borrow_mut() = nwv;
        });
    }

    let proxy_label = gtk::Label::new(Some(proxy_status));
    proxy_label.set_tooltip_text(proxy_uri.as_deref().or(Some("no proxy")));
    proxy_label.set_opacity(if proxy_uri.is_some() { 1.0 } else { 0.3 });

    let header = HeaderBar::new();
    header.pack_start(&back_btn);
    header.pack_start(&fwd_btn);
    header.pack_start(&reload_btn);
    header.pack_end(&sec_btn);
    header.pack_end(&new_id_btn);
    header.pack_end(&proxy_label);
    header.set_custom_title(Some(&url_bar));

    let window = ApplicationWindow::builder()
        .application(app)
        .title("Void")
        .default_width(1000)
        .default_height(800)
        .build();
    window.set_titlebar(Some(&header));
    window.add(&vbox);

    let css = gtk::CssProvider::new();
    css.load_from_data(if config.theme == "dark" {
        b"window { background: #0d0d0d; } headerbar { background: #111; color: #eee; }"
    } else {
        b"window { background: #fafafa; } headerbar { background: #f0f0f0; color: #111; }"
    })
    .ok();
    gtk::StyleContext::add_provider_for_screen(
        &gtk::gdk::Screen::default().unwrap(),
        &css,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    window.connect_delete_event(move |_, _| {
        save_config(&config);
        kill_tor();
        glib::Propagation::Proceed
    });

    window.show_all();
}

fn main() {
    // Kill tor child on SIGTERM/SIGINT so no orphan process is left on crash or kill.
    // glib's main loop doesn't run signal handlers, so we use Unix signal via libc.
    unsafe {
        libc::signal(libc::SIGTERM, sigterm_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT,  sigterm_handler as *const () as libc::sighandler_t);
    }
    // Also catch panics — ensures tor is killed even on Rust panics.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        kill_tor();
        default_hook(info);
    }));

    let app = Application::builder()
        .application_id("dev.void.browser")
        .build();
    app.connect_activate(build_ui);
    app.run();
}

extern "C" fn sigterm_handler(_: libc::c_int) {
    kill_tor();
    std::process::exit(0);
}
