use gtk::prelude::*;
use gtk::{
    Application, ApplicationWindow, Box as GBox, Button, ComboBoxText, Entry, HeaderBar, Label,
    Notebook, Orientation,
};
use webkit2gtk::{
    AuthenticationRequestExt, CacheModel, CookieAcceptPolicy, CookieManagerExt, DownloadExt,
    FileChooserRequestExt, HardwareAccelerationPolicy, LoadEvent, NavigationPolicyDecision,
    NavigationPolicyDecisionExt, NetworkProxyMode, NetworkProxySettings, PermissionRequestExt,
    PolicyDecisionExt, PolicyDecisionType, Settings, SettingsExt, TLSErrorsPolicy, URIRequestExt,
    UserContentInjectedFrames, UserContentManager, UserContentManagerExt, UserScript,
    UserScriptInjectionTime, WebContext, WebContextExt, WebView, WebViewExt, WebsiteDataManager,
    WebsiteDataManagerExt,
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use std::{env, fs};

const SPOOFED_UA: &str = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0";
const DEFAULT_HOME: &str = "https://search.brave.com/";
const TOR_ADDR: &str = "127.0.0.1:9050";
const LETTERBOX_W: i32 = 1000;
const LETTERBOX_H: i32 = 800;

/// Hosts (and their subdomains) that never get a request from void.
/// Kept host-only so entries can't accidentally match a page path.
const BLOCK_HOSTS: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googletagmanager.com",
    "googletagservices.com",
    "google-analytics.com",
    "googleadservices.com",
    "adservice.google.com",
    "2mdn.net",
    "connect.facebook.net",
    "analytics.twitter.com",
    "ads.twitter.com",
    "ads.linkedin.com",
    "amazon-adsystem.com",
    "adnxs.com",
    "adsrvr.org",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",
    "criteo.com",
    "criteo.net",
    "outbrain.com",
    "taboola.com",
    "scorecardresearch.com",
    "quantserve.com",
    "chartbeat.com",
    "hotjar.com",
    "mouseflow.com",
    "fullstory.com",
    "mixpanel.com",
    "segment.com",
    "segment.io",
    "amplitude.com",
    "heap.io",
    "intercom.io",
    "intercomcdn.com",
    "cdn.mxpnl.com",
    "bat.bing.com",
    "clarity.ms",
    "mc.yandex.ru",
    "mc.yandex.com",
    "ads.yahoo.com",
    "media.net",
    "bidswitch.net",
    "smartadserver.com",
    "appnexus.com",
    "lijit.com",
    "sovrn.com",
    "sharethrough.com",
    "triplelift.com",
    "indexexchange.com",
    "33across.com",
    "spotxchange.com",
    "spotx.tv",
    "teads.tv",
    "yieldmo.com",
    "undertone.com",
    "mathtag.com",
    "bluekai.com",
    "krxd.net",
    "demdex.net",
    "omtrdc.net",
    "moatads.com",
    "doubleverify.com",
    "adsafeprotected.com",
    "sizmek.com",
    "flashtalking.com",
    "serving-sys.com",
    "turn.com",
    "eyeota.net",
    "exelator.com",
    "lotame.com",
    "addthis.com",
    "sharethis.com",
];

// ── process state ────────────────────────────────────────────────────────────

static TOR_CHILD: Mutex<Option<Child>> = Mutex::new(None);
static TOR_UP: AtomicBool = AtomicBool::new(false);
static TOR_MONITOR: AtomicBool = AtomicBool::new(false);
static TAB_COUNTER: AtomicU64 = AtomicU64::new(1);
static IDENTITY_EPOCH: AtomicU64 = AtomicU64::new(1);

type TabOpener = Rc<RefCell<Option<Rc<dyn Fn(&str)>>>>;

#[derive(Clone)]
enum NetMode {
    Direct,
    Tor,
    Custom(String),
}

impl NetMode {
    fn is_tor(&self) -> bool {
        matches!(self, NetMode::Tor)
    }

    fn proxy_for(&self, circuit: &str) -> Option<String> {
        match self {
            NetMode::Direct => None,
            NetMode::Tor => Some(format!("socks5://{}:x@{}", circuit, TOR_ADDR)),
            NetMode::Custom(uri) => Some(uri.clone()),
        }
    }

    fn label(&self) -> String {
        match self {
            NetMode::Direct => "direct".to_string(),
            NetMode::Tor => "tor".to_string(),
            NetMode::Custom(uri) => format!("proxy · {}", redact_proxy(uri)),
        }
    }
}

// ── config ───────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct Config {
    theme: String,
    home: String,
    proxy: Option<String>,
    security: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
            home: DEFAULT_HOME.into(),
            proxy: None,
            security: 0,
        }
    }
}

fn config_dir() -> PathBuf {
    let mut p = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push("void");
    p
}

fn config_path() -> PathBuf {
    config_dir().join("settings.json")
}

fn valid_proxy(uri: &str) -> bool {
    ["socks5://", "socks5h://", "http://", "https://"]
        .iter()
        .any(|p| uri.starts_with(p))
}

fn normalize_home(home: &str) -> String {
    let h = home.trim();
    if h.is_empty() {
        return DEFAULT_HOME.into();
    }
    match target_for(h, DEFAULT_HOME) {
        Some(u) if u.starts_with("http://") || u.starts_with("https://") => u,
        _ => DEFAULT_HOME.into(),
    }
}

fn load_config() -> Config {
    let mut c: Config = fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if c.theme != "light" {
        c.theme = "dark".into();
    }
    c.home = normalize_home(&c.home);
    if c.security > 2 {
        c.security = 0;
    }
    if let Some(p) = c.proxy.as_ref() {
        if !valid_proxy(p) {
            c.proxy = None;
        }
    }
    c
}

fn save_config(c: &Config) {
    let dir = config_dir();
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }

    let json = match serde_json::to_string_pretty(c) {
        Ok(j) => j,
        Err(_) => return,
    };
    let path = config_path();
    let tmp = dir.join("settings.json.tmp");
    if fs::write(&tmp, json).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    let _ = fs::rename(&tmp, &path);
}

// ── urls ─────────────────────────────────────────────────────────────────────

fn authority_of(uri: &str) -> Option<&str> {
    let rest = uri.split_once("://")?.1;
    Some(
        rest.split(|c| c == '/' || c == '?' || c == '#')
            .next()
            .unwrap_or(rest),
    )
}

fn host_of(uri: &str) -> Option<String> {
    let auth = authority_of(uri)?;
    let host_port = auth.rsplit('@').next()?;
    if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        let host = &host_port[1..end];
        return if host.is_empty() {
            None
        } else {
            Some(host.to_ascii_lowercase())
        };
    }
    let host = host_port.split(':').next()?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn explicit_port(uri: &str) -> Option<u16> {
    let auth = authority_of(uri)?;
    let host_port = auth.rsplit('@').next()?;
    if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        return host_port[end + 1..].strip_prefix(':')?.parse().ok();
    }
    host_port.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}

fn is_local_host(host: &str) -> bool {
    let h = host
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".onion")
        || h.ends_with(".i2p")
    {
        return true;
    }
    if h == "::1" || h == "127.0.0.1" {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        };
    }
    false
}

fn is_tracker(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    BLOCK_HOSTS.iter().any(|d| {
        h == *d
            || (h.len() > d.len() && h.ends_with(*d) && h.as_bytes()[h.len() - d.len() - 1] == b'.')
    })
}

fn upgrade_http(uri: &str) -> String {
    if !uri.starts_with("http://") {
        return uri.to_string();
    }
    let host = match host_of(uri) {
        Some(h) => h,
        None => return uri.to_string(),
    };
    if is_local_host(&host) {
        return uri.to_string();
    }
    match explicit_port(uri) {
        None | Some(80) | Some(443) => format!("https://{}", &uri[7..]),
        _ => uri.to_string(),
    }
}

fn target_for(input: &str, home: &str) -> Option<String> {
    let t = input.trim();
    if t.is_empty() {
        return Some(home.to_string());
    }
    let lower = t.to_ascii_lowercase();
    if lower == "about:blank" {
        return Some("about:blank".into());
    }

    if let Some(i) = t.find("://") {
        let scheme = t[..i].to_ascii_lowercase();
        return match scheme.as_str() {
            "http" | "https" => Some(upgrade_http(t)),
            _ => None,
        };
    }
    if lower.starts_with("about:") {
        return None;
    }

    let looks_like_host = !t.chars().any(char::is_whitespace)
        && (t.contains('.')
            || t.contains(':')
            || t.starts_with('[')
            || lower == "localhost");
    if looks_like_host {
        let with_scheme = format!("http://{}", t);
        let host = match host_of(&with_scheme) {
            Some(h) => h,
            None => return None,
        };
        if host.is_empty() {
            return None;
        }
        let port = explicit_port(&with_scheme);
        // "word:word" is a search, not a broken host:port.
        if t.contains(':') && !t.starts_with('[') && port.is_none() {
            return Some(format!(
                "https://search.brave.com/search?q={}",
                urlencoding::encode(t)
            ));
        }
        let scheme = if is_local_host(&host) || matches!(port, Some(p) if p != 443) {
            "http"
        } else {
            "https"
        };
        return Some(format!("{}://{}", scheme, t));
    }

    Some(format!(
        "https://search.brave.com/search?q={}",
        urlencoding::encode(t)
    ))
}

fn scheme_allowed(uri: &str) -> bool {
    let scheme = uri
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(scheme.as_str(), "http" | "https" | "about" | "blob")
}

fn redact_proxy(uri: &str) -> String {
    match uri.split_once("://") {
        Some((scheme, rest)) => {
            let authority = rest.split('/').next().unwrap_or(rest);
            let host = authority.rsplit('@').next().unwrap_or(authority);
            format!("{}://{}", scheme, host)
        }
        None => uri.to_string(),
    }
}

// ── tor ──────────────────────────────────────────────────────────────────────

fn tor_running() -> bool {
    match TOR_ADDR.parse() {
        Ok(addr) => TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok(),
        Err(_) => false,
    }
}

fn tor_available() -> bool {
    Command::new("tor")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn spawn_tor() -> bool {
    let mut cmd = Command::new("tor");
    cmd.arg("--SocksPort").arg("9050");

    // Make Tor die with void even if void is SIGKILLed.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                if libc::getppid() == 1 {
                    libc::_exit(0);
                }
                Ok(())
            });
        }
    }

    match cmd.spawn() {
        Ok(child) => {
            if let Ok(mut g) = TOR_CHILD.lock() {
                *g = Some(child);
            }
            true
        }
        Err(_) => false,
    }
}

fn wait_tor() -> bool {
    for _ in 0..75 {
        if tor_running() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn reap_tor() {
    if let Ok(mut g) = TOR_CHILD.lock() {
        let dead = match g.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(Some(_)) | Err(_)),
            None => false,
        };
        if dead {
            *g = None;
        }
    }
}

fn kill_tor() {
    if let Ok(mut g) = TOR_CHILD.lock() {
        if let Some(mut c) = g.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn start_tor_monitor() {
    if TOR_MONITOR.swap(true, Ordering::Relaxed) {
        return;
    }
    std::thread::spawn(|| loop {
        std::thread::sleep(Duration::from_secs(4));
        TOR_UP.store(tor_running(), Ordering::Relaxed);
        reap_tor();
    });
}

// ── injected: network guard ──────────────────────────────────────────────────

const NET_SCRIPT: &str = r#"
(function () {
    'use strict';

    var BLOCKED = [
        'doubleclick.net', 'googlesyndication.com', 'googletagmanager.com',
        'googletagservices.com', 'google-analytics.com', 'googleadservices.com',
        'adservice.google.com', '2mdn.net', 'connect.facebook.net',
        'analytics.twitter.com', 'ads.twitter.com', 'ads.linkedin.com',
        'amazon-adsystem.com', 'adnxs.com', 'adsrvr.org', 'rubiconproject.com',
        'pubmatic.com', 'openx.net', 'casalemedia.com', 'criteo.com', 'criteo.net',
        'outbrain.com', 'taboola.com', 'scorecardresearch.com', 'quantserve.com',
        'chartbeat.com', 'hotjar.com', 'mouseflow.com', 'fullstory.com',
        'mixpanel.com', 'segment.com', 'segment.io', 'amplitude.com', 'heap.io',
        'intercom.io', 'intercomcdn.com', 'cdn.mxpnl.com', 'bat.bing.com',
        'clarity.ms', 'mc.yandex.ru', 'mc.yandex.com', 'ads.yahoo.com', 'media.net',
        'bidswitch.net', 'smartadserver.com', 'appnexus.com', 'lijit.com',
        'sovrn.com', 'sharethrough.com', 'triplelift.com', 'indexexchange.com',
        '33across.com', 'spotxchange.com', 'spotx.tv', 'teads.tv', 'yieldmo.com',
        'undertone.com', 'mathtag.com', 'bluekai.com', 'krxd.net', 'demdex.net',
        'omtrdc.net', 'moatads.com', 'doubleverify.com', 'adsafeprotected.com',
        'sizmek.com', 'flashtalking.com', 'serving-sys.com', 'turn.com',
        'eyeota.net', 'exelator.com', 'lotame.com', 'addthis.com', 'sharethis.com'
    ];

    function hostOf(u) {
        try {
            return new URL(String(u), location.href).hostname.toLowerCase();
        } catch (e) {
            return '';
        }
    }

    function blocked(u) {
        var h = hostOf(u);
        if (!h) return false;
        for (var i = 0; i < BLOCKED.length; i++) {
            var d = BLOCKED[i];
            if (h === d || h.slice(-(d.length + 1)) === '.' + d) return true;
        }
        return false;
    }

    function localHost(h) {
        h = (h || '').toLowerCase();
        return h === 'localhost' || h.slice(-10) === '.localhost' ||
            h.slice(-6) === '.local' || h.slice(-6) === '.onion' ||
            h.slice(-4) === '.i2p' || h === '127.0.0.1' ||
            h === '::1' || h === '[::1]' || h.slice(0, 3) === '10.' ||
            h.slice(0, 8) === '192.168.' ||
            /^172\.(1[6-9]|2\d|3[01])\./.test(h);
    }

    // ── fetch / XHR / beacon / sockets ───────────────────────────────────────
    try {
        if (window.fetch) {
            var _fetch = window.fetch;
            window.fetch = function (input, init) {
                var u = typeof input === 'string' ? input : (input && input.url) || '';
                if (blocked(u)) {
                    return Promise.reject(new TypeError('Blocked by void'));
                }
                return _fetch.call(this, input, init);
            };
        }
    } catch (e) {}

    try {
        var _open = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (method, url) {
            if (blocked(url)) {
                this.__voidBlocked = true;
                return;
            }
            return _open.apply(this, arguments);
        };
        var _send = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function () {
            if (this.__voidBlocked) return;
            return _send.apply(this, arguments);
        };
    } catch (e) {}

    try {
        if (navigator.sendBeacon) {
            var _beacon = navigator.sendBeacon.bind(navigator);
            navigator.sendBeacon = function (url, data) {
                return blocked(url) ? false : _beacon(url, data);
            };
        }
    } catch (e) {}

    try {
        if (window.WebSocket) {
            var _WS = window.WebSocket;
            window.WebSocket = new Proxy(_WS, {
                construct: function (target, args) {
                    if (blocked(args[0])) {
                        throw new DOMException('Blocked by void', 'SecurityError');
                    }
                    return Reflect.construct(target, args);
                }
            });
        }
    } catch (e) {}

    try {
        if (window.EventSource) {
            var _ES = window.EventSource;
            window.EventSource = new Proxy(_ES, {
                construct: function (target, args) {
                    if (blocked(args[0])) {
                        throw new DOMException('Blocked by void', 'SecurityError');
                    }
                    return Reflect.construct(target, args);
                }
            });
        }
    } catch (e) {}

    // ── subresource elements ─────────────────────────────────────────────────
    try {
        var _setAttr = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function (name, value) {
            var n = String(name).toLowerCase();
            var tag = this.tagName ? String(this.tagName).toLowerCase() : '';
            if ((n === 'src' || n === 'href') &&
                (tag === 'img' || tag === 'iframe' || tag === 'script' ||
                 tag === 'source' || tag === 'link') &&
                blocked(value)) {
                return;
            }
            return _setAttr.call(this, name, value);
        };
    } catch (e) {}

    function guardSrc(proto) {
        try {
            var d = Object.getOwnPropertyDescriptor(proto, 'src');
            if (!d || !d.set) return;
            Object.defineProperty(proto, 'src', {
                configurable: true,
                enumerable: d.enumerable,
                get: d.get,
                set: function (v) {
                    if (blocked(v)) return;
                    d.set.call(this, v);
                }
            });
        } catch (e) {}
    }
    try {
        [HTMLImageElement, HTMLIFrameElement, HTMLScriptElement, HTMLSourceElement]
            .forEach(function (C) { if (C) guardSrc(C.prototype); });
    } catch (e) {}

    // ── https upgrade for clicks and form posts ──────────────────────────────
    function upgraded(u) {
        try {
            var url = new URL(u, location.href);
            if (url.protocol === 'http:' && !localHost(url.hostname)) {
                return 'https://' + url.href.slice(7);
            }
        } catch (e) {}
        return null;
    }

    document.addEventListener('click', function (e) {
        var el = e.target;
        var a = el && el.closest ? el.closest('a[href]') : null;
        if (!a) return;
        var next = upgraded(a.href);
        if (next) {
            e.preventDefault();
            location.href = next;
        }
    }, true);

    document.addEventListener('submit', function (e) {
        var f = e.target;
        if (!f || String(f.tagName).toUpperCase() !== 'FORM') return;
        var action = f.getAttribute('action') || location.href;
        var next = upgraded(action);
        if (next) f.setAttribute('action', next);
    }, true);

    // ── referrer ─────────────────────────────────────────────────────────────
    function addReferrer() {
        try {
            if (!document.head) {
                setTimeout(addReferrer, 0);
                return;
            }
            var m = document.createElement('meta');
            m.name = 'referrer';
            m.content = 'no-referrer';
            document.head.insertBefore(m, document.head.firstChild);
        } catch (e) {}
    }
    addReferrer();
})();
"#;

// ── injected: fingerprint normalisation ──────────────────────────────────────

const FINGERPRINT_SCRIPT: &str = r#"
(function () {
    'use strict';

    function define(obj, props) {
        Object.keys(props).forEach(function (k) {
            try {
                Object.defineProperty(obj, k, { get: props[k], configurable: true });
            } catch (e) {}
        });
    }

    // ── canvas: stable 1-LSB noise so the output is not hardware-unique ─────
    try {
        var seed = (Math.random() * 0x7fffffff) | 0;
        function noiseAt(i) {
            var x = (i ^ seed) >>> 0;
            x = Math.imul(x, 2654435761) >>> 0;
            x ^= x >>> 13;
            return x & 1;
        }
        function noisy(data) {
            for (var i = 0, p = 0; i < data.length; i += 4, p++) {
                var n = noiseAt(p);
                data[i] = (data[i] + n) & 255;
                data[i + 1] = (data[i + 1] + n) & 255;
                data[i + 2] = (data[i + 2] + n) & 255;
            }
            return data;
        }

        if (window.CanvasRenderingContext2D) {
            var _get = CanvasRenderingContext2D.prototype.getImageData;
            CanvasRenderingContext2D.prototype.getImageData = function () {
                var d = _get.apply(this, arguments);
                try { if (d && d.data) noisy(d.data); } catch (e) {}
                return d;
            };
        }

        function cloneNoisy(canvas) {
            try {
                if (!canvas.width || !canvas.height ||
                    canvas.width * canvas.height > 4000000) return canvas;
                var c = document.createElement('canvas');
                c.width = canvas.width;
                c.height = canvas.height;
                var g = c.getContext('2d');
                if (!g) return canvas;
                g.drawImage(canvas, 0, 0);
                var d = g.getImageData(0, 0, c.width, c.height);
                noisy(d.data);
                g.putImageData(d, 0, 0);
                return c;
            } catch (e) {
                return canvas;
            }
        }

        var _toDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function () {
            return _toDataURL.apply(cloneNoisy(this), arguments);
        };
        var _toBlob = HTMLCanvasElement.prototype.toBlob;
        HTMLCanvasElement.prototype.toBlob = function () {
            return _toBlob.apply(cloneNoisy(this), arguments);
        };
    } catch (e) {}

    // ── audio ────────────────────────────────────────────────────────────────
    try {
        var AC = window.AudioContext || window.webkitAudioContext;
        if (AC) {
            var _createAnalyser = AC.prototype.createAnalyser;
            AC.prototype.createAnalyser = function () {
                var node = _createAnalyser.call(this);
                ['getFloatFrequencyData', 'getByteFrequencyData',
                 'getFloatTimeDomainData', 'getByteTimeDomainData'].forEach(function (m) {
                    if (typeof node[m] !== 'function') return;
                    var _m = node[m].bind(node);
                    node[m] = function (arr) {
                        _m(arr);
                        try { arr.fill(0); } catch (e) {}
                    };
                });
                return node;
            };
        }
    } catch (e) {}

    // ── webrtc / capture ─────────────────────────────────────────────────────
    ['RTCPeerConnection', 'webkitRTCPeerConnection', 'mozRTCPeerConnection',
     'RTCDataChannel', 'RTCSessionDescription', 'RTCIceCandidate'].forEach(function (k) {
        try {
            Object.defineProperty(window, k, { get: function () { return undefined; }, configurable: true });
        } catch (e) {}
    });
    try {
        Object.defineProperty(navigator, 'mediaDevices', {
            get: function () { return undefined; },
            configurable: true
        });
    } catch (e) {}

    // ── screen ───────────────────────────────────────────────────────────────
    define(screen, {
        width: function () { return 1920; },
        height: function () { return 1080; },
        availWidth: function () { return 1920; },
        availHeight: function () { return 1040; },
        colorDepth: function () { return 24; },
        pixelDepth: function () { return 24; }
    });
    try {
        Object.defineProperty(window, 'devicePixelRatio', {
            get: function () { return 1; },
            configurable: true
        });
    } catch (e) {}
    try {
        if (screen.orientation) {
            define(screen.orientation, {
                type: function () { return 'landscape-primary'; },
                angle: function () { return 0; }
            });
        }
    } catch (e) {}

    // ── window: letterboxed 1000x800 ─────────────────────────────────────────
    define(window, {
        outerWidth: function () { return 1000; },
        outerHeight: function () { return 800; },
        innerWidth: function () { return 1000; },
        innerHeight: function () { return 800; },
        screenX: function () { return 0; },
        screenY: function () { return 0; }
    });

    // ── navigator: Firefox 115 ESR on Windows ────────────────────────────────
    define(navigator, {
        hardwareConcurrency: function () { return 2; },
        platform: function () { return 'Win32'; },
        language: function () { return 'en-US'; },
        languages: function () { return Object.freeze(['en-US', 'en']); },
        vendor: function () { return ''; },
        productSub: function () { return '20100101'; },
        maxTouchPoints: function () { return 0; },
        oscpu: function () { return 'Windows NT 10.0; Win64; x64'; },
        buildID: function () { return '20181001000000'; },
        appName: function () { return 'Netscape'; },
        appCodeName: function () { return 'Mozilla'; },
        appVersion: function () { return '5.0 (Windows)'; },
        product: function () { return 'Gecko'; },
        webdriver: function () { return false; },
        doNotTrack: function () { return '1'; },
        plugins: function () { return Object.freeze([]); },
        mimeTypes: function () { return Object.freeze([]); }
    });

    // ── timers: 100ms clock, 4ms floor (Tor Browser behaviour) ───────────────
    try {
        var _now = performance.now.bind(performance);
        performance.now = function () { return Math.floor(_now() / 100) * 100; };
    } catch (e) {}

    try {
        var _st = window.setTimeout;
        window.setTimeout = function (fn, delay) {
            var extra = Array.prototype.slice.call(arguments, 2);
            return _st.apply(window, [fn, Math.max(delay | 0, 4)].concat(extra));
        };
        var _si = window.setInterval;
        window.setInterval = function (fn, delay) {
            var extra = Array.prototype.slice.call(arguments, 2);
            return _si.apply(window, [fn, Math.max(delay | 0, 4)].concat(extra));
        };
    } catch (e) {}

    // ── shared memory (Spectre timing) ───────────────────────────────────────
    ['SharedArrayBuffer', 'Atomics'].forEach(function (k) {
        try {
            Object.defineProperty(window, k, {
                get: function () { return undefined; },
                configurable: true
            });
        } catch (e) {}
    });

    try { window.name = ''; } catch (e) {}
})();
"#;

// ── internal pages ───────────────────────────────────────────────────────────

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn page_html(title: &str, body: &str) -> String {
    let t = html_escape(title);
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>{t}</title><style>
html,body{{margin:0;background:#0d0a12;color:#f3e9ff;font-family:system-ui,-apple-system,'Segoe UI',sans-serif}}
main{{max-width:640px;margin:14vh auto 0;padding:0 28px}}
h1{{font-size:22px;color:#ff9ad5;font-weight:600}}
p{{line-height:1.65;color:#cbbde0}}
code{{background:#1e1529;border:1px solid #312042;padding:2px 6px;border-radius:6px;font-size:13px}}
</style></head><body><main><h1>{t}</h1>{body}</main></body></html>"#
    )
}

fn block_page(host: &str) -> String {
    page_html(
        "Tracker blocked",
        &format!(
            "<p><code>{}</code> is on void's blocklist, so the request never left the browser.</p>\
             <p>Go back, or type another address above.</p>",
            html_escape(host)
        ),
    )
}

fn tor_down_page() -> String {
    page_html(
        "Tor is offline",
        "<p>void is in strict Tor mode and the local proxy at <code>127.0.0.1:9050</code> \
         is not reachable.</p><p>Every request stays blocked until Tor comes back. Start Tor, \
         then reload with <code>Ctrl+R</code>.</p>",
    )
}

// ── webkit ───────────────────────────────────────────────────────────────────

fn apply_level(s: &Settings, level: u8) {
    s.set_enable_javascript(level == 0);
    s.set_enable_media(level < 2);
    s.set_enable_mediasource(level == 0);
    s.set_enable_webaudio(level < 2);
}

fn apply_sec_level(wv: &WebView, level: u8) {
    if let Some(s) = wv.settings() {
        apply_level(&s, level);
    }
}

fn make_webcontext(proxy: &Option<String>, status: &Label) -> WebContext {
    let data_mgr = WebsiteDataManager::new_ephemeral();

    match proxy {
        Some(uri) => {
            let mut ps = NetworkProxySettings::new(Some(uri.as_str()), &[]);
            data_mgr.set_network_proxy_settings(NetworkProxyMode::Custom, Some(&mut ps));
        }
        None => {
            data_mgr.set_network_proxy_settings(NetworkProxyMode::NoProxy, None);
        }
    }

    let ctx = WebContext::builder()
        .website_data_manager(&data_mgr)
        .time_zone_override("UTC")
        .process_swap_on_cross_site_navigation_enabled(true)
        .build();

    ctx.set_cache_model(CacheModel::DocumentViewer);
    ctx.set_preferred_languages(&["en-US", "en"]);
    #[allow(deprecated)]
    ctx.set_tls_errors_policy(TLSErrorsPolicy::Fail);
    ctx.set_sandbox_enabled(true);

    // First-party cookies are needed for logins; everything else is denied.
    if let Some(cm) = ctx.cookie_manager() {
        cm.set_accept_policy(CookieAcceptPolicy::NoThirdParty);
    }
    data_mgr.set_itp_enabled(true);
    data_mgr.set_persistent_credential_storage_enabled(false);

    let st = status.clone();
    ctx.connect_download_started(move |_, dl| {
        dl.cancel();
        st.set_text("Download blocked · void does not write files");
    });

    ctx
}

fn make_webview(ctx: &WebContext, level: u8) -> WebView {
    let s = Settings::new();
    s.set_user_agent(Some(SPOOFED_UA));
    s.set_hardware_acceleration_policy(HardwareAccelerationPolicy::Never);
    s.set_enable_webgl(false);
    #[allow(deprecated)]
    s.set_enable_accelerated_2d_canvas(false);
    s.set_enable_dns_prefetching(false);
    s.set_enable_html5_database(false);
    s.set_enable_html5_local_storage(true);
    #[allow(deprecated)]
    s.set_enable_offline_web_application_cache(false);
    s.set_enable_page_cache(false);
    s.set_enable_media_stream(false);
    s.set_enable_webrtc(false);
    s.set_allow_modal_dialogs(true);
    s.set_enable_site_specific_quirks(true);
    #[allow(deprecated)]
    s.set_enable_java(false);
    #[allow(deprecated)]
    s.set_enable_plugins(false);
    s.set_enable_javascript_markup(false);
    s.set_enable_developer_extras(false);
    s.set_enable_write_console_messages_to_stdout(false);
    s.set_javascript_can_open_windows_automatically(false);
    s.set_javascript_can_access_clipboard(false);
    s.set_allow_top_navigation_to_data_urls(false);
    s.set_allow_file_access_from_file_urls(false);
    s.set_allow_universal_access_from_file_urls(false);
    s.set_enable_fullscreen(false);
    s.set_enable_encrypted_media(false);
    s.set_enable_media_capabilities(true);
    s.set_media_playback_requires_user_gesture(true);
    s.set_enable_hyperlink_auditing(false);
    s.set_enable_smooth_scrolling(false);
    s.set_enable_back_forward_navigation_gestures(false);
    s.set_default_font_family("serif");
    s.set_sans_serif_font_family("sans-serif");
    s.set_monospace_font_family("monospace");
    s.set_default_font_size(16);
    s.set_default_monospace_font_size(13);
    apply_level(&s, level);

    let ucm = UserContentManager::new();
    ucm.add_script(&UserScript::new(
        NET_SCRIPT,
        UserContentInjectedFrames::AllFrames,
        UserScriptInjectionTime::Start,
        &[],
        &[],
    ));
    ucm.add_script(&UserScript::new(
        FINGERPRINT_SCRIPT,
        UserContentInjectedFrames::AllFrames,
        UserScriptInjectionTime::Start,
        &[],
        &[],
    ));

    let wv = WebView::builder()
        .web_context(ctx)
        .user_content_manager(&ucm)
        .build();
    wv.set_settings(&s);
    wv.set_size_request(LETTERBOX_W, LETTERBOX_H);
    wv.set_vexpand(false);
    wv.set_hexpand(false);
    wv
}

fn attach_hooks(
    wv: &WebView,
    strict_tor: bool,
    status: &Label,
    opener: &TabOpener,
    home: &str,
) {
    // Everything a site can ask for is denied. No exceptions.
    {
        let st = status.clone();
        wv.connect_permission_request(move |_, req| {
            req.deny();
            st.set_text("Permission denied · void blocks every site permission");
            true
        });
    }
    {
        let st = status.clone();
        wv.connect_authenticate(move |_, req| {
            req.cancel();
            st.set_text("HTTP auth blocked");
            true
        });
    }
    {
        let st = status.clone();
        wv.connect_run_file_chooser(move |_, req| {
            req.cancel();
            st.set_text("File upload blocked");
            true
        });
    }

    // Popups become separate, isolated tabs instead of child windows.
    {
        let opener = opener.clone();
        let home = home.to_string();
        let st = status.clone();
        wv.connect_create(move |_, action| -> Option<gtk::Widget> {
            if let Some(uri) = action.request().and_then(|r| r.uri()) {
                if let Some(target) = target_for(uri.as_str(), &home) {
                    if let Some(open) = opener.borrow().as_ref() {
                        open(&target);
                        st.set_text("Opened link in a fresh isolated tab");
                    }
                }
            }
            None
        });
    }

    {
        let st = status.clone();
        wv.connect_load_changed(move |_, event| match event {
            LoadEvent::Started => st.set_text("Loading…"),
            LoadEvent::Finished => st.set_text("Ready · ephemeral session"),
            _ => {}
        });
    }

    {
        let st = status.clone();
        wv.connect_load_failed(move |_, _event, uri, error| {
            if !uri.starts_with("about:") {
                st.set_text(&format!("Could not load · {}", error));
            }
            false
        });
    }

    {
        let st = status.clone();
        wv.connect_decide_policy(move |wv, decision, kind| {
            if kind != PolicyDecisionType::NavigationAction {
                return false;
            }
            let nav = match decision.downcast_ref::<NavigationPolicyDecision>() {
                Some(n) => n,
                None => return false,
            };
            let uri = match nav.navigation_action().and_then(|a| a.request()).and_then(|r| r.uri())
            {
                Some(u) => u.to_string(),
                None => return false,
            };
            let is_top = nav.frame_name().map_or(true, |n| n.is_empty());

            if !scheme_allowed(&uri) {
                nav.ignore();
                if is_top {
                    let scheme = uri.split(':').next().unwrap_or("link");
                    st.set_text(&format!("Blocked unsupported {} link", scheme));
                }
                return true;
            }

            let is_web = uri.starts_with("http://") || uri.starts_with("https://");
            if strict_tor && is_web && !TOR_UP.load(Ordering::Relaxed) {
                nav.ignore();
                if is_top {
                    wv.load_html(&tor_down_page(), None);
                    st.set_text("Tor offline · request blocked");
                }
                return true;
            }

            if is_top {
                let upgraded = upgrade_http(&uri);
                if upgraded != uri {
                    nav.ignore();
                    wv.load_uri(&upgraded);
                    return true;
                }
            }

            if let Some(host) = host_of(&uri) {
                if is_tracker(&host) {
                    nav.ignore();
                    if is_top {
                        wv.load_html(&block_page(&host), None);
                        st.set_text(&format!("Blocked tracker · {}", host));
                    }
                    return true;
                }
            }

            false
        });
    }
}

// ── ui helpers ───────────────────────────────────────────────────────────────

fn view_of(widget: &gtk::Widget) -> Option<WebView> {
    if let Some(v) = widget.downcast_ref::<WebView>() {
        return Some(v.clone());
    }
    if let Some(c) = widget.downcast_ref::<gtk::Container>() {
        for child in c.children() {
            if let Some(v) = view_of(&child) {
                return Some(v);
            }
        }
    }
    None
}

fn current_view(notebook: &Notebook) -> Option<WebView> {
    let idx = notebook.current_page()?;
    let page = notebook.nth_page(Some(idx))?;
    view_of(&page)
}

fn set_theme(window: &ApplicationWindow, dark: bool) {
    let sc = window.style_context();
    if dark {
        sc.remove_class("void-light");
        sc.add_class("void-dark");
    } else {
        sc.remove_class("void-dark");
        sc.add_class("void-light");
    }
}

const CSS: &str = r#"
window.void-dark { background-color: #0d0a12; }
window.void-dark headerbar { background-image: none; background-color: #171021; color: #f3e9ff; border: none; box-shadow: none; }
window.void-dark headerbar button { background-image: none; background-color: #241733; color: #f3e9ff; border: 1px solid #3a2a4d; border-radius: 8px; }
window.void-dark headerbar button:hover { background-color: #34204a; }
window.void-dark entry { background-color: #1e1529; color: #f3e9ff; border: 1px solid #3a2a4d; border-radius: 8px; }
window.void-dark notebook { background-color: #0d0a12; }
window.void-dark notebook tab { background-color: #1e1529; color: #cbbde0; border-radius: 8px 8px 0 0; padding: 4px 10px; }
window.void-dark notebook tab:checked { background-color: #2a1c3a; color: #ff9ad5; }
window.void-dark #void-stage { background-color: #0d0a12; }
window.void-dark .void-bar { background-color: #171021; color: #b9a8cf; }
window.void-dark .void-credit { color: #ff9ad5; }
window.void-dark .void-status { color: #b9a8cf; font-size: 11px; }
window.void-dark .void-proxy { color: #b9a8cf; font-size: 11px; }
window.void-dark button.void-close { background-image: none; background-color: transparent; border: none; color: #b9a8cf; padding: 0 4px; min-height: 16px; min-width: 16px; }
window.void-dark button.void-close:hover { color: #ff9ad5; }

window.void-light { background-color: #fbf7ff; }
window.void-light headerbar { background-image: none; background-color: #f3e9ff; color: #2a1735; border: none; box-shadow: none; }
window.void-light headerbar button { background-image: none; background-color: #ffffff; color: #2a1735; border: 1px solid #e0cdea; border-radius: 8px; }
window.void-light headerbar button:hover { background-color: #f7e7ff; }
window.void-light entry { background-color: #ffffff; color: #2a1735; border: 1px solid #e0cdea; border-radius: 8px; }
window.void-light notebook { background-color: #fbf7ff; }
window.void-light notebook tab { background-color: #f1e6ff; color: #6b5580; border-radius: 8px 8px 0 0; padding: 4px 10px; }
window.void-light notebook tab:checked { background-color: #e6d2ff; color: #b02a86; }
window.void-light #void-stage { background-color: #fbf7ff; }
window.void-light .void-bar { background-color: #f3e9ff; color: #6b5580; }
window.void-light .void-credit { color: #b02a86; }
window.void-light .void-status { color: #6b5580; font-size: 11px; }
window.void-light .void-proxy { color: #6b5580; font-size: 11px; }
window.void-light button.void-close { background-image: none; background-color: transparent; border: none; color: #6b5580; padding: 0 4px; min-height: 16px; min-width: 16px; }
window.void-light button.void-close:hover { color: #b02a86; }
"#;

// ── app ──────────────────────────────────────────────────────────────────────

fn positional_arg(args: &[String]) -> Option<String> {
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a == "--proxy" {
            skip = true;
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        return Some(a.clone());
    }
    None
}

fn build_ui(app: &Application) {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = Rc::new(RefCell::new(load_config()));

    let force_tor = args.iter().any(|a| a == "--tor" || a == "--tor-strict");
    let direct = args.iter().any(|a| a == "--direct");

    if force_tor {
        if tor_running() {
            TOR_UP.store(true, Ordering::Relaxed);
        } else if tor_available() && spawn_tor() && wait_tor() {
            TOR_UP.store(true, Ordering::Relaxed);
        } else {
            TOR_UP.store(false, Ordering::Relaxed);
            eprintln!("void: Tor is not reachable — strict mode will block every request");
        }
        start_tor_monitor();
    }

    let cli_proxy = args
        .windows(2)
        .find(|w| w[0] == "--proxy")
        .map(|w| w[1].clone());
    let env_proxy = env::var("ALL_PROXY")
        .ok()
        .or_else(|| env::var("all_proxy").ok());
    let chosen_proxy = cli_proxy
        .or_else(|| config.borrow().proxy.clone())
        .or(env_proxy)
        .filter(|p| valid_proxy(p));

    let net = if force_tor {
        NetMode::Tor
    } else if direct {
        NetMode::Direct
    } else {
        match chosen_proxy {
            Some(p) => NetMode::Custom(p),
            None => NetMode::Direct,
        }
    };

    let strict_tor = force_tor;
    let home = config.borrow().home.clone();

    let initial_status = if strict_tor && !TOR_UP.load(Ordering::Relaxed) {
        "Tor offline · requests blocked"
    } else if net.is_tor() {
        "Ready · fresh circuit per tab"
    } else if matches!(&net, NetMode::Custom(_)) {
        "Ready · proxied"
    } else {
        "Ready · direct connection"
    };

    let status = Label::new(Some(initial_status));
    status.style_context().add_class("void-status");
    status.set_halign(gtk::Align::Start);
    status.set_ellipsize(gtk::pango::EllipsizeMode::End);

    let proxy_label = Label::new(Some(&net.label()));
    proxy_label.style_context().add_class("void-proxy");
    proxy_label.set_halign(gtk::Align::End);
    proxy_label.set_tooltip_text(Some(&net.label()));

    let notebook = Notebook::new();
    notebook.set_scrollable(true);
    notebook.set_vexpand(true);

    let url_bar = Entry::builder()
        .placeholder_text("Search or enter address")
        .hexpand(true)
        .build();

    let opener_slot: TabOpener = Rc::new(RefCell::new(None));

    let make_tab: Rc<dyn Fn(&str)> = {
        let notebook_weak = notebook.downgrade();
        let url_bar = url_bar.clone();
        let status = status.clone();
        let config = config.clone();
        let net = net.clone();
        let home = home.clone();
        let opener_slot = opener_slot.clone();

        Rc::new(move |requested: &str| {
            let notebook = match notebook_weak.upgrade() {
                Some(n) => n,
                None => return,
            };

            let circuit = format!(
                "void-{}-{}",
                IDENTITY_EPOCH.load(Ordering::Relaxed),
                TAB_COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let proxy = net.proxy_for(&circuit);
            let level = config.borrow().security;
            let ctx = make_webcontext(&proxy, &status);
            let wv = make_webview(&ctx, level);
            attach_hooks(&wv, strict_tor, &status, &opener_slot, &home);

            // Letterbox: the WebView stays at 1000x800, spacers take the rest.
            let page = GBox::new(Orientation::Vertical, 0);
            page.set_widget_name("void-stage");
            page.set_vexpand(true);

            let top = GBox::new(Orientation::Horizontal, 0);
            top.set_vexpand(true);
            let bottom = GBox::new(Orientation::Horizontal, 0);
            bottom.set_vexpand(true);

            let row = GBox::new(Orientation::Horizontal, 0);
            let left = GBox::new(Orientation::Vertical, 0);
            left.set_hexpand(true);
            let right = GBox::new(Orientation::Vertical, 0);
            right.set_hexpand(true);
            row.pack_start(&left, true, true, 0);
            row.pack_start(&wv, false, false, 0);
            row.pack_start(&right, true, true, 0);

            page.pack_start(&top, true, true, 0);
            page.pack_start(&row, false, false, 0);
            page.pack_start(&bottom, true, true, 0);

            let tab_box = GBox::new(Orientation::Horizontal, 6);
            let tab_label = Label::new(Some(&home));
            tab_label.set_max_width_chars(22);
            tab_label.set_ellipsize(gtk::pango::EllipsizeMode::End);
            let close_btn = Button::with_label("×");
            close_btn.style_context().add_class("void-close");
            close_btn.set_relief(gtk::ReliefStyle::None);
            close_btn.set_focus_on_click(false);
            close_btn.set_tooltip_text(Some("Close tab"));
            tab_box.pack_start(&tab_label, true, true, 0);
            tab_box.pack_start(&close_btn, false, false, 0);
            tab_box.show_all();

            {
                let tab_label = tab_label.clone();
                wv.connect_title_notify(move |wv| {
                    if let Some(t) = wv.title() {
                        let text = t.as_str().trim();
                        if !text.is_empty() {
                            tab_label.set_text(text);
                        }
                    }
                });
            }

            {
                let url_bar = url_bar.clone();
                let page_weak = page.downgrade();
                let nb_weak = notebook.downgrade();
                wv.connect_uri_notify(move |wv| {
                    if let (Some(page), Some(nb)) = (page_weak.upgrade(), nb_weak.upgrade()) {
                        if let Some(idx) = nb.page_num(&page) {
                            if nb.current_page() == Some(idx) {
                                if let Some(uri) = wv.uri() {
                                    url_bar.set_text(uri.as_str());
                                }
                            }
                        }
                    }
                });
            }

            {
                let page_weak = page.downgrade();
                let nb_weak = notebook.downgrade();
                let opener_slot = opener_slot.clone();
                let home = home.clone();
                close_btn.connect_clicked(move |_| {
                    if let Some(page) = page_weak.upgrade() {
                        if let Some(nb) = nb_weak.upgrade() {
                            if let Some(idx) = nb.page_num(&page) {
                                nb.remove_page(Some(idx));
                            }
                            if nb.n_pages() == 0 {
                                if let Some(open) = opener_slot.borrow().as_ref() {
                                    open(&home);
                                }
                            }
                        }
                    }
                });
            }

            let idx = notebook.append_page(&page, Some(&tab_box));
            notebook.set_tab_reorderable(&page, true);
            page.show_all();
            notebook.set_current_page(Some(idx));

            if strict_tor && !TOR_UP.load(Ordering::Relaxed) {
                wv.load_html(&tor_down_page(), None);
            } else {
                let target = target_for(requested, &home).unwrap_or_else(|| home.clone());
                wv.load_uri(&target);
            }
        })
    };

    *opener_slot.borrow_mut() = Some(make_tab.clone());
    let open = make_tab.clone();

    let window = ApplicationWindow::builder()
        .application(app)
        .title("void")
        .default_width(1080)
        .default_height(940)
        .build();
    window.set_position(gtk::WindowPosition::Center);

    let close_current: Rc<dyn Fn()> = {
        let notebook = notebook.clone();
        let opener_slot = opener_slot.clone();
        let home = home.clone();
        Rc::new(move || {
            if let Some(idx) = notebook.current_page() {
                notebook.remove_page(Some(idx));
            }
            if notebook.n_pages() == 0 {
                if let Some(open) = opener_slot.borrow().as_ref() {
                    open(&home);
                }
            }
        })
    };

    let new_identity: Rc<dyn Fn()> = {
        let notebook = notebook.clone();
        let opener_slot = opener_slot.clone();
        let home = home.clone();
        let status = status.clone();
        Rc::new(move || {
            IDENTITY_EPOCH.fetch_add(1, Ordering::Relaxed);
            while notebook.n_pages() > 0 {
                notebook.remove_page(Some(0));
            }
            if let Some(open) = opener_slot.borrow().as_ref() {
                open(&home);
            }
            status.set_text("New identity · fresh circuits, empty session");
        })
    };

    // ── toolbar ──────────────────────────────────────────────────────────────
    let back_btn = Button::with_label("‹");
    back_btn.set_tooltip_text(Some("Back"));
    let fwd_btn = Button::with_label("›");
    fwd_btn.set_tooltip_text(Some("Forward"));
    let reload_btn = Button::with_label("↻");
    reload_btn.set_tooltip_text(Some("Reload"));
    let home_btn = Button::with_label("⌂");
    home_btn.set_tooltip_text(Some("Home"));
    let new_tab_btn = Button::with_label("+");
    new_tab_btn.set_tooltip_text(Some("New tab · isolated context (Ctrl+T)"));
    let new_id_btn = Button::with_label("new id");
    new_id_btn.set_tooltip_text(Some("New identity · fresh context and circuits"));
    let theme_btn = Button::with_label(if config.borrow().theme == "dark" { "☾" } else { "☀" });
    theme_btn.set_tooltip_text(Some("Toggle theme"));

    let sec_combo = ComboBoxText::new();
    sec_combo.append_text("Standard");
    sec_combo.append_text("Safer");
    sec_combo.append_text("Safest");
    sec_combo.set_active(Some(config.borrow().security as u32));
    sec_combo.set_tooltip_text(Some("Security level (all tabs)"));

    {
        let notebook = notebook.clone();
        back_btn.connect_clicked(move |_| {
            if let Some(wv) = current_view(&notebook) {
                if wv.can_go_back() {
                    wv.go_back();
                }
            }
        });
    }
    {
        let notebook = notebook.clone();
        fwd_btn.connect_clicked(move |_| {
            if let Some(wv) = current_view(&notebook) {
                if wv.can_go_forward() {
                    wv.go_forward();
                }
            }
        });
    }
    {
        let notebook = notebook.clone();
        reload_btn.connect_clicked(move |_| {
            if let Some(wv) = current_view(&notebook) {
                wv.reload();
            }
        });
    }
    {
        let notebook = notebook.clone();
        let home = home.clone();
        home_btn.connect_clicked(move |_| {
            if let Some(wv) = current_view(&notebook) {
                wv.load_uri(&home);
            }
        });
    }
    {
        let open = open.clone();
        let home = home.clone();
        new_tab_btn.connect_clicked(move |_| open(&home));
    }
    {
        let new_identity = new_identity.clone();
        new_id_btn.connect_clicked(move |_| new_identity());
    }
    {
        let window_weak = window.downgrade();
        let config = config.clone();
        let btn = theme_btn.clone();
        theme_btn.connect_clicked(move |_| {
            let dark = {
                let mut c = config.borrow_mut();
                c.theme = if c.theme == "dark" { "light".into() } else { "dark".into() };
                c.theme == "dark"
            };
            if let Some(w) = window_weak.upgrade() {
                set_theme(&w, dark);
            }
            btn.set_label(if dark { "☾" } else { "☀" });
            if let Ok(c) = config.try_borrow() {
                save_config(&c);
            }
        });
    }
    {
        let url_bar = url_bar.clone();
        let notebook = notebook.clone();
        let status = status.clone();
        let home = home.clone();
        url_bar.connect_activate(move |entry| {
            let text = entry.text().to_string();
            match target_for(&text, &home) {
                Some(target) => {
                    if let Some(wv) = current_view(&notebook) {
                        wv.load_uri(&target);
                    }
                }
                None => status.set_text("Blocked unsupported address"),
            }
        });
    }
    {
        let notebook = notebook.clone();
        let config = config.clone();
        let status = status.clone();
        sec_combo.connect_changed(move |c| {
            let level = match c.active() {
                Some(i) => i.min(2) as u8,
                None => return,
            };
            {
                let mut cc = config.borrow_mut();
                if cc.security == level {
                    return;
                }
                cc.security = level;
            }
            for i in 0..notebook.n_pages() {
                if let Some(page) = notebook.nth_page(Some(i)) {
                    if let Some(wv) = view_of(&page) {
                        apply_sec_level(&wv, level);
                        wv.reload();
                    }
                }
            }
            status.set_text(match level {
                0 => "Security level · Standard",
                1 => "Security level · Safer",
                _ => "Security level · Safest",
            });
            if let Ok(c) = config.try_borrow() {
                save_config(&c);
            }
        });
    }

    let header = HeaderBar::new();
    header.style_context().add_class("void-bar");
    header.pack_start(&back_btn);
    header.pack_start(&fwd_btn);
    header.pack_start(&reload_btn);
    header.pack_start(&home_btn);
    header.pack_end(&theme_btn);
    header.pack_end(&new_id_btn);
    header.pack_end(&new_tab_btn);
    header.pack_end(&sec_combo);
    header.set_custom_title(Some(&url_bar));
    window.set_titlebar(Some(&header));

    // ── status bar ───────────────────────────────────────────────────────────
    let bar = GBox::new(Orientation::Horizontal, 10);
    bar.style_context().add_class("void-bar");
    bar.set_margin_top(3);
    bar.set_margin_bottom(3);
    bar.set_margin_start(10);
    bar.set_margin_end(10);

    let credit = Label::new(Some("made by Ivoryy06 ♡"));
    credit.style_context().add_class("void-credit");

    status.set_hexpand(true);

    bar.pack_start(&credit, false, false, 0);
    bar.pack_start(&status, true, true, 0);
    bar.pack_end(&proxy_label, false, false, 0);

    let content = GBox::new(Orientation::Vertical, 0);
    content.pack_start(&notebook, true, true, 0);
    content.pack_start(&bar, false, false, 0);
    window.add(&content);

    // ── theme + styles ───────────────────────────────────────────────────────
    let provider = gtk::CssProvider::new();
    provider.load_from_data(CSS.as_bytes()).ok();
    if let Some(screen) = gtk::gdk::Screen::default() {
        gtk::StyleContext::add_provider_for_screen(
            &screen,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
    set_theme(&window, config.borrow().theme == "dark");

    // ── keyboard ─────────────────────────────────────────────────────────────
    {
        let open = open.clone();
        let close_current = close_current.clone();
        let new_identity = new_identity.clone();
        let notebook = notebook.clone();
        let url_bar = url_bar.clone();
        let home = home.clone();
        let window_weak = window.downgrade();

        window.connect_key_press_event(move |_, ev| {
            if !ev
                .state()
                .contains(gtk::gdk::ModifierType::CONTROL_MASK)
            {
                return glib::Propagation::Proceed;
            }
            let key = *ev.keyval();
            match key {
                0x74 | 0x54 => open(&home),          // Ctrl+T
                0x77 | 0x57 => close_current(),      // Ctrl+W
                0x6c | 0x4c => {                     // Ctrl+L
                    url_bar.grab_focus();
                    url_bar.select_region(0, -1);
                }
                0x72 | 0x52 => {                     // Ctrl+R
                    if let Some(wv) = current_view(&notebook) {
                        wv.reload();
                    }
                }
                0x68 | 0x48 => {                     // Ctrl+H
                    if let Some(wv) = current_view(&notebook) {
                        wv.load_uri(&home);
                    }
                }
                0x6e | 0x4e => new_identity(),       // Ctrl+N
                0x71 | 0x51 => {                     // Ctrl+Q
                    if let Some(w) = window_weak.upgrade() {
                        w.close();
                    }
                }
                _ => return glib::Propagation::Proceed,
            }
            glib::Propagation::Stop
        });
    }

    {
        let config = config.clone();
        window.connect_delete_event(move |_, _| {
            if let Ok(c) = config.try_borrow() {
                save_config(&c);
            }
            glib::Propagation::Proceed
        });
    }

    notebook.connect_switch_page({
        let url_bar = url_bar.clone();
        move |_, page, _| {
            if let Some(wv) = view_of(page) {
                if let Some(uri) = wv.uri() {
                    url_bar.set_text(uri.as_str());
                }
            }
        }
    });

    let start = positional_arg(&args)
        .and_then(|a| target_for(&a, &home))
        .unwrap_or_else(|| home.clone());
    open(&start);

    window.show_all();
}

fn print_help() {
    println!(
        "void {} — a quiet private browser\n\n\
         usage: void [options] [address]\n\n\
         options:\n\
           --tor          route through Tor and block everything if Tor is down\n\
           --proxy URI    use a custom proxy (socks5://, http://, https://)\n\
           --direct       ignore config and environment proxies\n\
           -h, --help     show this help\n\
           -V, --version  show version\n\n\
         config: ~/.config/void/settings.json\n\n\
         made by Ivoryy06 ♡",
        env!("CARGO_PKG_VERSION")
    );
}

// async-signal-safe: only _exit. Tor is a child with PDEATHSIG, so it follows.
extern "C" fn on_signal(_: libc::c_int) {
    unsafe {
        libc::_exit(0);
    }
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            on_signal as *const () as libc::sighandler_t,
        );
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_signal as *const () as libc::sighandler_t);
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("void {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    install_signal_handlers();

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        kill_tor();
        default_hook(info);
    }));

    let app = Application::builder()
        .application_id("me.ivy06.void")
        .build();
    app.connect_activate(build_ui);
    app.connect_shutdown(|_| kill_tor());
    let _ = app.run();
}
