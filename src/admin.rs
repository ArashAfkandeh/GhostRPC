//! Built-in web admin panel: login page, session handling and the JSON API used by `panel/`.
//!
//! Security model
//! * Passwords are stored as Argon2id hashes (`admin_credentials.json`, mode 0600), never in clear.
//! * Sessions are random 256-bit tokens kept server-side (only their SHA-256 is stored), sent in an
//!   `HttpOnly; SameSite=Strict` cookie. Every state-changing request also needs the per-session
//!   `X-CSRF-Token` header, and the API only accepts `application/json` bodies.
//! * Failed logins are rate limited per client IP with growing lock-outs, hashing work is bounded
//!   by a semaphore and a dummy hash equalises the timing of "unknown user" and "wrong password".
//! * The panel listens on loopback by default. To publish it, put it behind the built-in TLS
//!   `reverse_proxy` web server and set `trust_proxy = true`.

use crate::config::{AdminConfig, AppConfig};
use crate::metrics;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

// ==========================================================================
// Embedded UI
// ==========================================================================

const INDEX_HTML: &str = include_str!("../panel/index.html");
const LOGIN_HTML: &str = include_str!("../panel/login.html");
const APP_CSS: &str = include_str!("../panel/app.css");
const CORE_JS: &str = include_str!("../panel/modules/core.js");
const LOGIN_JS: &str = include_str!("../panel/modules/login.js");
const I18N_JS: &str = include_str!("../panel/i18n.js");
const DASHBOARD_JS: &str = include_str!("../panel/modules/dashboard.js");
const TUNNELS_JS: &str = include_str!("../panel/modules/tunnels.js");
const CONNECTIONS_JS: &str = include_str!("../panel/modules/connections.js");
const LOGS_JS: &str = include_str!("../panel/modules/logs.js");
const CONFIG_JS: &str = include_str!("../panel/modules/config.js");
const CERTS_JS: &str = include_str!("../panel/modules/certs.js");
const ACCOUNT_JS: &str = include_str!("../panel/modules/account.js");
const FONT_WOFF2: &[u8] = include_bytes!("../panel/fonts/vazirmatn.woff2");
const FAVICON_SVG: &str = include_str!("../panel/favicon.svg");
const CLIENT_CONFIG_SAMPLE: &str = include_str!("../client.toml");
const SERVER_CONFIG_SAMPLE: &str = include_str!("../server.toml");

const COOKIE_NAME: &str = "ghost_sid";
const SESSION_ABSOLUTE_SECS: u64 = 7 * 24 * 3600;
const MAX_SESSIONS: usize = 20;
const MAX_FAILS: u32 = 5;
const FAIL_WINDOW_SECS: u64 = 600;
const MIN_PASSWORD_LEN: usize = 10;
const BACKUPS_KEPT: usize = 15;
const MAX_CONFIG_BYTES: usize = 512 * 1024;

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: https://github.com https://avatars.githubusercontent.com; \
font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

// ==========================================================================
// State
// ==========================================================================

#[derive(Serialize, Deserialize, Clone)]
struct Credentials {
    username: String,
    password_hash: String,
    /// True while the password is one the operator did not choose (generated / from the config).
    #[serde(default)]
    must_change: bool,
    #[serde(default)]
    updated_at: u64,
}

#[derive(Clone)]
struct Session {
    sid: u64,
    user: String,
    csrf: String,
    created: u64,
    last_seen: u64,
    ip: String,
    ua: String,
}

#[derive(Default)]
struct Attempt {
    fails: u32,
    window_start: u64,
    locked_until: u64,
    lock_level: u32,
}

struct Inner {
    cfg: AdminConfig,
    config_path: PathBuf,
    creds_path: PathBuf,
    /// True when `[admin] password` is set: then the config file is where the password lives.
    password_in_config: bool,
    creds: RwLock<Credentials>,
    sessions: DashMap<String, Session>,
    attempts: DashMap<IpAddr, Attempt>,
    dummy_hash: String,
    hash_sem: tokio::sync::Semaphore,
    ttl_secs: u64,
}

type Shared = Arc<Inner>;

// ==========================================================================
// Small helpers
// ==========================================================================

fn now() -> u64 {
    metrics::now_unix()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn sha256_hex(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    hex(d.as_slice())
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    for chunk in b.chunks_mut(8) {
        chunk.copy_from_slice(&rand::random::<u64>().to_le_bytes());
    }
    hex(&b)
}

/// Constant-time equality for secrets of (possibly) different length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

fn random_password(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let limit = 256 - (256 % ALPHABET.len());
    let mut out = String::with_capacity(len);
    while out.len() < len {
        let b = rand::random::<u8>() as usize;
        if b < limit {
            out.push(ALPHABET[b % ALPHABET.len()] as char);
        }
    }
    out
}

fn hash_password(pw: &str) -> Result<String, String> {
    let mut salt_bytes = [0u8; 16];
    for chunk in salt_bytes.chunks_mut(8) {
        chunk.copy_from_slice(&rand::random::<u64>().to_le_bytes());
    }
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| e.to_string())?;
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

fn verify_password(hash: &str, pw: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(h) => Argon2::default().verify_password(pw.as_bytes(), &h).is_ok(),
        Err(_) => false,
    }
}

fn json_err(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

fn json_err_detail(status: StatusCode, code: &str, detail: &str) -> Response {
    (status, Json(json!({ "error": code, "detail": detail }))).into_response()
}

fn html(body: &'static str) -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Writes `data` to a temp file next to `path` and renames it over `path`.
fn atomic_write(path: &FsPath, data: &[u8], private: bool) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let tmp = match dir {
        Some(d) => d.join(format!(".{}.tmp-admin", name)),
        None => PathBuf::from(format!(".{}.tmp-admin", name)),
    };
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if private {
            0o600
        } else {
            std::fs::metadata(path)
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0o644)
        };
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = private;
    std::fs::rename(&tmp, path)
}

fn resolve_next_to_config(config_path: &str, name: &str) -> PathBuf {
    let p = FsPath::new(name);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    match FsPath::new(config_path).parent() {
        Some(d) if !d.as_os_str().is_empty() => d.join(p),
        _ => p.to_path_buf(),
    }
}

fn credentials_path(cfg: &AdminConfig, config_path: &str) -> PathBuf {
    let name = cfg
        .credentials_file
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("admin_credentials.json");
    resolve_next_to_config(config_path, name)
}

fn save_credentials(path: &FsPath, c: &Credentials) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(c).map_err(|e| e.to_string())?;
    atomic_write(path, &data, true).map_err(|e| format!("{}: {}", path.display(), e))
}

// ==========================================================================
// Credentials bootstrap + CLI reset
// ==========================================================================

enum Seed {
    /// Loaded from the credentials file.
    Existing,
    /// `username` / `password` of the `[admin]` section (authoritative, no file involved).
    Config,
    /// Random password generated on first start (stored in the credentials file).
    Generated(String),
}

fn config_username(cfg: &AdminConfig) -> String {
    cfg.username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("admin")
        .to_string()
}

fn config_password(cfg: &AdminConfig) -> Option<&str> {
    cfg.password.as_deref().filter(|p| !p.is_empty())
}

/// TOML basic-string literal (with quotes) for `s`.
fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Sets `password = "..."` inside the `[admin]` table of a config text, keeping everything else
/// (comments, order, line endings) untouched.
fn set_admin_password_in_text(content: &str, new_pw: &str) -> Result<String, String> {
    let crlf = content.contains("\r\n");
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    let is_admin_header = |l: &str| l.split('#').next().unwrap_or("").trim() == "[admin]";
    let start = lines
        .iter()
        .position(|l| is_admin_header(l))
        .ok_or_else(|| "the config has no [admin] section".to_string())?;
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.trim_start().starts_with('['))
        .map(|i| start + 1 + i)
        .unwrap_or(lines.len());
    let new_line = format!("password = {}", toml_string(new_pw));
    let mut replaced = false;
    for l in &mut lines[start + 1..end] {
        let t = l.trim_start();
        if t.starts_with("password") && t["password".len()..].trim_start().starts_with('=') {
            *l = new_line.clone();
            replaced = true;
            break;
        }
    }
    if !replaced {
        lines.insert(start + 1, new_line);
    }
    let nl = if crlf { "\r\n" } else { "\n" };
    let mut out = lines.join(nl);
    if content.ends_with('\n') {
        out.push_str(nl);
    }
    Ok(out)
}

fn load_or_create_credentials(
    cfg: &AdminConfig,
    path: &FsPath,
) -> Result<(Credentials, Seed), String> {
    // `[admin] password = "..."` in the config is the source of truth: edit the file, reload, done.
    if let Some(pw) = config_password(cfg) {
        let c = Credentials {
            username: config_username(cfg),
            password_hash: hash_password(pw)?,
            must_change: false,
            updated_at: now(),
        };
        return Ok((c, Seed::Config));
    }
    if let Ok(raw) = std::fs::read_to_string(path) {
        let c: Credentials = serde_json::from_str(&raw)
            .map_err(|e| format!("{} is not valid: {}", path.display(), e))?;
        if c.username.trim().is_empty() || PasswordHash::new(&c.password_hash).is_err() {
            return Err(format!(
                "{} has an empty username or an invalid password hash (delete it or run with --reset-admin-password)",
                path.display()
            ));
        }
        return Ok((c, Seed::Existing));
    }

    let username = config_username(cfg);
    let password = random_password(18);
    let seed = Seed::Generated(password.clone());
    let c = Credentials {
        username,
        password_hash: hash_password(&password)?,
        must_change: true,
        updated_at: now(),
    };
    save_credentials(path, &c)?;
    Ok((c, seed))
}

/// `GhostRPC <config> --reset-admin-password`: sets a new random password and prints it. The
/// password is written to `[admin]` of the config when the config holds one, otherwise to the
/// credentials file.
pub fn cli_reset_password(config_path: &str) -> i32 {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Cannot read {}: {}", config_path, e);
            return 1;
        }
    };
    let app: AppConfig = match toml::from_str(&content) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("❌ {} is not valid TOML: {}", config_path, e);
            return 1;
        }
    };
    let cfg = app.admin.unwrap_or_else(|| toml::from_str("").unwrap());
    let password = random_password(18);
    if config_password(&cfg).is_some() {
        let text = match set_admin_password_in_text(&content, &password) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("❌ {}", e);
                return 1;
            }
        };
        if let Err(e) = atomic_write(FsPath::new(config_path), text.as_bytes(), false) {
            eprintln!("❌ {}: {}", config_path, e);
            return 1;
        }
        println!("✅ Admin password reset in the [admin] section of {}", config_path);
        println!("   username: {}", config_username(&cfg));
        println!("   password: {}", password);
        println!("   A running GhostRPC applies it by itself (hot-reload).");
        return 0;
    }
    let path = credentials_path(&cfg, config_path);
    let username = std::fs::read_to_string(&path)
        .ok()
        .and_then(|r| serde_json::from_str::<Credentials>(&r).ok())
        .map(|c| c.username)
        .unwrap_or_else(|| config_username(&cfg));
    let hash = match hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("❌ Hashing failed: {}", e);
            return 1;
        }
    };
    let c = Credentials {
        username: username.clone(),
        password_hash: hash,
        must_change: true,
        updated_at: now(),
    };
    if let Err(e) = save_credentials(&path, &c) {
        eprintln!("❌ {}", e);
        return 1;
    }
    println!("✅ Admin password reset ({})", path.display());
    println!("   username: {}", username);
    println!("   password: {}", password);
    println!("   Restart GhostRPC for the new password to take effect (running instances keep the old one in memory).");
    0
}

// ==========================================================================
// Sessions + login limiter
// ==========================================================================

impl Inner {
    fn cookie_secure(&self, headers: &HeaderMap) -> bool {
        match self.cfg.secure_cookie {
            Some(v) => v,
            None => {
                self.cfg.trust_proxy
                    && headers
                        .get("x-forwarded-proto")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.split(',').next().unwrap_or("").trim().eq_ignore_ascii_case("https"))
                        .unwrap_or(false)
            }
        }
    }

    fn client_ip(&self, headers: &HeaderMap, peer: &SocketAddr) -> IpAddr {
        if self.cfg.trust_proxy {
            if let Some(ip) = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
            {
                return ip;
            }
        }
        peer.ip()
    }

    fn token_from_headers(headers: &HeaderMap) -> Option<String> {
        // Browsers speaking HTTP/2 split the Cookie header into several fields ("crumbs") and the
        // built-in reverse proxy forwards them as separate headers, so every one must be inspected.
        for raw in headers.get_all(header::COOKIE) {
            let Ok(raw) = raw.to_str() else { continue };
            for part in raw.split(';') {
                let part = part.trim();
                if let Some(v) = part.strip_prefix(COOKIE_NAME).and_then(|r| r.strip_prefix('=')) {
                    if !v.is_empty() && v.len() <= 128 {
                        return Some(v.to_string());
                    }
                }
            }
        }
        None
    }

    /// Returns the session key (hash of the token) and the session when the cookie is valid.
    fn authenticate(&self, headers: &HeaderMap) -> Option<(String, Session)> {
        let token = Self::token_from_headers(headers)?;
        let key = sha256_hex(token.as_bytes());
        let t = now();
        let mut entry = self.sessions.get_mut(&key)?;
        let idle = t.saturating_sub(entry.last_seen);
        let age = t.saturating_sub(entry.created);
        if idle > self.ttl_secs || age > SESSION_ABSOLUTE_SECS {
            drop(entry);
            self.sessions.remove(&key);
            return None;
        }
        if t > entry.last_seen {
            entry.last_seen = t;
        }
        Some((key, entry.clone()))
    }

    fn lock_remaining(&self, ip: IpAddr) -> u64 {
        self.attempts
            .get(&ip)
            .map(|a| a.locked_until.saturating_sub(now()))
            .unwrap_or(0)
    }

    fn record_failure(&self, ip: IpAddr) {
        let t = now();
        let mut a = self.attempts.entry(ip).or_default();
        if t.saturating_sub(a.window_start) > FAIL_WINDOW_SECS {
            a.window_start = t;
            a.fails = 0;
        }
        a.fails += 1;
        if a.fails >= MAX_FAILS {
            a.lock_level = (a.lock_level + 1).min(6);
            let secs = (300u64 << (a.lock_level - 1)).min(3600);
            a.locked_until = t + secs;
            a.fails = 0;
        }
    }

    fn create_session(&self, ip: &IpAddr, ua: &str, user: &str) -> (String, Session) {
        // Keep the number of live sessions bounded: drop the least recently used ones.
        if self.sessions.len() >= MAX_SESSIONS {
            let mut all: Vec<(String, u64)> = self
                .sessions
                .iter()
                .map(|e| (e.key().clone(), e.value().last_seen))
                .collect();
            all.sort_by_key(|(_, t)| *t);
            for (k, _) in all.iter().take(self.sessions.len() + 1 - MAX_SESSIONS) {
                self.sessions.remove(k);
            }
        }
        let token = random_token();
        let t = now();
        let sess = Session {
            sid: rand::random::<u64>() >> 11,
            user: user.to_string(),
            csrf: random_token(),
            created: t,
            last_seen: t,
            ip: ip.to_string(),
            ua: ua.chars().filter(|c| !c.is_control()).take(160).collect(),
        };
        self.sessions.insert(sha256_hex(token.as_bytes()), sess.clone());
        (token, sess)
    }

    fn session_cookie(&self, token: &str, secure: bool) -> String {
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
            COOKIE_NAME,
            token,
            self.ttl_secs,
            if secure { "; Secure" } else { "" }
        )
    }

    fn clear_cookie(secure: bool) -> String {
        format!(
            "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
            COOKIE_NAME,
            if secure { "; Secure" } else { "" }
        )
    }

    /// Verifies a password against the stored hash (or the dummy hash when `use_real` is false) on
    /// the blocking pool, bounded by the semaphore.
    async fn check_password(&self, pw: String, use_real: bool) -> bool {
        let _permit = match self.hash_sem.acquire().await {
            Ok(p) => p,
            Err(_) => return false,
        };
        let hash = if use_real {
            self.creds.read().unwrap().password_hash.clone()
        } else {
            self.dummy_hash.clone()
        };
        let ok = tokio::task::spawn_blocking(move || verify_password(&hash, &pw))
            .await
            .unwrap_or(false);
        ok && use_real
    }
}

// ==========================================================================
// Middleware
// ==========================================================================

async fn auth_mw(State(st): State<Shared>, mut req: Request, next: Next) -> Response {
    let Some((_, sess)) = st.authenticate(req.headers()) else {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        let sent = req
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct_eq(sent.as_bytes(), sess.csrf.as_bytes()) {
            return json_err(StatusCode::FORBIDDEN, "csrf");
        }
    }
    req.extensions_mut().insert(sess);
    next.run(req).await
}

async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    h.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

// ==========================================================================
// Pages and assets
// ==========================================================================

async fn page_index(State(st): State<Shared>, headers: HeaderMap) -> Response {
    if st.authenticate(&headers).is_none() {
        return Redirect::to("/login").into_response();
    }
    html(INDEX_HTML)
}

async fn page_login(State(st): State<Shared>, headers: HeaderMap) -> Response {
    if st.authenticate(&headers).is_some() {
        return Redirect::to("/").into_response();
    }
    html(LOGIN_HTML)
}

async fn asset(Path(name): Path<String>) -> Response {
    const SHORT: &str = "public, max-age=300";
    let (ctype, cache): (&str, &str) = match name.as_str() {
        "app.css" => ("text/css; charset=utf-8", SHORT),
        "i18n.js" => ("text/javascript; charset=utf-8", SHORT),
        "modules/core.js" | "modules/login.js" | "modules/dashboard.js" | "modules/tunnels.js"
        | "modules/connections.js" | "modules/logs.js" | "modules/config.js"
        | "modules/certs.js" | "modules/account.js" => ("text/javascript; charset=utf-8", SHORT),
        "vazirmatn.woff2" => ("font/woff2", "public, max-age=31536000, immutable"),
        "favicon.svg" => ("image/svg+xml", SHORT),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let body: axum::body::Body = match name.as_str() {
        "app.css" => APP_CSS.into(),
        "modules/core.js" => CORE_JS.into(),
        "modules/login.js" => LOGIN_JS.into(),
        "i18n.js" => I18N_JS.into(),
        "modules/dashboard.js" => DASHBOARD_JS.into(),
        "modules/tunnels.js" => TUNNELS_JS.into(),
        "modules/connections.js" => CONNECTIONS_JS.into(),
        "modules/logs.js" => LOGS_JS.into(),
        "modules/config.js" => CONFIG_JS.into(),
        "modules/certs.js" => CERTS_JS.into(),
        "modules/account.js" => ACCOUNT_JS.into(),
        "favicon.svg" => FAVICON_SVG.into(),
        _ => FONT_WOFF2.into(),
    };
    (
        [
            (header::CONTENT_TYPE, ctype),
            (header::CACHE_CONTROL, cache),
        ],
        body,
    )
        .into_response()
}

// ==========================================================================
// Auth endpoints
// ==========================================================================

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn api_login(
    State(st): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Response {
    let ip = st.client_ip(&headers, &peer);
    let wait = st.lock_remaining(ip);
    if wait > 0 {
        let mut res = json_err_detail(StatusCode::TOO_MANY_REQUESTS, "locked", &wait.to_string());
        if let Ok(v) = HeaderValue::from_str(&wait.to_string()) {
            res.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return res;
    }
    if req.username.len() > 64 || req.password.is_empty() || req.password.len() > 256 {
        return json_err(StatusCode::BAD_REQUEST, "bad_request");
    }

    let (stored_user, must_change) = {
        let c = st.creds.read().unwrap();
        (c.username.clone(), c.must_change)
    };
    let user_ok = ct_eq(req.username.trim().as_bytes(), stored_user.as_bytes());
    let pass_ok = st.check_password(req.password, user_ok).await;

    if !pass_ok {
        st.record_failure(ip);
        warn!("🔐 [Admin] Failed panel login from {}", ip);
        let jitter = 250 + (rand::random::<u64>() % 400);
        tokio::time::sleep(Duration::from_millis(jitter)).await;
        return json_err(StatusCode::UNAUTHORIZED, "invalid_credentials");
    }

    st.attempts.remove(&ip);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (token, sess) = st.create_session(&ip, ua, &stored_user);
    info!("🔓 [Admin] Panel login: '{}' from {}", stored_user, ip);
    let secure = st.cookie_secure(&headers);
    let mut res = Json(json!({
        "ok": true,
        "username": sess.user,
        "csrf": sess.csrf,
        "must_change_password": must_change,
    }))
    .into_response();
    if let Ok(v) = HeaderValue::from_str(&st.session_cookie(&token, secure)) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    res
}

async fn api_session(State(st): State<Shared>, headers: HeaderMap) -> Response {
    match st.authenticate(&headers) {
        Some((_, s)) => {
            let must_change = st.creds.read().unwrap().must_change;
            Json(json!({
                "authenticated": true,
                "username": s.user,
                "csrf": s.csrf,
                "sid": s.sid,
                "must_change_password": must_change,
                "read_only": st.cfg.read_only,
                "version": env!("CARGO_PKG_VERSION"),
                "role": metrics::role(),
            }))
            .into_response()
        }
        None => Json(json!({ "authenticated": false })).into_response(),
    }
}

async fn api_logout(
    State(st): State<Shared>,
    headers: HeaderMap,
    Extension(sess): Extension<Session>,
) -> Response {
    if let Some((key, _)) = st.authenticate(&headers) {
        st.sessions.remove(&key);
    }
    info!("🔒 [Admin] Panel logout: '{}'", sess.user);
    let mut res = Json(json!({ "ok": true })).into_response();
    if let Ok(v) = HeaderValue::from_str(&Inner::clear_cookie(st.cookie_secure(&headers))) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    res
}

#[derive(Deserialize)]
struct PasswordReq {
    current: String,
    new: String,
}

async fn api_change_password(
    State(st): State<Shared>,
    headers: HeaderMap,
    Extension(sess): Extension<Session>,
    Json(req): Json<PasswordReq>,
) -> Response {
    if req.new.chars().count() < MIN_PASSWORD_LEN || req.new.len() > 256 {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "password_too_short");
    }
    if req.new == req.current {
        return json_err(StatusCode::UNPROCESSABLE_ENTITY, "password_same");
    }
    if !st.check_password(req.current, true).await {
        tokio::time::sleep(Duration::from_millis(400)).await;
        return json_err(StatusCode::FORBIDDEN, "wrong_password");
    }
    let new_plain = req.new.clone();
    let new_pw = req.new;
    let hash = match tokio::task::spawn_blocking(move || hash_password(&new_pw)).await {
        Ok(Ok(h)) => h,
        _ => return json_err(StatusCode::INTERNAL_SERVER_ERROR, "hash_failed"),
    };
    let updated = {
        let mut c = st.creds.write().unwrap();
        c.password_hash = hash;
        c.must_change = false;
        c.updated_at = now();
        c.clone()
    };
    if st.password_in_config {
        // The password lives in `[admin]` of the config file: update it there (a backup of the old
        // file is kept). The panel restarts with the new section, so everybody signs in again.
        let res = current_config(&st)
            .map_err(|e| e.to_string())
            .and_then(|text| set_admin_password_in_text(&text, &new_plain))
            .and_then(|text| apply_config(&st, &text));
        if let Err(e) = res {
            error!("❌ [Admin] Could not write the password to the config: {}", e);
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, "save_failed");
        }
    } else if let Err(e) = save_credentials(&st.creds_path, &updated) {
        error!("❌ [Admin] Could not save credentials: {}", e);
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, "save_failed");
    }
    // Sign out every other session.
    let keep = st.authenticate(&headers).map(|(k, _)| k);
    st.sessions.retain(|k, _| Some(k) == keep.as_ref());
    info!("🔑 [Admin] Password changed by '{}'", sess.user);
    Json(json!({ "ok": true, "relogin": st.password_in_config })).into_response()
}

async fn api_list_sessions(
    State(st): State<Shared>,
    Extension(sess): Extension<Session>,
) -> Response {
    let mut v: Vec<serde_json::Value> = st
        .sessions
        .iter()
        .map(|e| {
            let s = e.value();
            json!({
                "sid": s.sid,
                "ip": s.ip,
                "ua": s.ua,
                "created": s.created,
                "last_seen": s.last_seen,
                "current": s.sid == sess.sid,
            })
        })
        .collect();
    v.sort_by_key(|x| std::cmp::Reverse(x["last_seen"].as_u64().unwrap_or(0)));
    Json(json!({ "sessions": v })).into_response()
}

async fn api_revoke_session(State(st): State<Shared>, Path(sid): Path<u64>) -> Response {
    let before = st.sessions.len();
    st.sessions.retain(|_, s| s.sid != sid);
    Json(json!({ "ok": true, "revoked": before - st.sessions.len() })).into_response()
}

// ==========================================================================
// Overview / metrics
// ==========================================================================

fn read_proc_kb(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
}

fn system_info() -> serde_json::Value {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let load: Vec<f64> = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|s| {
            s.split_whitespace()
                .take(3)
                .filter_map(|v| v.parse::<f64>().ok())
                .collect()
        })
        .unwrap_or_default();
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mem_total = read_proc_kb(&meminfo, "MemTotal:").map(|k| k * 1024);
    let mem_avail = read_proc_kb(&meminfo, "MemAvailable:").map(|k| k * 1024);
    let rss = read_proc_kb(&status, "VmRSS:").map(|k| k * 1024);
    let threads = status
        .lines()
        .find(|l| l.starts_with("Threads:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok());
    let fds = std::fs::read_dir("/proc/self/fd").ok().map(|d| d.count());
    #[allow(unused_mut)]
    let mut fd_limit: Option<u64> = None;
    #[cfg(unix)]
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            fd_limit = Some(rl.rlim_cur as u64);
        }
    }
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string());
    json!({
        "host": host,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "cpus": cpus,
        "load": load,
        "mem_total": mem_total,
        "mem_available": mem_avail,
        "rss": rss,
        "threads": threads,
        "fds": fds,
        "fd_limit": fd_limit,
    })
}

fn read_app_config(st: &Inner) -> Option<AppConfig> {
    let raw = std::fs::read_to_string(&st.config_path).ok()?;
    toml::from_str(&raw).ok()
}

fn config_summary(app: &AppConfig) -> serde_json::Value {
    let proto_list = |p: &Option<Vec<String>>| -> Vec<String> {
        crate::transport::parse_list(p.as_ref(), "admin")
            .iter()
            .map(|x| x.name().to_string())
            .collect()
    };
    if let Some(s) = &app.server {
        let reverse: Vec<_> = s
            .reverse
            .iter()
            .flatten()
            .map(|r| {
                json!({
                    "sni": r.sni,
                    "clean_ip": r.clean_ip,
                    "pool_size": r.pool_size.unwrap_or(8),
                    "location": r.location,
                })
            })
            .collect();
        let web: Vec<_> = s
            .web_server
            .iter()
            .flatten()
            .map(|w| json!({ "domain": w.domain, "path": w.path, "type": w.r#type, "target": w.target, "root": w.root }))
            .collect();
        let sni_proxy: Vec<_> = s
            .sni_proxy
            .iter()
            .flatten()
            .map(|p| json!({ "incoming_sni": p.incoming_sni, "target": p.target }))
            .collect();
        json!({
            "role": "server",
            "bind_addr": s.bind_addr,
            "protocols": proto_list(&s.protocols),
            "tunnel_sni": s.tunnel_sni,
            "camouflage_target": s.camouflage_target,
            "hidden_path": s.hidden_path,
            "secret_set": s.secret.as_deref().is_some_and(|v| !v.is_empty()),
            "acme": s.cloudflare_api_token.is_some() || s.arvancloud_api_token.is_some(),
            "reverse": reverse,
            "web_server": web,
            "sni_proxy": sni_proxy,
        })
    } else if let Some(c) = &app.client {
        let remotes: Vec<_> = c
            .remotes
            .iter()
            .map(|r| {
                json!({
                    "location": r.location,
                    "share_sni": r.share_sni.unwrap_or(0),
                    "sni": r.sni,
                    "port_mappings": r.port_mappings,
                })
            })
            .collect();
        let web: Vec<_> = c
            .web_server
            .iter()
            .flatten()
            .map(|w| json!({ "domain": w.domain, "path": w.path, "type": w.r#type, "target": w.target, "root": w.root }))
            .collect();
        let sni_proxy: Vec<_> = c
            .sni_proxy
            .iter()
            .flatten()
            .map(|p| json!({ "incoming_sni": p.incoming_sni, "target": p.target }))
            .collect();
        json!({
            "role": "client",
            "protocols": proto_list(&c.protocols),
            "remotes": remotes,
            "pool_size_per_node": c.pool_size_per_node.unwrap_or(8),
            "reverse_bind_addr": c.reverse_bind_addr,
            "reverse_tunnel_sni": c.reverse_tunnel_sni,
            "scanner_cdn": c.scanner_cdn,
            "check_interval_minutes": c.check_interval_minutes,
            "max_ping_ms": c.max_ping_ms,
            "hidden_path": c.hidden_path,
            "secret_set": c.secret.as_deref().is_some_and(|v| !v.is_empty()),
            "acme": c.cloudflare_api_token.is_some() || c.arvancloud_api_token.is_some(),
            "web_server": web,
            "sni_proxy": sni_proxy,
        })
    } else {
        json!({ "role": "unknown" })
    }
}

async fn api_overview(State(st): State<Shared>) -> Response {
    use std::sync::atomic::Ordering::Relaxed;
    let (tx_rate, rx_rate) = metrics::current_rate(3);
    let sessions = metrics::session_list();
    let count = |proto: &str| sessions.iter().filter(|s| s.proto == proto).count();
    let (mut n_h2, mut n_ws) = (count("h2"), count("wssmux"));
    if metrics::role() == "client" {
        // Direct pool connections are not in the registry: add the connected slots.
        let (h2, ws) = crate::client::admin_pool_counts().await;
        n_h2 += h2;
        n_ws += ws;
    }
    let path = if metrics::role() == "client" {
        crate::client::admin_path_name()
    } else {
        None
    };
    let summary = read_app_config(&st).map(|a| config_summary(&a));
    Json(json!({
        "role": metrics::role(),
        "version": env!("CARGO_PKG_VERSION"),
        "uptime": metrics::uptime_secs(),
        "now": now(),
        "traffic": {
            "tx_total": metrics::TX_BYTES.load(Relaxed),
            "rx_total": metrics::RX_BYTES.load(Relaxed),
            "tx_rate": tx_rate,
            "rx_rate": rx_rate,
        },
        "streams": {
            "active": metrics::STREAMS_ACTIVE.load(Relaxed),
            "total": metrics::STREAMS_TOTAL.load(Relaxed),
        },
        "unauthorized": metrics::UNAUTHORIZED.load(Relaxed),
        "sessions": { "total": n_h2 + n_ws, "h2": n_h2, "wssmux": n_ws },
        "path": path,
        "config": summary,
        "system": system_info(),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct SeriesQuery {
    res: Option<String>,
}

async fn api_series(Query(q): Query<SeriesQuery>) -> Response {
    let res = if q.res.as_deref() == Some("min") { "min" } else { "sec" };
    Json(json!({ "res": res, "points": metrics::series_points(res) })).into_response()
}

async fn api_tunnels() -> Response {
    let role = metrics::role();
    let client = if role == "client" {
        crate::client::admin_snapshot().await
    } else {
        None
    };
    let server = if role == "server" {
        Some(crate::server::admin_snapshot())
    } else {
        None
    };
    Json(json!({
        "role": role,
        "sessions": metrics::session_list(),
        "client": client,
        "server": server,
        "reverse": crate::reverse::admin_snapshot().await,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct StreamsQuery {
    limit: Option<usize>,
}

async fn api_streams(Query(q): Query<StreamsQuery>) -> Response {
    let (list, total) = metrics::stream_list(q.limit.unwrap_or(200).clamp(1, 1000));
    Json(json!({ "total": total, "streams": list, "now": now() })).into_response()
}

#[derive(Deserialize)]
struct LogsQuery {
    after: Option<u64>,
    level: Option<String>,
    limit: Option<usize>,
}

async fn api_logs(Query(q): Query<LogsQuery>) -> Response {
    let (entries, last) = metrics::logs_after(
        q.after.unwrap_or(0),
        q.level.as_deref(),
        q.limit.unwrap_or(500).clamp(1, 2000),
    );
    Json(json!({ "last": last, "entries": entries })).into_response()
}

// ==========================================================================
// Certificates
// ==========================================================================

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
        .parent()
        .unwrap_or(FsPath::new(""))
        .to_path_buf()
}

fn cert_infos() -> Vec<serde_json::Value> {
    let dir = exe_dir().join("certs");
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return out;
    };
    let t = now() as i64;
    for entry in rd.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let zone = entry.file_name().to_string_lossy().to_string();
        let full = entry.path().join("fullchain.pem");
        let Ok(file) = std::fs::File::open(&full) else {
            continue;
        };
        let mut reader = std::io::BufReader::new(file);
        let first = rustls_pemfile::certs(&mut reader).next().and_then(|r| r.ok());
        let validity = first.as_ref().and_then(|der| crate::certinfo::validity(der.as_ref()));
        let modified = std::fs::metadata(&full)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        out.push(json!({
            "zone": zone,
            "not_before": validity.map(|v| v.not_before),
            "not_after": validity.map(|v| v.not_after),
            "days_left": validity.map(|v| (v.not_after - t).div_euclid(86400)),
            "needs_renewal": crate::acme::needs_renewal(&zone),
            "has_key": entry.path().join("privkey.pem").exists(),
            "modified": modified,
        }));
    }
    out.sort_by(|a, b| a["zone"].as_str().cmp(&b["zone"].as_str()));
    out
}

async fn api_certs() -> Response {
    let list = tokio::task::spawn_blocking(cert_infos).await.unwrap_or_default();
    Json(json!({ "certs": list, "now": now() })).into_response()
}

// ==========================================================================
// Config editor
// ==========================================================================

fn backup_prefix(st: &Inner) -> String {
    format!(
        "{}.bak-",
        st.config_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "config.toml".into())
    )
}

fn list_backups(st: &Inner) -> Vec<serde_json::Value> {
    let prefix = backup_prefix(st);
    let dir = match st.config_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut v: Vec<(u64, String, u64)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let ts = name.strip_prefix(&prefix)?.parse::<u64>().ok()?;
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            Some((ts, name, size))
        })
        .collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.0));
    v.into_iter()
        .map(|(ts, name, size)| json!({ "name": name, "time": ts, "size": size }))
        .collect()
}

fn prune_backups(st: &Inner) {
    let all = list_backups(st);
    let dir = match st.config_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    for old in all.iter().skip(BACKUPS_KEPT) {
        if let Some(n) = old["name"].as_str() {
            let _ = std::fs::remove_file(dir.join(n));
        }
    }
}

/// Parses and sanity-checks a config. Returns warning codes for the UI.
fn validate_config(st: &Inner, content: &str) -> Result<Vec<&'static str>, String> {
    if content.len() > MAX_CONFIG_BYTES {
        return Err("config is too large".into());
    }
    let app: AppConfig = toml::from_str(content).map_err(|e| e.to_string())?;
    if app.server.is_none() && app.client.is_none() {
        return Err("neither a [server] nor a [client] section was found".into());
    }
    let mut warnings = Vec::new();
    if app.server.is_some() && app.client.is_some() {
        warnings.push("both_roles");
    }
    if let Some(a) = &app.admin {
        if a.bind_addr.parse::<SocketAddr>().is_err() {
            return Err(format!("[admin] bind_addr '{}' is not a valid ip:port", a.bind_addr));
        }
        if !a.enabled {
            warnings.push("admin_disabled");
        }
        if config_password(a).is_some_and(|p| p.chars().count() < MIN_PASSWORD_LEN) {
            warnings.push("admin_weak_password");
        }
        if a.bind_addr != st.cfg.bind_addr {
            warnings.push("admin_bind_changed");
        }
        if a.trust_proxy != st.cfg.trust_proxy {
            warnings.push("admin_proxy_changed");
        }
    } else {
        warnings.push("admin_removed");
    }
    Ok(warnings)
}

fn current_config(st: &Inner) -> Result<String, std::io::Error> {
    std::fs::read_to_string(&st.config_path)
}

fn apply_config(st: &Inner, content: &str) -> Result<Option<String>, String> {
    let mut backup_name = None;
    if let Ok(old) = current_config(st) {
        if !old.trim().is_empty() && old != content {
            let name = format!("{}{}", backup_prefix(st), now());
            let path = st
                .config_path
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .map(|d| d.join(&name))
                .unwrap_or_else(|| PathBuf::from(&name));
            atomic_write(&path, old.as_bytes(), true).map_err(|e| format!("backup: {}", e))?;
            backup_name = Some(name);
        }
    }
    atomic_write(&st.config_path, content.as_bytes(), false).map_err(|e| e.to_string())?;
    prune_backups(st);
    Ok(backup_name)
}

async fn api_config_get(State(st): State<Shared>) -> Response {
    match current_config(&st) {
        Ok(content) => {
            let modified = std::fs::metadata(&st.config_path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            Json(json!({
                "content": content,
                "hash": sha256_hex(content.as_bytes()),
                "path": st.config_path.display().to_string(),
                "modified": modified,
                "read_only": st.cfg.read_only,
                "backups": list_backups(&st),
            }))
            .into_response()
        }
        Err(e) => json_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "read_failed", &e.to_string()),
    }
}

async fn api_config_guide() -> Response {
    Json(json!({
        "client": CLIENT_CONFIG_SAMPLE,
        "server": SERVER_CONFIG_SAMPLE,
    }))
    .into_response()
}

async fn api_repo_stars() -> Response {
    let response = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .user_agent(concat!("GhostRPC/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client
            .get("https://api.github.com/repos/ArashAfkandeh/GhostRPC")
            .send()
            .await,
        Err(e) => {
            warn!("Could not create GitHub repository stats request: {}", e);
            return json_err(StatusCode::SERVICE_UNAVAILABLE, "repo_stats_unavailable");
        }
    };

    match response {
        Ok(response) if response.status().is_success() => match response.json::<serde_json::Value>().await {
            Ok(data) => match data.get("stargazers_count").and_then(serde_json::Value::as_u64) {
                Some(stars) => Json(json!({ "stars": stars })).into_response(),
                None => {
                    warn!("GitHub repository stats response did not contain a valid star count");
                    json_err(StatusCode::BAD_GATEWAY, "repo_stats_invalid")
                }
            },
            Err(e) => {
                warn!("Could not read GitHub repository stats response: {}", e);
                json_err(StatusCode::BAD_GATEWAY, "repo_stats_unavailable")
            }
        },
        Ok(response) => {
            warn!("GitHub repository stats request returned HTTP {}", response.status());
            json_err(StatusCode::BAD_GATEWAY, "repo_stats_unavailable")
        }
        Err(e) => {
            warn!("Could not fetch GitHub repository stats: {}", e);
            json_err(StatusCode::SERVICE_UNAVAILABLE, "repo_stats_unavailable")
        }
    }
}

#[derive(Deserialize)]
struct ValidateReq {
    content: String,
}

async fn api_config_validate(State(st): State<Shared>, Json(req): Json<ValidateReq>) -> Response {
    match validate_config(&st, &req.content) {
        Ok(w) => Json(json!({ "ok": true, "warnings": w })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e })).into_response(),
    }
}

#[derive(Deserialize)]
struct SaveReq {
    content: String,
    base_hash: String,
}

async fn api_config_put(
    State(st): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(sess): Extension<Session>,
    Json(req): Json<SaveReq>,
) -> Response {
    if st.cfg.read_only {
        return json_err(StatusCode::FORBIDDEN, "read_only");
    }
    let current = match current_config(&st) {
        Ok(c) => c,
        Err(e) => return json_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "read_failed", &e.to_string()),
    };
    let cur_hash = sha256_hex(current.as_bytes());
    if cur_hash != req.base_hash {
        return json_err_detail(StatusCode::CONFLICT, "conflict", &cur_hash);
    }
    let warnings = match validate_config(&st, &req.content) {
        Ok(w) => w,
        Err(e) => return json_err_detail(StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", &e),
    };
    // Normalise line endings so the editor round-trips cleanly.
    let content = req.content.replace("\r\n", "\n");
    match apply_config(&st, &content) {
        Ok(backup) => {
            info!(
                "📝 [Admin] Config saved by '{}' from {} (hot-reload will apply it)",
                sess.user,
                st.client_ip(&headers, &peer)
            );
            Json(json!({
                "ok": true,
                "hash": sha256_hex(content.as_bytes()),
                "backup": backup,
                "warnings": warnings,
            }))
            .into_response()
        }
        Err(e) => json_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "write_failed", &e),
    }
}

#[derive(Deserialize)]
struct RestoreReq {
    name: String,
}

async fn api_config_restore(
    State(st): State<Shared>,
    Extension(sess): Extension<Session>,
    Json(req): Json<RestoreReq>,
) -> Response {
    if st.cfg.read_only {
        return json_err(StatusCode::FORBIDDEN, "read_only");
    }
    let prefix = backup_prefix(&st);
    if !req.name.starts_with(&prefix)
        || req.name.contains('/')
        || req.name.contains('\\')
        || req.name[prefix.len()..].parse::<u64>().is_err()
    {
        return json_err(StatusCode::BAD_REQUEST, "bad_backup_name");
    }
    let path = st
        .config_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.join(&req.name))
        .unwrap_or_else(|| PathBuf::from(&req.name));
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return json_err(StatusCode::NOT_FOUND, "backup_not_found"),
    };
    if let Err(e) = validate_config(&st, &content) {
        return json_err_detail(StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", &e);
    }
    match apply_config(&st, &content) {
        Ok(backup) => {
            info!("♻️ [Admin] Config restored from {} by '{}'", req.name, sess.user);
            Json(json!({ "ok": true, "hash": sha256_hex(content.as_bytes()), "backup": backup })).into_response()
        }
        Err(e) => json_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "write_failed", &e),
    }
}

// ==========================================================================
// Actions
// ==========================================================================

async fn api_action_reload(
    State(st): State<Shared>,
    Extension(sess): Extension<Session>,
) -> Response {
    if st.cfg.read_only {
        return json_err(StatusCode::FORBIDDEN, "read_only");
    }
    info!("🔄 [Admin] Config reload requested by '{}'", sess.user);
    metrics::reload_notify().notify_one();
    Json(json!({ "ok": true })).into_response()
}

async fn api_action_clear_dead(
    State(st): State<Shared>,
    Extension(sess): Extension<Session>,
) -> Response {
    if st.cfg.read_only {
        return json_err(StatusCode::FORBIDDEN, "read_only");
    }
    let n = if metrics::role() == "client" {
        let mut g = crate::client::get_client_dead_targets().write().unwrap();
        let n = g.len();
        g.clear();
        n
    } else {
        let mut g = crate::server::get_dead_targets().write().unwrap();
        let n = g.len();
        g.clear();
        n
    };
    info!("🧹 [Admin] Circuit breaker cleared ({} target(s)) by '{}'", n, sess.user);
    Json(json!({ "ok": true, "cleared": n })).into_response()
}

async fn api_action_rescan_clean_ips(
    State(st): State<Shared>,
    Extension(sess): Extension<Session>,
) -> Response {
    if st.cfg.read_only {
        return json_err(StatusCode::FORBIDDEN, "read_only");
    }
    if metrics::role() != "client" {
        return json_err(StatusCode::CONFLICT, "scanner_unavailable");
    }
    match crate::client::admin_clear_clean_ips().await {
        Ok(cleared) => {
            info!(
                "🧹 [Admin] Clean-IP cache cleared ({} IP(s)); a new scan was requested by '{}'",
                cleared, sess.user
            );
            Json(json!({ "ok": true, "cleared": cleared, "scan_requested": true })).into_response()
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::NotConnected
            ) =>
        {
            json_err(StatusCode::SERVICE_UNAVAILABLE, "scanner_unavailable")
        }
        Err(e) => {
            error!("❌ [Admin] Could not clear clean-IP cache: {}", e);
            json_err(StatusCode::INTERNAL_SERVER_ERROR, "clean_ip_clear_failed")
        }
    }
}

// ==========================================================================
// Router + entry point
// ==========================================================================

fn build_router(st: Shared) -> Router {
    let protected = Router::new()
        .route("/api/logout", post(api_logout))
        .route("/api/overview", get(api_overview))
        .route("/api/series", get(api_series))
        .route("/api/tunnels", get(api_tunnels))
        .route("/api/streams", get(api_streams))
        .route("/api/logs", get(api_logs))
        .route("/api/certs", get(api_certs))
        .route("/api/config", get(api_config_get).put(api_config_put))
        .route("/api/config-guide", get(api_config_guide))
        .route("/api/repo-stars", get(api_repo_stars))
        .route("/api/config/validate", post(api_config_validate))
        .route("/api/config/restore", post(api_config_restore))
        .route("/api/actions/reload", post(api_action_reload))
        .route("/api/actions/clear-dead-targets", post(api_action_clear_dead))
        .route("/api/actions/rescan-clean-ips", post(api_action_rescan_clean_ips))
        .route("/api/account/password", post(api_change_password))
        .route("/api/account/sessions", get(api_list_sessions))
        .route("/api/account/sessions/{sid}", delete(api_revoke_session))
        .route_layer(middleware::from_fn_with_state(st.clone(), auth_mw));

    Router::new()
        .route("/", get(page_index))
        .route("/login", get(page_login))
        .route("/assets/{*name}", get(asset))
        .route("/api/login", post(api_login))
        .route("/api/session", get(api_session))
        .merge(protected)
        .layer(middleware::map_response(security_headers))
        .with_state(st)
}

fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Runs the panel until `cancel` fires. Errors are logged, never fatal for the tunnel.
pub async fn run(cfg: AdminConfig, config_path: String, cancel: CancellationToken) {
    let addr: SocketAddr = match cfg.bind_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("❌ [Admin] Invalid bind_addr '{}': {}", cfg.bind_addr, e);
            return;
        }
    };
    let creds_path = credentials_path(&cfg, &config_path);
    let (creds, seed) = match load_or_create_credentials(&cfg, &creds_path) {
        Ok(v) => v,
        Err(e) => {
            error!("❌ [Admin] Credentials error: {}", e);
            return;
        }
    };
    match &seed {
        Seed::Generated(pw) => {
            eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║  👻 GhostRPC admin panel — first start                        ");
            eprintln!("║  username: {}", creds.username);
            eprintln!("║  password: {}", pw);
            eprintln!("║  (shown once — change it after signing in)");
            eprintln!("╚══════════════════════════════════════════════════════════════╝\n");
        }
        Seed::Config => {
            if config_password(&cfg).is_some_and(|p| p.chars().count() < MIN_PASSWORD_LEN) {
                warn!("⚠️ [Admin] The [admin] password in the config is shorter than {} characters.", MIN_PASSWORD_LEN);
            }
            info!("🔑 [Admin] Credentials are taken from the [admin] section of the config file.");
        }
        Seed::Existing => {}
    }

    let dummy_hash = match hash_password(&random_token()) {
        Ok(h) => h,
        Err(e) => {
            error!("❌ [Admin] Hashing self-test failed: {}", e);
            return;
        }
    };
    let ttl = cfg.session_ttl_minutes.unwrap_or(480).max(5) * 60;
    let st: Shared = Arc::new(Inner {
        cfg: cfg.clone(),
        config_path: PathBuf::from(&config_path),
        creds_path,
        password_in_config: config_password(&cfg).is_some(),
        creds: RwLock::new(creds),
        sessions: DashMap::new(),
        attempts: DashMap::new(),
        dummy_hash,
        hash_sem: tokio::sync::Semaphore::new(4),
        ttl_secs: ttl,
    });

    // Housekeeping: expired sessions and old limiter entries.
    {
        let st = st.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tick.tick() => {
                        let t = now();
                        st.sessions.retain(|_, s| {
                            t.saturating_sub(s.last_seen) <= st.ttl_secs
                                && t.saturating_sub(s.created) <= SESSION_ABSOLUTE_SECS
                        });
                        st.attempts.retain(|_, a| {
                            a.locked_until > t || t.saturating_sub(a.window_start) <= FAIL_WINDOW_SECS * 6
                        });
                    }
                }
            }
        });
    }

    // The previous instance (hot-reload) may still be releasing the port: retry briefly.
    let mut listener = None;
    for _ in 0..20 {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                listener = Some(l);
                break;
            }
            Err(e) => {
                if cancel.is_cancelled() {
                    return;
                }
                if e.kind() != std::io::ErrorKind::AddrInUse {
                    error!("❌ [Admin] Cannot listen on {}: {}", addr, e);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
    let Some(listener) = listener else {
        error!("❌ [Admin] Address {} stays in use; panel not started.", addr);
        return;
    };

    info!("🖥️ [Admin] Panel listening on http://{} (user '{}')", addr, st.creds.read().unwrap().username);
    if !is_loopback(&addr) && !cfg.trust_proxy {
        warn!(
            "⚠️ [Admin] The panel is reachable from the network over plain HTTP. Bind it to 127.0.0.1 and publish it through a TLS reverse_proxy web_server route (then set trust_proxy = true)."
        );
    }
    if cfg.read_only {
        info!("🔒 [Admin] Read-only mode: config edits and actions are disabled.");
    }

    metrics::spawn_sampler();
    let app = build_router(st).into_make_service_with_connect_info::<SocketAddr>();
    let shutdown = cancel.clone();
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
    {
        error!("❌ [Admin] Server error: {}", e);
    }
    info!("🖥️ [Admin] Panel on {} stopped", addr);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password(&h, "correct horse battery"));
        assert!(!verify_password(&h, "correct horse batterY"));
        assert!(!verify_password("not a hash", "x"));
    }

    #[test]
    fn ct_eq_handles_length_and_content() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"", b"a"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn generated_passwords_use_the_safe_alphabet() {
        let p = random_password(24);
        assert_eq!(p.len(), 24);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric() && !"0O1lI".contains(c)));
        assert_ne!(random_password(24), random_password(24));
    }

    #[test]
    fn tokens_are_unique_and_long() {
        let a = random_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, random_token());
    }

    #[test]
    fn cookie_parsing() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; ghost_sid=abc123; b=2"));
        assert_eq!(Inner::token_from_headers(&h).as_deref(), Some("abc123"));
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("ghost_sidx=abc; other=1"));
        assert!(Inner::token_from_headers(&h).is_none());
        assert!(Inner::token_from_headers(&HeaderMap::new()).is_none());
    }

    #[test]
    fn cookie_header_split_into_crumbs_is_handled() {
        // HTTP/2 browsers send each cookie as its own header field; the session cookie may not be first.
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, HeaderValue::from_static("theme=dark"));
        h.append(header::COOKIE, HeaderValue::from_static("other=1"));
        h.append(header::COOKIE, HeaderValue::from_static("ghost_sid=tok123"));
        assert_eq!(Inner::token_from_headers(&h).as_deref(), Some("tok123"));
    }

    #[test]
    fn toml_string_escapes_round_trip() {
        for pw in ["plain-pass-123", "with \"quotes\" and \\ slash", "tab\tnew\nline", "ünïcödé-پسورد-۱۲۳", "a#b = [c]"] {
            let doc = format!("p = {}", toml_string(pw));
            let v: toml::Value = toml::from_str(&doc).unwrap_or_else(|e| panic!("{}: {}", doc, e));
            assert_eq!(v["p"].as_str(), Some(pw));
        }
    }

    #[test]
    fn admin_password_is_rewritten_in_place() {
        let cfg = "[server]\nbind_addr = \"0.0.0.0:443\"\n\n# panel\n[admin]   # panel section\nbind_addr = \"127.0.0.1:8088\"\n# password = \"commented\"\npassword = \"old-password-1\"\nusername = \"root\"\n\n[other]\npassword = \"keep-me\"\n";
        let out = set_admin_password_in_text(cfg, "new \"pw\" 12345").unwrap();
        let parsed: AppConfig = toml::from_str(&out).unwrap();
        let a = parsed.admin.unwrap();
        assert_eq!(a.password.as_deref(), Some("new \"pw\" 12345"));
        assert_eq!(a.username.as_deref(), Some("root"));
        assert!(out.contains("# password = \"commented\""));
        assert!(out.contains("[other]\npassword = \"keep-me\""));
        assert!(out.ends_with('\n'));
        // No password line yet: it is inserted right below the header.
        let out2 = set_admin_password_in_text("[client]\n[admin]\nenabled = true\n", "abcdefghij1").unwrap();
        let a2: AppConfig = toml::from_str(&out2).unwrap();
        assert_eq!(a2.admin.unwrap().password.as_deref(), Some("abcdefghij1"));
        // CRLF files stay CRLF.
        let out3 = set_admin_password_in_text("[client]\r\n[admin]\r\npassword = \"x\"\r\n", "abcdefghij1").unwrap();
        assert!(out3.contains("\r\n") && !out3.replace("\r\n", "").contains('\n'));
        assert!(set_admin_password_in_text("[client]\n", "x").is_err());
    }

    #[test]
    fn config_credentials_are_authoritative() {
        let cfg: AdminConfig = toml::from_str("username = \"arash\"\npassword = \"my-config-pass-1\"").unwrap();
        let (c, seed) = load_or_create_credentials(&cfg, FsPath::new("/nonexistent/creds.json")).unwrap();
        assert!(matches!(seed, Seed::Config));
        assert_eq!(c.username, "arash");
        assert!(!c.must_change);
        assert!(verify_password(&c.password_hash, "my-config-pass-1"));
        assert!(!verify_password(&c.password_hash, "other"));
    }

    #[test]
    fn paths_resolve_next_to_config() {
        assert_eq!(
            resolve_next_to_config("/etc/ghost/config.toml", "creds.json"),
            PathBuf::from("/etc/ghost/creds.json")
        );
        assert_eq!(
            resolve_next_to_config("config.toml", "creds.json"),
            PathBuf::from("creds.json")
        );
        assert_eq!(
            resolve_next_to_config("/etc/ghost/config.toml", "/var/lib/creds.json"),
            PathBuf::from("/var/lib/creds.json")
        );
    }

    fn test_state(trust_proxy: bool) -> Inner {
        let cfg: AdminConfig = toml::from_str(&format!("trust_proxy = {}", trust_proxy)).unwrap();
        Inner {
            cfg,
            config_path: PathBuf::from("config.toml"),
            creds_path: PathBuf::from("creds.json"),
            password_in_config: false,
            creds: RwLock::new(Credentials {
                username: "admin".into(),
                password_hash: String::new(),
                must_change: false,
                updated_at: 0,
            }),
            sessions: DashMap::new(),
            attempts: DashMap::new(),
            dummy_hash: String::new(),
            hash_sem: tokio::sync::Semaphore::new(1),
            ttl_secs: 600,
        }
    }

    #[test]
    fn login_limiter_locks_after_repeated_failures() {
        let st = test_state(false);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        for _ in 0..MAX_FAILS - 1 {
            st.record_failure(ip);
            assert_eq!(st.lock_remaining(ip), 0);
        }
        st.record_failure(ip);
        let wait = st.lock_remaining(ip);
        assert!(wait > 0 && wait <= 300, "wait = {}", wait);
        // Another address is unaffected.
        assert_eq!(st.lock_remaining("203.0.113.10".parse().unwrap()), 0);
    }

    #[test]
    fn forwarded_ip_only_trusted_when_configured() {
        let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.7, 10.0.0.1"));
        assert_eq!(test_state(false).client_ip(&h, &peer), peer.ip());
        assert_eq!(
            test_state(true).client_ip(&h, &peer),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn sessions_expire_and_are_bounded() {
        let st = test_state(false);
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let (token, sess) = st.create_session(&ip, "ua", "admin");
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(&format!("{}={}", COOKIE_NAME, token)).unwrap());
        assert_eq!(st.authenticate(&h).map(|(_, s)| s.sid), Some(sess.sid));
        // Idle timeout.
        for mut e in st.sessions.iter_mut() {
            e.last_seen = now() - st.ttl_secs - 5;
        }
        assert!(st.authenticate(&h).is_none());
        assert!(st.sessions.is_empty());
        // Cap.
        for _ in 0..MAX_SESSIONS + 5 {
            st.create_session(&ip, "ua", "admin");
        }
        assert!(st.sessions.len() <= MAX_SESSIONS);
    }

    #[test]
    fn config_validation_rules() {
        let st = test_state(false);
        assert!(validate_config(&st, "[server]\nbind_addr = \"0.0.0.0:443\"\n").is_ok());
        assert!(validate_config(&st, "[server\n").is_err());
        assert!(validate_config(&st, "log_level = \"info\"\n").is_err());
        assert!(validate_config(&st, "[client]\n[admin]\nbind_addr = \"nope\"\n").is_err());
        let w = validate_config(&st, "[client]\n[server]\n[admin]\nenabled = false\n").unwrap();
        assert!(w.contains(&"both_roles") && w.contains(&"admin_disabled"));
        let w = validate_config(&st, "[client]\n").unwrap();
        assert!(w.contains(&"admin_removed"));
    }
}
