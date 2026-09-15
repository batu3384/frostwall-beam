//! Frostwall Beam mailbox — rendezvous: pairing code → iroh `EndpointId`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

const TTL: Duration = Duration::from_secs(10 * 60);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const REGISTER_RATE_MAX: u32 = 30;
const LOOKUP_RATE_MAX: u32 = 120;
const RATE_WINDOW: Duration = Duration::from_secs(60);

const MAX_HINT_LEN: usize = 256;
/// Lockstep client `internet.rs` `MAILBOX_BODY_MAX`.
const BODY_MAX: usize = 64 * 1024;
/// Lockstep `internet.rs` invite caps.
const MAX_RELAYS: usize = 3;
const MAX_IPS: usize = 6;
/// Lockstep `protocol::MAX_DISPLAY_NAME`.
const MAX_DISPLAY_NAME: usize = 48;

/// Standalone binary bind. `host` must be an IP (`MAILBOX_BIND`, default
/// `127.0.0.1` in `main`) so a bare `cargo run` is not a LAN listener.
pub fn parse_listen_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("MAILBOX_BIND must be an IP address".into());
    }
    let ip: IpAddr = host
        .parse()
        .map_err(|_| format!("MAILBOX_BIND must be an IP address (got {host:?})"))?;
    Ok(SocketAddr::new(ip, port))
}

struct Entry {
    endpoint_id: String,
    device_name: Option<String>,
    relays: Vec<String>,
    ips: Vec<String>,
    token: String,
    expires_at: Instant,
}

#[derive(Default)]
struct Mailbox {
    entries: Mutex<HashMap<String, Entry>>,
    rates: Mutex<HashMap<String, (u32, Instant)>>,
}

type SharedState = Arc<Mailbox>;

#[derive(Deserialize)]
struct RegisterRequest {
    code: String,
    endpoint_id: String,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    ips: Vec<String>,
}

/// Optional body on `POST /register/{code}/refresh`. Empty body = TTL only.
/// Present `relays`/`ips` replace dial hints in place (no unregister gap).
#[derive(Deserialize)]
struct RefreshRequest {
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    relays: Option<Vec<String>>,
    #[serde(default)]
    ips: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct RegisterResponse {
    token: String,
}

#[derive(Serialize, Deserialize)]
pub struct LookupResponse {
    pub endpoint_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn normalize_code(code: &str) -> String {
    code.trim().to_string()
}

fn valid_code(code: &str) -> bool {
    code.len() == 6 && code.chars().all(|c| c.is_ascii_digit())
}

fn valid_endpoint_id(id: &str) -> bool {
    let t = id.trim();
    t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())
}

/// Same rules as `internet.rs` `shareable_socket`: do not publish loopback,
/// RFC1918, CGNAT, or link-local as Remote dial hints.
fn ipv4_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 0x40
}

fn shareable_v4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_private()
        && !ipv4_cgnat(ip)
        && !ip.is_broadcast()
}

fn shareable_socket(sa: &SocketAddr) -> bool {
    match sa.ip() {
        IpAddr::V4(ip) => shareable_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return shareable_v4(v4);
            }
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_unique_local()
        }
    }
}

fn sanitize_display_name(name: Option<&str>) -> Option<String> {
    let t = name?.trim();
    if t.is_empty() {
        return None;
    }
    let mut out = String::new();
    for c in t.chars() {
        if c.is_control() {
            continue;
        }
        if out.len() + c.len_utf8() > MAX_DISPLAY_NAME {
            break;
        }
        out.push(c);
    }
    if out.is_empty() { None } else { Some(out) }
}

fn https_url_host(s: &str) -> Option<&str> {
    if s.len() < 8 || !s.is_char_boundary(8) || !s[..8].eq_ignore_ascii_case("https://") {
        return None;
    }
    let rest = &s[8..];
    if rest.is_empty() || rest.contains('@') {
        return None;
    }
    let auth = rest.split('/').next().unwrap_or("");
    if auth.is_empty() {
        return None;
    }
    if let Some(inner) = auth.strip_prefix('[') {
        return inner.split(']').next().filter(|h| !h.is_empty());
    }
    Some(auth.split(':').next().unwrap_or("")).filter(|h| !h.is_empty())
}

fn relay_host_shareable(host: &str) -> bool {
    // Lockstep `internet.rs`: iroh FQDN trailing dots are valid.
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return shareable_socket(&SocketAddr::new(ip, 443));
    }
    host.contains('.') && !host.starts_with('.')
}

fn sanitize_relays(raw: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for s in raw {
        let t = s.trim();
        if t.is_empty() || t.len() > MAX_HINT_LEN || t.chars().any(|c| c.is_control() || c.is_whitespace()) {
            continue;
        }
        if !t.to_ascii_lowercase().starts_with("https://") {
            continue;
        }
        let Some(host) = https_url_host(t) else {
            continue;
        };
        if !relay_host_shareable(host) {
            continue;
        }
        out.push(t.to_string());
        if out.len() >= MAX_RELAYS {
            break;
        }
    }
    out
}

fn sanitize_ips(raw: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for s in raw {
        let t = s.trim();
        if t.is_empty() || t.len() > MAX_HINT_LEN {
            continue;
        }
        let Ok(sa) = t.parse::<SocketAddr>() else {
            continue;
        };
        if !shareable_socket(&sa) {
            continue;
        }
        out.push(sa.to_string());
        if out.len() >= MAX_IPS {
            break;
        }
    }
    out
}

async fn allow_rate(state: &Mailbox, key: &str, max: u32) -> bool {
    let mut rates = state.rates.lock().await;
    let now = Instant::now();
    let entry = rates.entry(key.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) > RATE_WINDOW {
        *entry = (0, now);
    }
    if entry.0 >= max {
        return false;
    }
    entry.0 += 1;
    true
}

fn client_rate_key(addr: SocketAddr) -> String {
    addr.ip().to_string()
}

async fn register(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), StatusCode> {
    if !allow_rate(
        &state,
        &format!("reg:{}", client_rate_key(addr)),
        REGISTER_RATE_MAX,
    )
    .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let code = normalize_code(&req.code);
    if !valid_code(&code) || !valid_endpoint_id(&req.endpoint_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut entries = state.entries.lock().await;
    let now = Instant::now();
    match entries.get(&code) {
        Some(e) if e.expires_at > now => return Err(StatusCode::CONFLICT),
        Some(_) => {
            entries.remove(&code);
        }
        None => {}
    }
    let token = Uuid::new_v4().to_string();
    entries.insert(
        code,
        Entry {
            endpoint_id: req.endpoint_id.trim().to_string(),
            device_name: sanitize_display_name(req.device_name.as_deref()),
            relays: sanitize_relays(req.relays),
            ips: sanitize_ips(req.ips),
            token: token.clone(),
            expires_at: Instant::now() + TTL,
        },
    );
    Ok((StatusCode::CREATED, Json(RegisterResponse { token })))
}

async fn lookup(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(code): Path<String>,
) -> Result<Json<LookupResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !allow_rate(
        &state,
        &format!("lkp:{}", client_rate_key(addr)),
        LOOKUP_RATE_MAX,
    )
    .await
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limit exceeded".to_string(),
            }),
        ));
    }
    let code = normalize_code(&code);
    if !valid_code(&code) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid code format".to_string(),
            }),
        ));
    }
    let entries = state.entries.lock().await;
    match entries.get(&code) {
        Some(entry) if entry.expires_at > Instant::now() => Ok(Json(LookupResponse {
            endpoint_id: entry.endpoint_id.clone(),
            device_name: entry.device_name.clone(),
            relays: entry.relays.clone(),
            ips: entry.ips.clone(),
        })),
        _ => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "no peer registered for this code (expired or never registered)".to_string(),
            }),
        )),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

async fn unregister(
    State(state): State<SharedState>,
    Path(code): Path<String>,
    headers: HeaderMap,
) -> StatusCode {
    let code = normalize_code(&code);
    if !valid_code(&code) {
        return StatusCode::BAD_REQUEST;
    }
    let Some(token) = bearer_token(&headers) else {
        return StatusCode::UNAUTHORIZED;
    };
    let mut entries = state.entries.lock().await;
    match entries.get(&code) {
        Some(entry) if entry.token == token => {
            entries.remove(&code);
            StatusCode::NO_CONTENT
        }
        _ => StatusCode::UNAUTHORIZED,
    }
}

async fn refresh(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(code): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    if !allow_rate(
        &state,
        &format!("reg:{}", client_rate_key(addr)),
        REGISTER_RATE_MAX,
    )
    .await
    {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let code = normalize_code(&code);
    if !valid_code(&code) {
        return StatusCode::BAD_REQUEST;
    }
    let Some(token) = bearer_token(&headers) else {
        return StatusCode::UNAUTHORIZED;
    };
    let hints = if body.is_empty() {
        None
    } else {
        match serde_json::from_slice::<RefreshRequest>(&body) {
            Ok(r) => Some(r),
            Err(_) => return StatusCode::BAD_REQUEST,
        }
    };
    let mut entries = state.entries.lock().await;
    match entries.get_mut(&code) {
        Some(entry) if entry.token == token => {
            if let Some(h) = hints {
                if let Some(relays) = h.relays {
                    entry.relays = sanitize_relays(relays);
                }
                if let Some(ips) = h.ips {
                    entry.ips = sanitize_ips(ips);
                }
                if let Some(name) = h.device_name {
                    entry.device_name = sanitize_display_name(Some(&name));
                }
            }
            entry.expires_at = Instant::now() + TTL;
            StatusCode::NO_CONTENT
        }
        _ => StatusCode::UNAUTHORIZED,
    }
}

async fn healthz() -> &'static str {
    "ok"
}

async fn sweep(state: SharedState) {
    loop {
        tokio::time::sleep(SWEEP_INTERVAL).await;
        let now = Instant::now();
        let mut entries = state.entries.lock().await;
        entries.retain(|_, e| e.expires_at > now);
        let mut rates = state.rates.lock().await;
        rates.retain(|_, (_, start)| now.duration_since(*start) <= RATE_WINDOW);
    }
}

fn router(state: SharedState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/register", post(register))
        .route("/lookup/{code}", get(lookup))
        .route("/register/{code}", delete(unregister))
        .route("/register/{code}/refresh", post(refresh))
        .layer(DefaultBodyLimit::max(BODY_MAX))
        .with_state(state)
}

/// Run the mailbox HTTP server on an already-bound listener (does not return).
pub async fn run(listener: tokio::net::TcpListener) {
    let state: SharedState = Arc::new(Mailbox::default());
    tokio::spawn(sweep(state.clone()));
    let app = router(state);
    let _ = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await;
}

/// Bind `127.0.0.1:0`, spawn the server, return the base URL (`http://127.0.0.1:PORT`).
pub async fn start_local() -> std::io::Result<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(run(listener));
    wait_healthy(port).await?;
    Ok(format!("http://127.0.0.1:{port}"))
}

async fn wait_healthy(port: u16) -> std::io::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/healthz");
    for _ in 0..60 {
        if let Ok(res) = client.get(&url).send().await {
            if res.status().is_success()
                && res
                    .bytes()
                    .await
                    .map(|b| b.as_ref() == b"ok")
                    .unwrap_or(false)
            {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "embedded mailbox did not become healthy",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_app() -> Router {
        router(Arc::new(Mailbox::default()))
    }

    fn localhost() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:12345".parse().unwrap())
    }

    const EID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EID2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    async fn register_code(app: &Router, code: &str, endpoint_id: &str) -> RegisterResponse {
        let body = serde_json::to_vec(&serde_json::json!({
            "code": code,
            "endpoint_id": endpoint_id,
        }))
        .unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .extension(localhost())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn register_then_lookup_roundtrips() {
        let app = test_app();
        let reg = register_code(&app, "123456", EID).await;

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/lookup/123456")
                    .extension(localhost())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: LookupResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.endpoint_id, EID);
        assert!(parsed.relays.is_empty());
        assert!(parsed.ips.is_empty());
        assert!(reg.token.len() > 10);
    }

    #[tokio::test]
    async fn register_stores_dial_hints() {
        let app = test_app();
        let body = serde_json::to_vec(&serde_json::json!({
            "code": "111222",
            "endpoint_id": EID,
            "device_name": format!("  {}\u{0007}  ", "n".repeat(80)),
            "relays": [
                "https://relay.example/",
                "https://use1-1.relay.n0.iroh.link.",
                "",
                "http://insecure.example/",
                "https://127.0.0.1/",
                "https://192.168.0.1/",
                "https://localhost/",
                "https://user:pass@relay.example/"
            ],
            "ips": ["203.0.113.9:4242", "127.0.0.1:9", "100.64.1.8:9", "192.168.1.10:9"],
        }))
        .unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .extension(localhost())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/lookup/111222")
                    .extension(localhost())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: LookupResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            parsed.relays,
            vec![
                "https://relay.example/".to_string(),
                "https://use1-1.relay.n0.iroh.link.".to_string()
            ]
        );
        assert_eq!(parsed.ips, vec!["203.0.113.9:4242".to_string()]);
        let expected_name = "n".repeat(MAX_DISPLAY_NAME);
        assert_eq!(parsed.device_name.as_deref(), Some(expected_name.as_str()));
    }

    #[tokio::test]
    async fn register_twice_same_code_second_is_409() {
        let app = test_app();
        register_code(&app, "123456", EID).await;
        let body = serde_json::to_vec(&serde_json::json!({
            "code": "123456",
            "endpoint_id": EID2,
        }))
        .unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .extension(localhost())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn register_reclaims_expired_slot() {
        let state: SharedState = Arc::new(Mailbox::default());
        {
            let mut entries = state.entries.lock().await;
            entries.insert(
                "121212".into(),
                Entry {
                    endpoint_id: EID.to_string(),
                    device_name: None,
                    relays: vec![],
                    ips: vec![],
                    token: "stale".into(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                },
            );
        }
        let app = router(state);
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/lookup/121212")
                    .extension(localhost())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        register_code(&app, "121212", EID2).await;
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/lookup/121212")
                    .extension(localhost())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: LookupResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.endpoint_id, EID2);
    }

    #[tokio::test]
    async fn lookup_missing_code_is_404() {
        let app = test_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/lookup/000000")
                    .extension(localhost())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn register_oversize_body_is_413() {
        let app = test_app();
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .extension(localhost())
                    .body(Body::from(vec![b'x'; BODY_MAX + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn unregister_without_token_is_401() {
        let app = test_app();
        register_code(&app, "555555", EID).await;
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/register/555555")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unregister_with_token_removes_code() {
        let app = test_app();
        let reg = register_code(&app, "555555", EID).await;

        app.clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/register/555555")
                    .header("authorization", format!("Bearer {}", reg.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/lookup/555555")
                    .extension(localhost())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn normalize_code_trims_whitespace() {
        assert_eq!(normalize_code("  123456  "), "123456");
    }

    #[test]
    fn valid_code_rejects_non_six_digit() {
        assert!(!valid_code("12345"));
        assert!(!valid_code("1234567"));
        assert!(valid_code("123456"));
    }

    #[test]
    fn valid_endpoint_id_is_64_hex() {
        assert!(valid_endpoint_id(EID));
        let mixed = "Ab".repeat(32);
        assert!(valid_endpoint_id(&mixed));
        assert!(!valid_endpoint_id("deadbeef"));
        assert!(!valid_endpoint_id(""));
        assert!(!valid_endpoint_id(&(EID.to_string() + "aa")));
    }

    #[test]
    fn sanitize_relays_accepts_mixed_case_https() {
        let got = sanitize_relays(vec!["Https://use1-1.relay.n0.iroh.link.".into()]);
        assert_eq!(got.len(), 1, "{got:?}");
    }

    #[tokio::test]
    async fn refresh_with_token_extends_and_bad_token_is_401() {
        let app = test_app();
        let reg = register_code(&app, "777888", EID).await;

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register/777888/refresh")
                    .header("authorization", format!("Bearer {}", reg.token))
                    .extension(localhost())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register/777888/refresh")
                    .header("authorization", "Bearer wrong-token")
                    .extension(localhost())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/lookup/777888")
                    .extension(localhost())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn refresh_json_updates_hints_without_dropping_slot() {
        let app = test_app();
        let reg = register_code(&app, "424242", EID).await;
        let body = serde_json::to_vec(&serde_json::json!({
            "relays": ["https://relay.example/"],
            "ips": ["203.0.113.9:4242"],
            "device_name": "Desk",
        }))
        .unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register/424242/refresh")
                    .header("authorization", format!("Bearer {}", reg.token))
                    .header("content-type", "application/json")
                    .extension(localhost())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .extension(localhost())
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "code": "424242",
                            "endpoint_id": EID,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "in-place refresh must not free the code"
        );

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/lookup/424242")
                    .extension(localhost())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let got: LookupResponse = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(got.endpoint_id, EID);
        assert_eq!(got.device_name.as_deref(), Some("Desk"));
        assert_eq!(got.relays, vec!["https://relay.example/".to_string()]);
        assert_eq!(got.ips, vec!["203.0.113.9:4242".to_string()]);
    }

    #[tokio::test]
    async fn register_rejects_short_endpoint_id() {
        let app = test_app();
        let body = serde_json::to_vec(&serde_json::json!({
            "code": "123456",
            "endpoint_id": "deadbeef",
        }))
        .unwrap();
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .extension(localhost())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_listen_addr_defaults_and_rejects_hostnames() {
        let loopback = parse_listen_addr("127.0.0.1", 8787).unwrap();
        assert!(loopback.ip().is_loopback());
        assert_eq!(loopback.port(), 8787);
        let public = parse_listen_addr("0.0.0.0", 8787).unwrap();
        assert!(public.ip().is_unspecified());
        let v6 = parse_listen_addr("::1", 9).unwrap();
        assert!(v6.ip().is_loopback());
        assert!(parse_listen_addr("localhost", 8787).is_err());
        assert!(parse_listen_addr("", 8787).is_err());
        assert!(parse_listen_addr("  ", 8787).is_err());
    }
}
