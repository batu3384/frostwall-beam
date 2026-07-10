//! Frostwall Beam mailbox — a tiny, stateless-by-design rendezvous service.
//!
//! Maps a short pairing code to an iroh `EndpointId` so two peers on
//! different networks can find each other. It never sees file contents or
//! encryption keys: the SPAKE2 handshake and all file data still flow
//! directly (or via iroh's own relay) between the two peers, end-to-end
//! encrypted. This service only answers "which EndpointId did code X
//! register?" and forgets entries after a short TTL.
//!
//! Run with `PORT=8787 cargo run --release -p frostwall-mailbox`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

/// How long a registered code stays valid before it's forgotten.
const TTL: Duration = Duration::from_secs(10 * 60);
/// How often the background sweeper checks for expired entries.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Per-IP register attempts allowed per window.
const REGISTER_RATE_MAX: u32 = 30;
/// Per-IP lookup attempts allowed per window.
const LOOKUP_RATE_MAX: u32 = 120;
const RATE_WINDOW: Duration = Duration::from_secs(60);

struct Entry {
    endpoint_id: String,
    device_name: Option<String>,
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
}

#[derive(Serialize, Deserialize)]
struct RegisterResponse {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct LookupResponse {
    endpoint_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
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
    !t.is_empty() && t.len() <= 256
}

async fn allow_rate(
    state: &Mailbox,
    key: &str,
    max: u32,
) -> bool {
    let mut rates = state.rates.lock().await;
    let now = Instant::now();
    let entry = rates
        .entry(key.to_string())
        .or_insert((0, now));
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
    if !allow_rate(&state, &format!("reg:{}", client_rate_key(addr)), REGISTER_RATE_MAX).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let code = normalize_code(&req.code);
    if !valid_code(&code) || !valid_endpoint_id(&req.endpoint_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut entries = state.entries.lock().await;
    if entries.contains_key(&code) {
        return Err(StatusCode::CONFLICT);
    }
    let token = Uuid::new_v4().to_string();
    entries.insert(
        code,
        Entry {
            endpoint_id: req.endpoint_id.trim().to_string(),
            device_name: req
                .device_name
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
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
    if !allow_rate(&state, &format!("lkp:{}", client_rate_key(addr)), LOOKUP_RATE_MAX).await {
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
        })),
        _ => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "no peer registered for this code (expired or never registered)"
                    .to_string(),
            }),
        )),
    }
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
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let state: SharedState = Arc::new(Mailbox::default());
    tokio::spawn(sweep(state.clone()));

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/register", post(register))
        .route("/lookup/{code}", get(lookup))
        .route("/register/{code}", delete(unregister))
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8787);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!("frostwall-mailbox listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind mailbox listener");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("mailbox server error");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn app() -> Router {
        let state: SharedState = Arc::new(Mailbox::default());
        Router::new()
            .route("/register", post(register))
            .route("/lookup/{code}", get(lookup))
            .route("/register/{code}", delete(unregister))
            .with_state(state)
    }

    fn localhost() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:12345".parse().unwrap())
    }

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
        let app = app();
        let reg = register_code(&app, "123456", "deadbeef").await;

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
        assert_eq!(parsed.endpoint_id, "deadbeef");
        assert!(reg.token.len() > 10);
    }

    #[tokio::test]
    async fn register_twice_same_code_second_is_409() {
        let app = app();
        register_code(&app, "123456", "a").await;
        let body = serde_json::to_vec(&serde_json::json!({
            "code": "123456",
            "endpoint_id": "b",
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
    async fn lookup_missing_code_is_404() {
        let app = app();
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
    async fn unregister_without_token_is_401() {
        let app = app();
        register_code(&app, "555555", "abc").await;
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
        let app = app();
        let reg = register_code(&app, "555555", "abc").await;

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
}
