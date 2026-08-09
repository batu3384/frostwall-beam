//! Embedded localhost mailbox — runs inside the app on a free port.

use std::sync::Mutex;

static EMBEDDED_URL: Mutex<Option<String>> = Mutex::new(None);

/// Start an in-process mailbox on `127.0.0.1` with a free port. Idempotent.
pub async fn ensure_embedded() -> Option<String> {
    if let Ok(guard) = EMBEDDED_URL.lock() {
        if let Some(url) = guard.as_ref() {
            return Some(url.clone());
        }
    }

    let url = frostwall_mailbox::start_local().await.ok()?;
    if let Ok(mut guard) = EMBEDDED_URL.lock() {
        *guard = Some(url.clone());
    }
    Some(url)
}

pub fn embedded_url() -> Option<String> {
    EMBEDDED_URL.lock().ok().and_then(|g| g.clone())
}
