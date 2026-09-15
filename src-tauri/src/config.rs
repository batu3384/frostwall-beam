//! Persisted user configuration: download directory and device name.
//!
//! Stored as JSON at `<config_dir>/frostwall/config.json` (via `dirs::config_dir()`:
//! e.g. `~/Library/Application Support/frostwall/` on macOS, `%APPDATA%/frostwall/` on Windows).
//! Missing or malformed files degrade gracefully to defaults.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// User-tunable settings. All fields optional: unset means "use defaults".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserConfig {
    pub download_dir: Option<String>,
    pub device_name: Option<String>,
    /// Optional mailbox URL. Remote pairing defaults to a shareable iroh
    /// ticket (or legacy `fwb2-…`); a mailbox only lets joiners type the 6-digit code.
    pub mailbox_url: Option<String>,
}

/// Accept only HTTPS mailbox URLs in release; loopback HTTP in debug.
pub fn mailbox_url_allowed(url: &str) -> bool {
    let url = url.trim();
    if url.is_empty()
        || url.contains('@')
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    if url.len() >= 8 && url.is_char_boundary(8) && url[..8].eq_ignore_ascii_case("https://") {
        let host = url[8..].split('/').next().unwrap_or("");
        return !host.is_empty();
    }
    #[cfg(debug_assertions)]
    {
        // Exact loopback only — `http://127.0.0.1.evil.com` is not local.
        let lower = url.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("http://127.0.0.1") {
            return rest.is_empty() || rest.starts_with('/') || rest.starts_with(':');
        }
        if let Some(rest) = lower.strip_prefix("http://localhost") {
            return rest.is_empty() || rest.starts_with('/') || rest.starts_with(':');
        }
    }
    false
}

fn sanitize_mailbox_url(url: Option<&str>) -> Option<String> {
    let t = url?.trim();
    if t.is_empty() || !mailbox_url_allowed(t) {
        return None;
    }
    Some(t.trim_end_matches('/').to_string())
}

/// True when a mailbox URL is set (Settings or `FROSTWALL_MAILBOX_URL`).
/// That only enables 6-digit Remote lookup — it is not a relay.
pub fn remote_mailbox_configured(stored: &Option<String>) -> bool {
    configured_mailbox_url(stored).is_some()
}

/// Resolve a configured mailbox URL (user override → build-time).
/// Rejects `http://` (except debug loopback) so a planted config cannot
/// bypass [`mailbox_url_allowed`].
pub fn configured_mailbox_url(stored: &Option<String>) -> Option<String> {
    if let Some(url) = sanitize_mailbox_url(stored.as_deref()) {
        return Some(url);
    }
    sanitize_mailbox_url(option_env!("FROSTWALL_MAILBOX_URL"))
}

/// Canonical config file: `<config_dir>/frostwall/config.json`.
fn config_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("frostwall").join("config.json"))
}

/// Load config from the canonical location, or default on any failure.
pub fn load() -> UserConfig {
    match config_path() {
        Some(p) => load_at(&p),
        None => UserConfig::default(),
    }
}

/// Persist config to the canonical location (creates the parent dir).
pub fn save(cfg: &UserConfig) -> Result<()> {
    let p = config_path().context("could not resolve config directory")?;
    save_at(&p, cfg)
}

fn load_at(path: &Path) -> UserConfig {
    // Refuse to read a config file that is a symlink (planted-symlink defense).
    if crate::transfer::is_link_like_path(path) {
        return UserConfig::default();
    }
    match std::fs::read(path) {
        Ok(bytes) => {
            let mut cfg: UserConfig = serde_json::from_slice(&bytes).unwrap_or_default();
            cfg.mailbox_url = sanitize_mailbox_url(cfg.mailbox_url.as_deref());
            cfg
        }
        Err(_) => UserConfig::default(),
    }
}

fn save_at(path: &Path, cfg: &UserConfig) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if crate::transfer::path_has_symlink_component(path)
        || crate::transfer::path_has_symlink_component(parent)
    {
        anyhow::bail!("refusing to write through a symlink");
    }
    crate::transfer::mkdir_abs_nofollow(parent)
        .with_context(|| format!("creating config dir {}", parent.display()))?;

    let mut persist = cfg.clone();
    persist.mailbox_url = sanitize_mailbox_url(persist.mailbox_url.as_deref());
    let bytes = serde_json::to_vec_pretty(&persist).context("serializing config")?;
    let tmp = path.with_extension("json.tmp");
    // Crash leftover or planted symlink: truncate-open would follow.
    // Remove then exclusive-create (O_EXCL does not follow a symlink).
    let _ = std::fs::remove_file(&tmp);
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("writing config to {}", tmp.display()))?;
    f.write_all(&bytes)?;
    f.flush()?;
    let _ = f.sync_all();
    drop(f);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        // fsync the parent directory so the rename is durable across a crash.
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    std::fs::rename(&tmp, path)
        .with_context(|| format!("installing config at {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_mailbox_url_prefers_stored() {
        let stored = Some("https://custom.example.com".to_string());
        assert_eq!(
            configured_mailbox_url(&stored).as_deref(),
            Some("https://custom.example.com")
        );
    }

    #[test]
    fn configured_mailbox_url_none_when_unset() {
        assert!(configured_mailbox_url(&None).is_none());
    }

    #[test]
    fn remote_mailbox_configured_when_stored() {
        assert!(remote_mailbox_configured(&Some("https://x.example".into())));
        assert!(!remote_mailbox_configured(&None));
        assert!(!remote_mailbox_configured(&Some("http://evil.example".into())));
        assert!(!remote_mailbox_configured(&Some("https://user@host".into())));
    }

    #[test]
    fn mailbox_url_allowed_rejects_empty_host_and_userinfo() {
        assert!(mailbox_url_allowed("https://mailbox.example.com"));
        assert!(mailbox_url_allowed("https://mailbox.example.com/"));
        assert!(mailbox_url_allowed("HTTPS://mailbox.example.com"));
        assert!(mailbox_url_allowed("Https://mailbox.example.com/path"));
        assert!(!mailbox_url_allowed("https://"));
        assert!(!mailbox_url_allowed("https://user:pass@mailbox.example.com"));
        assert!(!mailbox_url_allowed("http://example.com"));
        #[cfg(debug_assertions)]
        {
            assert!(mailbox_url_allowed("http://127.0.0.1:8787"));
            assert!(mailbox_url_allowed("HTTP://127.0.0.1:8787"));
            assert!(mailbox_url_allowed("http://localhost/"));
            assert!(mailbox_url_allowed("HTTP://localhost/"));
            assert!(!mailbox_url_allowed("http://127.0.0.1.evil.com"));
            assert!(!mailbox_url_allowed("http://localhost.evil.com"));
        }
    }

    #[test]
    fn load_drops_planted_http_mailbox_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");
        std::fs::write(
            &path,
            br#"{"mailbox_url":"http://evil.example/hook"}"#,
        )
        .expect("write");
        let cfg = load_at(&path);
        assert!(cfg.mailbox_url.is_none());
        assert!(configured_mailbox_url(&Some("http://evil.example".into())).is_none());
    }

    #[test]
    fn save_strips_planted_http_mailbox_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");
        let cfg = UserConfig {
            download_dir: None,
            device_name: None,
            mailbox_url: Some("http://evil.example/hook".to_string()),
        };
        save_at(&path, &cfg).expect("save");
        let raw = std::fs::read_to_string(&path).expect("read");
        assert!(
            !raw.contains("evil.example"),
            "disk must not keep a planted http mailbox URL: {raw}"
        );
        assert!(load_at(&path).mailbox_url.is_none());
    }

    #[test]
    fn load_missing_returns_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing.json");
        let cfg = load_at(&path);
        assert_eq!(cfg, UserConfig::default());
        assert!(cfg.download_dir.is_none());
        assert!(cfg.device_name.is_none());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");
        let cfg = UserConfig {
            download_dir: Some("/some/where".to_string()),
            device_name: Some("laptop".to_string()),
            mailbox_url: Some("https://mailbox.example.com".to_string()),
        };
        save_at(&path, &cfg).expect("save");
        let loaded = load_at(&path);
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn save_creates_parent_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Parent does not exist yet.
        let path = dir.path().join("nested").join("deep").join("config.json");
        assert!(!path.parent().unwrap().exists());
        let cfg = UserConfig {
            download_dir: Some("/x".to_string()),
            device_name: None,
            mailbox_url: None,
        };
        save_at(&path, &cfg).expect("save");
        assert!(path.exists(), "config file should exist after save");
        assert!(path.parent().unwrap().exists(), "parent dir created");
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_symlinked_config() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real.json");
        let cfg = UserConfig {
            download_dir: Some("/attacker".to_string()),
            device_name: None,
            mailbox_url: None,
        };
        save_at(&real, &cfg).expect("save real");
        let link = dir.path().join("config.json");
        symlink(&real, &link).expect("symlink");
        // A symlinked config must be ignored (default), not followed.
        assert_eq!(load_at(&link), UserConfig::default());
    }

    #[cfg(unix)]
    #[test]
    fn save_refuses_symlinked_parent() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("realdir");
        std::fs::create_dir(&real).expect("realdir");
        let link = dir.path().join("frostwall");
        symlink(&real, &link).expect("symlink parent");
        let path = link.join("config.json");
        let err = save_at(&path, &UserConfig::default()).expect_err("symlink parent");
        assert!(
            err.to_string().contains("symlink"),
            "got {err:#}"
        );
        assert!(!path.exists(), "must not write through the config parent symlink");
    }

    #[cfg(unix)]
    #[test]
    fn save_does_not_follow_tmp_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.json");
        let secret = dir.path().join("secret.json");
        std::fs::write(&secret, b"KEEP").expect("secret");
        let tmp = path.with_extension("json.tmp");
        symlink(&secret, &tmp).expect("plant tmp symlink");
        let cfg = UserConfig {
            download_dir: None,
            device_name: Some("ok".into()),
            mailbox_url: None,
        };
        save_at(&path, &cfg).expect("save");
        assert_eq!(std::fs::read(&secret).expect("secret intact"), b"KEEP");
        assert_eq!(load_at(&path).device_name.as_deref(), Some("ok"));
        assert!(!tmp.exists());
    }
}
