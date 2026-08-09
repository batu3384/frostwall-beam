//! Persisted user configuration: download directory and device name.
//!
//! Stored as JSON at `<config_dir>/frostwall/config.json` (via `dirs::config_dir()`:
//! e.g. `~/Library/Application Support/frostwall/` on macOS, `%APPDATA%/frostwall/` on Windows).
//! Missing or malformed files degrade gracefully to defaults.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// User-tunable settings. All fields optional: unset means "use defaults".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserConfig {
    pub download_dir: Option<String>,
    pub device_name: Option<String>,
    /// Base URL of the mailbox rendezvous service used for internet (non-LAN)
    /// sessions. When unset, the app uses a built-in default (local sidecar in
    /// dev, or `FROSTWALL_MAILBOX_URL` at compile time for release).
    pub mailbox_url: Option<String>,
}

/// True when a real (non-localhost-only) rendezvous URL is configured.
pub fn remote_mailbox_configured(stored: &Option<String>) -> bool {
    if stored.as_ref().is_some_and(|s| !s.trim().is_empty()) {
        return true;
    }
    option_env!("FROSTWALL_MAILBOX_URL").is_some_and(|u| !u.is_empty())
}

/// Resolve a configured mailbox URL (user override → build-time). No localhost fallback.
pub fn configured_mailbox_url(stored: &Option<String>) -> Option<String> {
    if let Some(url) = stored.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        return Some(url.to_string());
    }
    option_env!("FROSTWALL_MAILBOX_URL")
        .filter(|u| !u.is_empty())
        .map(str::to_string)
}

/// Start the embedded localhost mailbox only when no remote URL is configured.
pub fn should_spawn_local_mailbox(stored: &Option<String>) -> bool {
    !remote_mailbox_configured(stored)
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
    if std::fs::symlink_metadata(path)
        .map(|m| m.is_symlink())
        .unwrap_or(false)
    {
        return UserConfig::default();
    }
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => UserConfig::default(),
    }
}

fn save_at(path: &Path, cfg: &UserConfig) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating config dir {}", parent.display()))?;

    let bytes = serde_json::to_vec_pretty(cfg).context("serializing config")?;
    let tmp = path.with_extension("json.tmp");

    // Never follow a pre-existing temp path (could be an attacker-planted
    // symlink): if it is a symlink, remove it first.
    if std::fs::symlink_metadata(&tmp)
        .map(|m| m.is_symlink())
        .unwrap_or(false)
    {
        let _ = std::fs::remove_file(&tmp);
    }

    // Write + fsync the temp file so a crash cannot leave a torn config.
    use std::fs::OpenOptions;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
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
}
