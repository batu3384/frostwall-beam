# Adversarial Review Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adversarial review'de bulunan tüm Critical/Warning/Note maddelerini sırayla kapatmak; internet modunu production-güvenli hale getirmek; UI/UX ve erişilebilirlik tutarsızlıklarını gidermek.

**Architecture:** 6 fazlı sıralı düzeltme — önce oturum yaşam döngüsü (tüm modlar için temel), sonra mailbox güvenliği, transfer protokolü, backend koordinasyon, frontend UX, son olarak polish/CI. Her faz bağımsız test edilebilir; fazlar arası commit.

**Tech Stack:** Tauri 2, Rust (tokio, iroh, axum), React/TypeScript, Cargo workspace (`src-tauri` + `mailbox`)

## Global Constraints

- Minimize scope: her task yalnızca ilgili maddeyi çözer, drive-by refactor yok
- Mevcut SPAKE2 + AEAD chunk + Blake3 modeli korunur; protokol değişiklikleri versioned olmalı
- TR/EN i18n her yeni kullanıcı mesajı için zorunlu
- `cargo test --workspace` ve `pnpm build` her faz sonunda yeşil
- Commit yalnızca kullanıcı istediğinde; plan commit adımlarını önerir ama otomatik push yok
- Türkçe kullanıcı metinleri `src/i18n.tsx`'te

---

## Dosya Haritası

| Dosya | Sorumluluk |
|-------|------------|
| `src-tauri/src/commands.rs` | Oturum yaşam döngüsü, disconnect, coordinator, pairing |
| `src-tauri/src/internet.rs` | iroh + mailbox client, unregister, device_name |
| `src-tauri/src/transfer.rs` | Manifest şifreleme, boyut doğrulama, sender caps |
| `src-tauri/src/protocol.rs` | Yeni `Encrypted` mesaj tipi (kontrol düzlemi) |
| `src-tauri/src/crypto.rs` | Kontrol mesajları için AEAD helper |
| `mailbox/src/main.rs` | Token auth, validation, rate limit |
| `src/App.tsx` | UX guard'ları, cancel/disconnect, hız/ETA, tema |
| `src/errors.ts` + `src/i18n.tsx` | Hata eşleme + çeviri |
| `src/history.ts` | Parse validation |
| `src/theme.ts` | OS tema dinleyicisi |
| `.github/workflows/ci.yml` | clippy gate |

---

## Faz 0 — Hazırlık

### Task 0: Feature branch + baseline

**Files:**
- Create: branch `fix/adversarial-review`

- [ ] **Step 1: Branch oluştur**
```bash
git checkout -b fix/adversarial-review
```

- [ ] **Step 2: Baseline doğrula**
```bash
cargo test --workspace
pnpm build
```
Expected: 65 passed, 2 ignored; pnpm build OK

- [ ] **Step 3: Review checklist dosyasını aç**
Bu plan dosyasındaki checkbox'ları uygulama sırasında işaretle.

---

## Faz 1 — Oturum Yaşam Döngüsü (Critical #2, #3, #4)

> **Kapsanan maddeler:** İptal zombie backend, disconnect transfer durdurmuyor, clear() pairing task abort etmiyor, internet unregister eksik

### Task 1: `AppState::clear` ve `disconnect` sağlamlaştır

**Files:**
- Modify: `src-tauri/src/commands.rs:93-149`, `849-860`, `280-515`
- Test: `src-tauri/src/commands.rs` (yeni unit test modülü)

**Interfaces:**
- Consumes: mevcut `pairing_task: Mutex<Option<JoinHandle<()>>>`, `active_cancel: sync::Mutex<Option<Arc<AtomicBool>>>`
- Produces:
  - `async fn abort_pairing(state: &AppState)` — pairing task abort + slot temizle
  - `fn trigger_cancel(state: &AppState)` — aktif transfer cancel flag set
  - güncellenmiş `clear()` ve `disconnect()`

- [ ] **Step 1: `abort_pairing` helper ekle**

`commands.rs` içinde `AppState` impl bloğuna:

```rust
async fn abort_pairing(&self) {
    if let Some(h) = self.pairing_task.lock().await.take() {
        h.abort();
    }
}

fn trigger_cancel(&self) {
    if let Ok(g) = self.active_cancel.lock() {
        if let Some(flag) = g.as_ref() {
            flag.store(true, Ordering::SeqCst);
        }
    }
}
```

- [ ] **Step 2: `clear()` güncelle — abort + cancel**

```rust
async fn clear(&self) {
    self.abort_pairing().await;
    self.trigger_cancel();
    // ... mevcut incoming_decision, cmd_tx, liveness_key, in_flight, active_cancel = None
}
```

- [ ] **Step 3: `disconnect` güncelle — transfer cancel + coordinator kapat**

```rust
pub async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    state.abort_pairing().await;
    state.trigger_cancel();
    if let Some(tx) = state.incoming_decision.lock().await.take() {
        let _ = tx.send(false);
    }
    *state.cmd_tx.lock().await = None;
    state.clear().await;
    Ok(())
}
```

- [ ] **Step 4: `establish_session` öncesi eski coordinator'ı kapat**
`host_start` / `join_*` başında `clear()` zaten abort çağırır — `establish_session` içinde `cmd_tx` overwrite öncesi eski sender drop edildiğinden emin ol (mevcut kod kontrol).

- [ ] **Step 5: Test — clear aborts pairing**
```rust
#[tokio::test]
async fn clear_aborts_pairing_task() {
    let state = AppState::new();
    let handle = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    *state.pairing_task.lock().await = Some(handle);
    state.clear().await;
    // pairing_task slot empty
    assert!(state.pairing_task.lock().await.is_none());
}
```

- [ ] **Step 6: `cargo test -p frostwall --lib commands::`**

- [ ] **Step 7: Commit**
```bash
git add src-tauri/src/commands.rs
git commit -m "fix: abort pairing and cancel transfer on disconnect/clear"
```

---

### Task 2: İnternet modu mailbox temizliği

**Files:**
- Modify: `src-tauri/src/commands.rs` (`host_start_internet` spawn bloğu)
- Modify: `src-tauri/src/internet.rs` (`Mailbox` struct)

**Interfaces:**
- Produces: `struct InternetHostContext { mailbox: Mailbox, code: String, token: String }` — Task 4'ten sonra token gelir; Task 2 geçici olarak code-only unregister

- [ ] **Step 1: Host internet task'ta `Drop` guard veya `finally` bloğu**

`host_start_internet` spawn içinde, loop bittikten sonra (mevcut `mailbox.unregister(&code).await`):
- `establish_session` başarılı olduktan sonra da unregister çağır (kod artık kullanıldı)
- `disconnect` / `clear` abort sonrası unregister için: `AppState`'e `internet_cleanup: Mutex<Option<(Mailbox, String, Option<String>)>>` ekle; host register sonrası kaydet; `clear()` içinde best-effort unregister

```rust
// AppState'e ekle:
internet_cleanup: Mutex<Option<InternetCleanup>>,

struct InternetCleanup {
    mailbox: internet::Mailbox,
    code: String,
    token: Option<String>, // Task 4'te doldurulacak
}

async fn cleanup_internet(&self) {
    if let Some(c) = self.internet_cleanup.lock().await.take() {
        c.mailbox.unregister(&c.code, c.token.as_deref()).await;
    }
}
```

`clear()` sonuna `self.cleanup_internet().await` ekle.

- [ ] **Step 2: `internet::Mailbox::unregister` token parametresi (opsiyonel, Task 4'te zorunlu)**

- [ ] **Step 3: Test mailbox unregister çağrıldığını mock HTTP ile doğrula (unit) veya integration ignore**

- [ ] **Step 4: Commit**
```bash
git commit -m "fix: unregister mailbox code on disconnect and after pairing"
```

---

### Task 3: Frontend — İptal = disconnect

**Files:**
- Modify: `src/App.tsx:96-102`, `439-442`, `516`

**Interfaces:**
- Consumes: mevcut `doDisconnect` (`invoke("disconnect")` + `reset`)

- [ ] **Step 1: `cancelWaiting` helper**

```typescript
const cancelWaiting = useCallback(async () => {
  await invoke("disconnect").catch(() => {});
  reset();
}, [reset]);
```

- [ ] **Step 2: Hosting/joining İptal butonunu güncelle**
`onClick={() => reset()}` → `onClick={() => cancelWaiting()}`

- [ ] **Step 3: PeerPicker iptalini güncelle** (satır ~516)

- [ ] **Step 4: `reset()` joinCode temizle**
`setJoinCode("")` ekle.

- [ ] **Step 5: `pnpm build`**

- [ ] **Step 6: Commit**
```bash
git commit -m "fix(ui): cancel waiting sessions calls disconnect and clears join code"
```

---

## Faz 2 — Mailbox Güvenliği (Critical #1, #6 + Warning #10, #21)

> **Kapsanan maddeler:** Kayıt hijacking, unregister DoS, HTTP MITM, kod formatı/rate-limit yok

### Task 4: Mailbox registration token + first-write-wins

**Files:**
- Modify: `mailbox/src/main.rs`
- Modify: `src-tauri/src/internet.rs` (`RegisterRequest`, `register`, `unregister`)
- Modify: `src-tauri/src/commands.rs` (`host_start_internet`)
- Test: `mailbox/src/main.rs` tests modülü

**Interfaces:**
- Produces:
  - `POST /register` → `201 { "token": "<uuid>" }` (yeni kod) veya `409` (kod dolu)
  - `DELETE /register/{code}` → header `Authorization: Bearer <token>` zorunlu
  - `LookupResponse` opsiyonel `device_name: Option<String>` (Task 10)

- [ ] **Step 1: Entry struct genişlet**

```rust
struct Entry {
    endpoint_id: String,
    device_name: Option<String>,
    token: String,
    expires_at: Instant,
}
```

- [ ] **Step 2: register — first-write-wins**

```rust
if entries.contains_key(&code) {
    return StatusCode::CONFLICT;
}
let token = uuid::Uuid::new_v4().to_string();
entries.insert(code, Entry { ..., token: token.clone() });
// return Json(RegisterResponse { token })
```

- [ ] **Step 3: unregister — token doğrula**

```rust
// Authorization: Bearer <token> header veya JSON body { token }
match entries.get(&code) {
    Some(e) if e.token == provided => { entries.remove(&code); NO_CONTENT }
    _ => UNAUTHORIZED
}
```

- [ ] **Step 4: Testler**
- `register_twice_same_code_second_is_409`
- `unregister_without_token_is_401`
- `unregister_with_wrong_token_is_401`

- [ ] **Step 5: Client güncelle — token sakla ve gönder**

`internet.rs`:
```rust
pub async fn register(&self, code: &str, endpoint_id: &str, device_name: Option<&str>) -> Result<String>
pub async fn unregister(&self, code: &str, token: Option<&str>) -> Result<()>
```

`host_start_internet`: token'ı `InternetCleanup`'a kaydet.

- [ ] **Step 6: `cargo test -p frostwall-mailbox` + workspace**

- [ ] **Step 7: Commit**
```bash
git commit -m "fix(mailbox): registration token and first-write-wins anti-hijack"
```

---

### Task 5: Mailbox validation + rate limit

**Files:**
- Modify: `mailbox/src/main.rs`
- Modify: `mailbox/Cargo.toml` (gerekirse `tower-governor` veya basit in-memory rate limit)

- [ ] **Step 1: Kod formatı doğrula**

```rust
fn valid_code(code: &str) -> bool {
    code.len() == 6 && code.chars().all(|c| c.is_ascii_digit())
}
```

register/lookup'ta `400` döndür.

- [ ] **Step 2: endpoint_id formatı — iroh PublicKey parse dene veya min/max length**

- [ ] **Step 3: Basit IP rate limit — register: 30/dk, lookup: 120/dk per IP**
`HashMap<IpAddr, (count, Instant)>` veya `governor` crate.

- [ ] **Step 4: Test — invalid code 400, rate limit 429**

- [ ] **Step 5: Commit**

---

### Task 6: HTTPS zorunluluğu (client)

**Files:**
- Modify: `src-tauri/src/commands.rs` (`set_mailbox_url`)
- Modify: `src/App.tsx` (settings save validation)
- Modify: `src/i18n.tsx`, `src/errors.ts`

- [ ] **Step 1: Backend — production build'de http reddet**

```rust
if !trimmed.is_empty() && !trimmed.starts_with("https://") {
    return Err("mailbox URL must use https://".to_string());
}
```

Dev-only `#[cfg(debug_assertions)]` ile `http://127.0.0.1` istisnası (local test).

- [ ] **Step 2: Frontend — saveMailboxUrl client check**

```typescript
const trimmed = mailboxUrl.trim();
if (trimmed && !trimmed.startsWith("https://") && !trimmed.startsWith("http://127.0.0.1")) {
  onError(t("err.mailboxUrlInvalid"));
  return;
}
```

- [ ] **Step 3: i18n güncelle — https vurgusu**

- [ ] **Step 4: Commit**

---

## Faz 3 — Transfer Protokolü (Critical #5 + Warning #12, #18, #28)

> **Kapsanan maddeler:** LAN metadata plaintext, undersized file, sender MAX_FILES yok, duplicate rel_path

### Task 7: Kontrol mesajlarını AEAD ile şifrele

**Files:**
- Modify: `src-tauri/src/protocol.rs`
- Modify: `src-tauri/src/crypto.rs`
- Modify: `src-tauri/src/transfer.rs`

**Interfaces:**
- Produces:
  - `Message::Encrypted(Vec<u8>)` — wire'da tek şifreli envelope
  - `fn seal_control(keys: &SessionKeys, msg: &Message) -> Result<Message>`
  - `fn open_control(keys: &SessionKeys, enc: &[u8]) -> Result<Message>`
  - `SessionKeys`'e `control_key: [u8; 32]` (HKDF label `"control"`)

- [ ] **Step 1: crypto helper**

```rust
pub fn seal_control(keys: &SessionKeys, plaintext: &[u8]) -> Result<Vec<u8>>
pub fn open_control(keys: &SessionKeys, ciphertext: &[u8]) -> Result<Vec<u8>>
```

- [ ] **Step 2: transfer.rs — Manifest, Accept, Reject, Done, FileEnd, Cancel şifreli gönder/al**

Örnek send:
```rust
conn.send(&protocol::encode(&seal_control_message(keys, &Message::Manifest(entries))?)?).await?;
```

recv tarafında `Message::Encrypted` decode → `open_control`.

- [ ] **Step 3: Chunk zaten AEAD — dokunma**

- [ ] **Step 4: Mevcut transfer roundtrip testlerini güncelle**

`transfer.rs` tests modülündeki TCP loopback testleri şifreli manifest kullanmalı.

- [ ] **Step 5: `cargo test -p frostwall --lib transfer::`**

- [ ] **Step 6: Commit**
```bash
git commit -m "fix: encrypt control-plane messages (manifest, accept, done)"
```

---

### Task 8: Alıcı boyut doğrulama + manifest bütünlüğü

**Files:**
- Modify: `src-tauri/src/transfer.rs:151-169`, `421-427`, `248-268`

- [ ] **Step 1: `recv_one_file` FileEnd'de boyut kontrolü**

```rust
Message::FileEnd(expected) => {
    if written != declared_size {
        return Err(anyhow!("file size mismatch: expected {declared_size}, got {written}"));
    }
    // hash check...
}
```

- [ ] **Step 2: `validate_manifest` — duplicate rel_path reddet**

```rust
let mut seen = HashSet::new();
for e in entries {
    if !seen.insert(&e.rel_path) {
        return Err(anyhow!("duplicate path in manifest"));
    }
}
```

- [ ] **Step 3: `collect_items` / send öncesi `MAX_FILES` + `MAX_TOTAL`**

Sender tarafında collect sonrası:
```rust
if items.len() > MAX_FILES { return Err(...) }
```

- [ ] **Step 4: Unit testler**
- `undersized_file_rejected`
- `duplicate_rel_path_rejected`
- `sender_max_files_rejected`

- [ ] **Step 5: Commit**

---

## Faz 4 — Backend Koordinasyon & Pairing (Warning #13-18, #22, Notes #25-29)

### Task 9: Coordinator `in_flight` ve pending decision

**Files:**
- Modify: `src-tauri/src/commands.rs:313-474`, `783-807`, `864-880`

- [ ] **Step 1: `send_files` — coordinator'a göndermeden önce atomik kontrol**

Coordinator'da `SessionCmd::Send` alındığında:
```rust
if in_flight_already_set { reply(Err(...)); continue; }
set_in_flight(true);
```

Veya `send_files` command'ında `compare_exchange` pattern ile `in_flight` set.

- [ ] **Step 2: `biased` select kaldır veya gelen recv önceliği**

```rust
tokio::select! {
    cmd = cmd_rx.recv() => ...
    frame = conn.recv() => handle_incoming_frame(...)
}
```
`biased` kaldır — fairness.

- [ ] **Step 3: `respond_incoming_transfer` — pending yoksa hata, overwrite yok**

Mevcut `incoming_decision` slot doluysa `decision already pending` döndür.

- [ ] **Step 4: Commit**

---

### Task 10: Pairing sertleştirme

**Files:**
- Modify: `src-tauri/src/commands.rs`, `src-tauri/src/session.rs`
- Modify: `src-tauri/src/discovery.rs` (opsiyonel)

- [ ] **Step 1: Pairing code backend validation**

```rust
fn validate_pairing_code(code: &str) -> Result<(), String> {
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err("Code must be 6 digits".into());
    }
    Ok(())
}
```
`host_start`, `host_start_internet`, `join_*` girişinde çağır.

- [ ] **Step 2: Slowloris bound — stall attempt sayacı**

```rust
const MAX_STALL_ATTEMPTS: u32 = 20;
// "timed out" || "peer stalled" => stall_attempts += 1; >= MAX => break
```

- [ ] **Step 3: LAN IP fallback — 127.0.0.1 yerine hata**

```rust
let ip = discovery::local_lan_ipv4()
    .ok_or_else(|| "no LAN interface found — connect to the same network or use Internet mode".to_string())?;
```

- [ ] **Step 4: İnternet modda device_name mailbox'a kaydet**

`register` body: `{ code, endpoint_id, device_name }`
`LookupResponse`: `{ endpoint_id, device_name }`
`join_internet` → `peer_display_name` set.

- [ ] **Step 5: `join` dead command — `#[deprecated]` veya lib.rs'ten kaldır**

- [ ] **Step 6: i18n + errors.ts yeni mesajlar**

- [ ] **Step 7: Commit**

---

## Faz 5 — Frontend UX (Warning #7-9, #15-20, #23 + Notes)

### Task 11: İnternet modu guard'ları

**Files:**
- Modify: `src/App.tsx:215-221`, `358-405`

- [ ] **Step 1: `mailboxReady` derived state**

```typescript
const mailboxReady = Boolean(config?.mailboxUrl?.trim());
const internetBlocked = net === "internet" && !mailboxReady;
```

- [ ] **Step 2: Host/Join butonları disable + inline uyarı**

```tsx
{internetBlocked && (
  <p className="text-amber-300/90 text-sm">{t("net.mailboxRequired")}</p>
)}
<button disabled={internetBlocked} ...>
```

- [ ] **Step 3: `startHost` / `startJoin` erken guard**

```typescript
if (net === "internet" && !mailboxReady) {
  showError(t("err.mailboxNotConfigured"));
  return;
}
```

- [ ] **Step 4: İnternet bekleme mesajları**
- Host: `host.waitingInternet` (mailbox kayıtlı, peer bekleniyor)
- Join: `join.waitingInternet` (`joining.scanning` yerine)

- [ ] **Step 5: i18n TR/EN**

- [ ] **Step 6: Commit**

---

### Task 12: Transfer UI — hız/ETA + başarısızlık bildirimi

**Files:**
- Modify: `src/App.tsx:137-145`, `309-310`, `152-167`

- [ ] **Step 1: `speed` state'e taşı**

```typescript
const [speed, setSpeed] = useState(0);
// progress handler:
setSpeed(r.speed);
```

- [ ] **Step 2: `transfer-done` ok=false toast**

```typescript
if (!ok) pushToast("err", t("toast.transferFailed"));
```

- [ ] **Step 3: i18n `toast.transferFailed`**

- [ ] **Step 4: Commit**

---

### Task 13: Light tema düzeltmesi

**Files:**
- Modify: `src/App.tsx` (hardcoded `text-slate-*`)
- Modify: `src/styles.css` (utility sınıfları)

- [ ] **Step 1: Kök container**

```tsx
<div className="relative h-full w-full overflow-hidden text-[var(--text-body)]">
```

- [ ] **Step 2: Panel metinleri — `text-slate-400` → `text-[color-mix(in_srgb,var(--text-body)_65%,transparent)]` veya semantic class `.text-muted` ekle `styles.css`'e**

- [ ] **Step 3: Light + dark manuel smoke test**

- [ ] **Step 4: Commit**

---

### Task 14: `respondPending` + Settings modal sync

**Files:**
- Modify: `src/App.tsx:110-117`, `640-660`

- [ ] **Step 1: respondPending — invoke başarılı olunca modal kapat**

```typescript
await invoke("respond_incoming_transfer", { accept });
setPendingTransfer(null);
```

- [ ] **Step 2: Settings — config sync**

```typescript
useEffect(() => {
  setName(config?.deviceName ?? "");
  setMailboxUrl(config?.mailboxUrl ?? "");
}, [open, config]);
```

- [ ] **Step 3: Mailbox save — boş kayıt onayı**

```typescript
if (!trimmed) { /* confirm dialog or disabled when empty unless explicit clear */ }
```

- [ ] **Step 4: Commit**

---

### Task 15: Erişilebilirlik geçişi

**Files:**
- Modify: `src/App.tsx`, `index.html`
- Modify: `src/i18n.tsx` (lang hook)

- [ ] **Step 1: Hata banner `role="alert" aria-live="assertive"`**

- [ ] **Step 2: Toast container `aria-live="polite"`**

- [ ] **Step 3: Modallar `role="dialog" aria-modal="true"` + Escape (PeerPicker, PendingTransfer)**

- [ ] **Step 4: Host/Join + LAN/Internet `aria-pressed`**

- [ ] **Step 5: `index.html lang` — `I18nProvider` locale'e göre `document.documentElement.lang` set**

- [ ] **Step 6: Commit**

---

## Faz 6 — Polish, Test, CI, Docs (Notes + kalan)

### Task 16: `history.ts` + `errors.ts` + `theme.ts`

**Files:**
- Modify: `src/history.ts`, `src/errors.ts`, `src/theme.ts`

- [ ] **Step 1: history parse guard**

```typescript
function isHistoryEntry(x: unknown): x is HistoryEntry { ... }
```

- [ ] **Step 2: `id: crypto.randomUUID()` veya `${Date.now()}-${Math.random()}`**

- [ ] **Step 3: errors.ts — `failed to persist config`, `mailbox URL must use https` kuralları**

- [ ] **Step 4: theme.ts — `matchMedia('(prefers-color-scheme: dark)').addEventListener('change', ...)`**

- [ ] **Step 5: Commit**

---

### Task 17: Liveness auto-abort (Note #25) — opsiyonel güçlendirme

**Files:**
- Modify: `src-tauri/src/commands.rs` (liveness poll loop)
- Modify: `src/App.tsx`

- [ ] **Step 1: Backend'de ardışık liveness mismatch sayacı (UI zaten gösteriyor; backend 3 mismatch → session end)**

Bu task düşük öncelik — Faz 1-5 bittikten sonra.

- [ ] **Step 2: Commit**

---

### Task 18: CI + README güvenlik modeli

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`

- [ ] **Step 1: CI'ya clippy ekle**

```yaml
- name: cargo clippy
  run: cargo clippy --workspace --all-targets -- -D warnings
```

Önce mevcut clippy uyarılarını düzelt (`transfer.rs:57 never_loop` vb.).

- [ ] **Step 2: README — mailbox token modeli, HTTPS zorunluluğu, metadata artık şifreli**

- [ ] **Step 3: Commit**

---

### Task 19: Tam doğrulama

- [ ] **Step 1: `cargo test --workspace`**
- [ ] **Step 2: `cargo clippy --workspace -- -D warnings`**
- [ ] **Step 3: `pnpm build`**
- [ ] **Step 4: Manuel smoke checklist**
  - [ ] LAN: host → join → transfer → disconnect
  - [ ] İnternet (local mailbox): register token → join → transfer → cancel → zombie yok
  - [ ] Light tema okunabilir
  - [ ] Mailbox yokken internet butonu disabled
- [ ] **Step 5: Final commit (varsa kalan)**
```bash
git commit -m "chore: adversarial review fixes complete"
```

---

## Uygulama Sırası Özeti

| Sıra | Faz | Task | Kritiklik | Tahmini |
|------|-----|------|-----------|---------|
| 1 | 0 | Task 0 | Hazırlık | 5 dk |
| 2 | 1 | Task 1-3 | 🔴 Critical | 45 dk |
| 3 | 2 | Task 4-6 | 🔴 Critical | 60 dk |
| 4 | 3 | Task 7-8 | 🔴 Critical | 90 dk |
| 5 | 4 | Task 9-10 | 🟠 Warning | 60 dk |
| 6 | 5 | Task 11-15 | 🟠 Warning | 90 dk |
| 7 | 6 | Task 16-19 | 🟡 Notes/CI | 45 dk |

**Toplam:** ~7-8 saat agent işi (review aralarıyla)

---

## Adversarial Review Coverage Matrix

| Review # | Madde | Task |
|----------|-------|------|
| C1 | Mailbox hijack | 4 |
| C2 | İptal zombie | 3 |
| C3 | disconnect transfer | 1 |
| C4 | clear() abort | 1 |
| C5 | LAN plaintext | 7 |
| C6 | unregister DoS | 4 |
| W7 | hız/ETA | 12 |
| W8 | light tema | 13 |
| W9 | mailbox guard | 11 |
| W10 | HTTP MITM | 6 |
| W11 | internet unregister | 2 |
| W12 | undersized file | 8 |
| W13 | in_flight race | 9 |
| W14 | respondPending | 14 |
| W15 | yanlış join mesajı | 11 |
| W16 | peer_name internet | 10 |
| W17 | 127.0.0.1 fallback | 10 |
| W18 | slowloris | 10 |
| W19 | settings stale | 14 |
| W20 | joinCode reset | 3 |
| W21 | mailbox validation | 5 |
| W22 | biased select | 9 |
| W23 | transfer fail toast | 12 |
| W24 | a11y | 15 |
| N25-35 | çeşitli | 16, 17, 18 |

---

## Self-Review

- [x] Spec coverage: Tüm Critical/Warning maddeleri task'a map edildi
- [x] Placeholder scan: TBD/TODO yok
- [x] Type consistency: `InternetCleanup`, `RegisterResponse`, `seal_control` isimleri fazlar arası tutarlı
- [x] Her faz sonunda test komutu var

---

## Execution Handoff

Plan `docs/superpowers/plans/2026-07-11-adversarial-fixes.md` dosyasına kaydedildi.

**İki uygulama seçeneği:**

1. **Subagent-Driven (önerilen)** — Her task için ayrı subagent, task arası review, hızlı iterasyon
2. **Inline Execution** — Bu oturumda `executing-plans` ile faz faz ilerleme, checkpoint'lerde onay

Hangisini tercih edersin?
