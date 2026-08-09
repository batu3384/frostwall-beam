import React, { createContext, useCallback, useContext, useEffect, useState } from "react";

export type Lang = "tr" | "en";

export const translations: Record<Lang, Record<string, string>> = {
  tr: {
    "hero.title": "Dosyaları buz gibi gönder",
    "hero.subtitle": "İki cihazı dönen kodla eşleştir. Uçtan uca şifreli.",
    "status.offline": "Çevrimdışı",
    "status.hosting": "Kod hazır",
    "status.connecting": "Bağlanıyor",
    "status.encrypted": "Şifreli",
    "mode.host": "Oturum başlat",
    "mode.join": "Oturuma katıl",
    "net.lan": "Aynı Wi‑Fi",
    "net.internet": "Uzaktan",
    "host.heading": "Kod oluştur",
    "host.desc": "Oluşan 6 haneli kodu karşı cihaza söyleyin. Ek ayar gerekmez.",
    "host.descInternet": "Farklı ağlardaki cihazlarla eşleşin. Karşı taraf da Uzaktan seçip aynı kodu girsin.",
    "host.button": "Kod oluştur",
    "join.heading": "Eşleşme kodunu gir",
    "join.desc": "Diğer cihazda görünen 6 haneli kod.",
    "join.descInternet": "Kodu oluşturan cihaz da Uzaktan modunda olmalı.",
    "join.waitingInternet": "Karşı cihaz aranıyor…",
    "join.button": "Bağlan",
    "join.error6": "Kod 6 haneli olmalı.",
    "waiting.codeLabel": "Eşleşme kodu",
    "waiting.copyHint": "Kodu kopyalamak için tıkla",
    "waiting.copied": "Kopyalandı ✓",
    "waiting.hostWait": "Bir cihazın bağlanması bekleniyor…",
    "joining.scanning": "Ağ taranıyor ve doğrulanıyor…",
    "common.cancel": "İptal",
    "connected.secure": "Bağlı · güvenli",
    "connected.rotates": "{n} sn sonra değişir",
    "connected.codeHint": "Doğrulama kodu · iki cihazda da aynı olmalı",
    "drop.hint": "Dosya veya klasörü buraya sürükle",
    "drop.or": "ya da seç",
    "drop.files": "Dosya seç",
    "drop.folder": "Klasör seç",
    "transfer.sending": "Gönderiliyor",
    "transfer.receiving": "Alınıyor",
    "transfer.completed": "Tamamlandı",
    "transfer.fileOne": "dosya",
    "transfer.fileMany": "dosya",
    "transfer.verified": "doğrulandı",
    "transfer.leftSuffix": "sn kaldı",
    "transfer.perSecSuffix": "/sn",
    "btn.disconnect": "Bağlantıyı kes",
    "toast.connected": "Bağlandı · şifreli kanal kuruldu",
    "toast.savedTo": "Şuraya kaydedildi: {x}",
    "toast.disconnected": "Bağlantı kesildi",
    "footer.crypto": "XChaCha20-Poly1305 · SPAKE2 · Blake3",
    "settings.title": "Ayarlar",
    "settings.language": "Dil",
    "settings.saveDir": "Alınan dosyaların kaydedileceği yer",
    "settings.saveDirChoose": "Seç…",
    "settings.saveDirDefault": "Varsayılan (~/Downloads/Frostwall Beam)",
    "settings.deviceName": "Cihaz adı",
    "settings.deviceNamePlaceholder": "örn. Mac mini",
    "settings.deviceNameSave": "Kaydet",
    "transfer.pending.title": "Gelen transfer",
    "transfer.pending.desc": "Karşı cihaz dosya göndermek istiyor. Kabul etmeden veri yazılmaz.",
    "transfer.pending.accept": "Kabul et",
    "transfer.pending.reject": "Reddet",
    "toast.transferRejected": "Transfer reddedildi",
    "common.dismiss": "Kapat",
    "err.notConnected": "Bağlı değil.",
    "err.transferInProgress": "Zaten devam eden bir transfer var.",
    "err.noPendingTransfer": "Bekleyen transfer yok.",
    "err.decisionHandled": "Transfer kararı zaten verildi.",
    "err.noPeer": "Ağda eş bulunamadı.",
    "err.keyConfirmation": "Anahtar doğrulaması başarısız. Kod yanlış veya arada saldırgan olabilir.",
    "err.tooManyPairingAttempts": "Çok fazla başarısız eşleşme denemesi. Yeni kod üretin.",
    "err.handshakeTimeout": "Eşleşme zaman aşımına uğradı.",
    "err.transferRejected": "Karşı taraf transferi reddetti.",
    "err.sessionEnded": "Oturum sona erdi.",
    "err.downloadDirSymlink": "İndirme klasörü sembolik link olamaz.",
    "err.downloadDirSystem": "Sistem klasörü indirme hedefi olamaz.",
    "err.deviceNameEmpty": "Cihaz adı boş olamaz.",
    "err.integrityFailed": "Dosya bütünlük doğrulaması başarısız.",
    "err.noDownloadDir": "İndirme klasörü bulunamadı.",
    "err.noTransferInProgress": "Devam eden transfer yok.",
    "err.transferCancelled": "Transfer iptal edildi.",
    "err.invalidAddress": "Geçersiz ağ adresi.",
    "err.noPeerForCode": "Bu kod için cihaz bulunamadı (süresi dolmuş olabilir veya kod henüz oluşturulmamış).",
    "err.invalidPeerAddress": "Geçersiz eş adresi.",
    "err.peerUnreachable": "Eşe ulaşılamadı (ağ veya güvenlik duvarı sorunu olabilir).",
    "err.rendezvousUnreachable": "Eşleşme sunucusuna ulaşılamıyor.",
    "err.remoteUnavailable": "Uzaktan eşleşme şu an kullanılamıyor.",
    "err.internetEndpointFailed": "Uzaktan bağlantı başlatılamadı (ağınızı kontrol edin).",
    "err.internetAcceptTimeout": "Bağlantı için zaman aşımı (kimse katılmadı).",
    "err.noLanInterface": "Yerel ağ arayüzü bulunamadı — aynı Wi‑Fi ağına bağlanın.",
    "err.tooManyStallAttempts": "Çok fazla takılan eşleşme denemesi — yeni kod üretin.",
    "err.configPersistFailed": "Ayarlar kaydedilemedi.",
    "err.codeAlreadyRegistered": "Bu kod zaten kayıtlı — yeni kod üretin.",
    "connected.peer": "Eş: {name}",
    "connected.you": "Bu cihaz: {name}",
    "connected.peerGeneric": "Eş cihaz bağlandı",
    "transfer.cancel": "Transferi iptal et",
    "toast.transferCancelled": "Transfer iptal edildi",
    "toast.transferFailed": "Transfer başarısız oldu",
    "join.pickPeer": "Bağlanılacak cihazı seç",
    "join.pickPeerDesc": "Aynı ağda birden fazla Frostwall Beam bulundu.",
    "join.scanningPeers": "Yakındaki cihazlar aranıyor…",
    "settings.theme": "Tema",
    "settings.theme.system": "Sistem",
    "settings.theme.dark": "Koyu",
    "settings.theme.light": "Açık",
    "settings.history": "Transfer geçmişi",
    "settings.historyEmpty": "Henüz kayıtlı transfer yok.",
    "settings.historyEntry": "{dir} · {n} dosya · {size}",
    "settings.historyOk": "başarılı",
    "settings.historyFail": "başarısız",
  },
  en: {
    "hero.title": "Send files, ice-cold",
    "hero.subtitle": "Pair two devices with a rotating code. End-to-end encrypted.",
    "status.offline": "Offline",
    "status.hosting": "Code ready",
    "status.connecting": "Connecting",
    "status.encrypted": "Encrypted",
    "mode.host": "Host a session",
    "mode.join": "Join a session",
    "net.lan": "Same Wi‑Fi",
    "net.internet": "Remote",
    "host.heading": "Create a code",
    "host.desc": "Share the 6-digit code with the other device. No setup needed.",
    "host.descInternet": "Pair across different networks. The other device must also pick Remote and enter the same code.",
    "host.button": "Create code",
    "join.heading": "Enter pairing code",
    "join.desc": "The 6-digit code shown on the other device.",
    "join.descInternet": "The device that created the code must be in Remote mode too.",
    "join.waitingInternet": "Looking for the other device…",
    "join.button": "Connect",
    "join.error6": "Code must be 6 digits.",
    "waiting.codeLabel": "Pairing code",
    "waiting.copyHint": "Click the code to copy",
    "waiting.copied": "Copied ✓",
    "waiting.hostWait": "Waiting for a device to connect…",
    "joining.scanning": "Scanning the network and verifying…",
    "common.cancel": "Cancel",
    "connected.secure": "Connected · secure",
    "connected.rotates": "rotates in {n}s",
    "connected.codeHint": "Verification code · must match on both devices",
    "drop.hint": "Drop files or folders here",
    "drop.or": "or browse",
    "drop.files": "Choose files",
    "drop.folder": "Choose folder",
    "transfer.sending": "Sending",
    "transfer.receiving": "Receiving",
    "transfer.completed": "Completed",
    "transfer.fileOne": "file",
    "transfer.fileMany": "files",
    "transfer.verified": "verified",
    "transfer.leftSuffix": "s left",
    "transfer.perSecSuffix": "/s",
    "btn.disconnect": "Disconnect",
    "toast.connected": "Connected · encrypted channel established",
    "toast.savedTo": "Saved to {x}",
    "toast.disconnected": "Disconnected",
    "footer.crypto": "XChaCha20-Poly1305 · SPAKE2 · Blake3",
    "settings.title": "Settings",
    "settings.language": "Language",
    "settings.saveDir": "Save received files to",
    "settings.saveDirChoose": "Choose…",
    "settings.saveDirDefault": "Default (~/Downloads/Frostwall Beam)",
    "settings.deviceName": "Device name",
    "settings.deviceNamePlaceholder": "e.g. Mac mini",
    "settings.deviceNameSave": "Save",
    "transfer.pending.title": "Incoming transfer",
    "transfer.pending.desc": "The other device wants to send files. Nothing is written until you accept.",
    "transfer.pending.accept": "Accept",
    "transfer.pending.reject": "Decline",
    "toast.transferRejected": "Transfer declined",
    "common.dismiss": "Dismiss",
    "err.notConnected": "Not connected.",
    "err.transferInProgress": "A transfer is already in progress.",
    "err.noPendingTransfer": "No pending transfer.",
    "err.decisionHandled": "Transfer decision already handled.",
    "err.noPeer": "No peer found on the LAN.",
    "err.keyConfirmation": "Key confirmation failed. Wrong code or a possible attacker.",
    "err.tooManyPairingAttempts": "Too many failed pairing attempts. Generate a new code.",
    "err.handshakeTimeout": "Pairing timed out.",
    "err.transferRejected": "The peer declined the transfer.",
    "err.sessionEnded": "Session ended.",
    "err.downloadDirSymlink": "Download directory cannot be a symlink.",
    "err.downloadDirSystem": "System directories cannot be used as download targets.",
    "err.deviceNameEmpty": "Device name cannot be empty.",
    "err.integrityFailed": "File integrity check failed.",
    "err.noDownloadDir": "No download directory available.",
    "err.noTransferInProgress": "No transfer in progress.",
    "err.transferCancelled": "Transfer cancelled.",
    "err.invalidAddress": "Invalid network address.",
    "err.noPeerForCode": "No peer found for this code (it may have expired, or the host hasn't started yet).",
    "err.invalidPeerAddress": "Invalid peer address.",
    "err.peerUnreachable": "Could not reach the peer (possible network or firewall issue).",
    "err.rendezvousUnreachable": "Could not reach the pairing server.",
    "err.remoteUnavailable": "Remote pairing is not available.",
    "err.internetEndpointFailed": "Could not start the remote connection (check your network).",
    "err.internetAcceptTimeout": "Timed out waiting for a connection (nobody joined).",
    "err.noLanInterface": "No LAN interface found — connect to the same Wi‑Fi network.",
    "err.tooManyStallAttempts": "Too many stalled pairing attempts — generate a new code.",
    "err.configPersistFailed": "Could not save settings.",
    "err.codeAlreadyRegistered": "This code is already registered — generate a new one.",
    "connected.peer": "Peer: {name}",
    "connected.you": "This device: {name}",
    "connected.peerGeneric": "Peer device connected",
    "transfer.cancel": "Cancel transfer",
    "toast.transferCancelled": "Transfer cancelled",
    "toast.transferFailed": "Transfer failed",
    "join.pickPeer": "Choose a device to join",
    "join.pickPeerDesc": "Multiple Frostwall Beam devices were found nearby.",
    "join.scanningPeers": "Scanning for nearby devices…",
    "settings.theme": "Theme",
    "settings.theme.system": "System",
    "settings.theme.dark": "Dark",
    "settings.theme.light": "Light",
    "settings.history": "Transfer history",
    "settings.historyEmpty": "No transfers recorded yet.",
    "settings.historyEntry": "{dir} · {n} files · {size}",
    "settings.historyOk": "ok",
    "settings.historyFail": "failed",
  },
};

const STORAGE_KEY = "frostwall.lang";
const DEFAULT_LANG: Lang = "tr";

interface I18nContextValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: string) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

function readStoredLang(): Lang {
  if (typeof window === "undefined") return DEFAULT_LANG;
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "tr" || stored === "en") return stored;
  } catch {
    // localStorage unavailable (e.g. privacy mode); fall back to default.
  }
  return DEFAULT_LANG;
}

export function LangProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  const [lang, setLangState] = useState<Lang>(readStoredLang);

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, lang);
    } catch {
      // Ignore write failures (storage full / disabled).
    }
    document.documentElement.lang = lang;
  }, [lang]);

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
  }, []);

  const t = useCallback(
    (key: string): string => {
      const table = translations[lang];
      const value = table[key];
      if (value === undefined) {
        if (import.meta.env && import.meta.env.DEV) {
          console.warn("[i18n] missing key:", key);
        }
        return key;
      }
      return value;
    },
    [lang],
  );

  const value = React.useMemo<I18nContextValue>(
    () => ({ lang, setLang, t }),
    [lang, setLang, t],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): { lang: Lang; setLang: (l: Lang) => void; t: (key: string) => string } {
  const ctx = useContext(I18nContext);
  if (ctx === null) {
    throw new Error("useI18n must be used within a LangProvider");
  }
  return ctx;
}
