/** Map backend error strings to i18n keys (substring match, first hit wins). */
const ERROR_RULES: [string, string][] = [
  ["not connected", "err.notConnected"],
  ["a transfer is already in progress", "err.transferInProgress"],
  ["no pending transfer", "err.noPendingTransfer"],
  ["transfer decision already handled", "err.decisionHandled"],
  ["no peer found on the LAN", "err.noPeer"],
  ["key confirmation failed", "err.keyConfirmation"],
  ["too many failed pairing attempts", "err.tooManyPairingAttempts"],
  ["handshake timed out", "err.handshakeTimeout"],
  ["transfer rejected by peer", "err.transferRejected"],
  ["session ended", "err.sessionEnded"],
  ["coordinator stopped", "err.sessionEnded"],
  ["download directory must not be a symlink", "err.downloadDirSymlink"],
  ["refusing a system directory", "err.downloadDirSystem"],
  ["device name must not be empty", "err.deviceNameEmpty"],
  ["Code must be 6 digits", "join.error6"],
  ["integrity check failed", "err.integrityFailed"],
  ["no download directory available", "err.noDownloadDir"],
  ["no transfer in progress", "err.noTransferInProgress"],
  ["transfer cancelled", "err.transferCancelled"],
  ["invalid address", "err.invalidAddress"],
];

export function translateError(raw: string, t: (key: string) => string): string {
  const lower = raw.toLowerCase();
  for (const [needle, key] of ERROR_RULES) {
    if (lower.includes(needle.toLowerCase())) {
      return t(key);
    }
  }
  return raw;
}
