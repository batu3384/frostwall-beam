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
  ["mailbox server is not configured", "err.mailboxNotConfigured"],
  ["no peer found for this code", "err.noPeerForCode"],
  ["invalid peer address", "err.invalidPeerAddress"],
  ["timed out connecting to the peer", "err.peerUnreachable"],
  ["could not reach peer", "err.peerUnreachable"],
  ["timed out establishing the data channel", "err.peerUnreachable"],
  ["mailbox unreachable", "err.mailboxUnreachable"],
  ["mailbox rejected registration", "err.mailboxUnreachable"],
  ["mailbox returned a malformed response", "err.mailboxUnreachable"],
  ["timed out starting the internet endpoint", "err.internetEndpointFailed"],
  ["failed to start internet endpoint", "err.internetEndpointFailed"],
  ["timed out waiting for an internet connection", "err.internetAcceptTimeout"],
  ["internet endpoint closed", "err.internetAcceptTimeout"],
  ["mailbox URL must use https", "err.mailboxUrlInvalid"],
  ["this pairing code is already registered", "err.codeAlreadyRegistered"],
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
