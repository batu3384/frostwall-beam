/** Invite layout — keep in lockstep with `internet.rs` `parse_invite`.
 *  endpoint<ticket>-<6 digits>[-<hex name>]
 *  fwb1-<64 hex>-<6 digits>
 *  fwb2-<64 hex>-<6 digits>-<hex payload>
 */
export const INVITE_MAX = 1024;
/** Raw paste including chat wrapping / trailing newline. Compact form still
 *  capped at `INVITE_MAX`. Lockstep `internet.rs` `INVITE_PASTE_MAX`. */
export const INVITE_PASTE_MAX = INVITE_MAX * 4;

/** Lockstep `internet.rs` `compact_invite`: drop ZWSP, quotes, punctuation. */
export function compactInvite(s: string): string {
  return s.replace(/[^a-zA-Z0-9-]/g, "").toLowerCase();
}

export function looksLikeInvite(s: string): boolean {
  const c = compactInvite(s);
  return /endpoint[a-z0-9]+-\d{6}/.test(c)
    || /fwb2-[0-9a-f]{64}-\d{6}-/.test(c)
    || /fwb1-[0-9a-f]{64}-\d{6}/.test(c);
}

/** SPAKE2 digits from an invite or raw LAN box. Never the EndpointId hex. */
export function lanCodeFromInput(s: string): string {
  const compact = compactInvite(s);
  const ticket = compact.match(/endpoint[a-z0-9]+-(\d{6})(?:-[0-9a-f]+)?/);
  if (ticket) return ticket[1];
  if (compact.includes("endpoint")) return "";
  const fwb2 = compact.match(/fwb2-[0-9a-f]{64}-(\d{6})-/);
  if (fwb2) return fwb2[1];
  const fwb1 = compact.match(/fwb1-[0-9a-f]{64}-(\d{6})/);
  if (fwb1) return fwb1[1];
  if (compact.includes("fwb")) return "";
  return compact.replace(/\D/g, "");
}
