const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** Envelope the client verifies: Ed25519 over the exact UTF-8 bytes of `payload`. */
export async function sign(snapshot, pkcs8Base64, kid) {
  const key = await crypto.subtle.importKey('pkcs8', unb64(pkcs8Base64), { name: 'Ed25519' }, false, ['sign']);
  const payload = JSON.stringify(snapshot);
  const sig = await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(payload));
  return { kid, payload, sig: b64(sig) };
}
