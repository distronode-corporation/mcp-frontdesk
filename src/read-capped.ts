/**
 * The capped reader for untrusted bodies (a token request, a client metadata
 * document fetched through the unsafe fetch option).
 *
 * The cap is enforced on the stream: a declared Content-Length over the cap is
 * refused before a byte is read, and a missing or lying one is caught chunk by
 * chunk, cancelling the stream at the first chunk that crosses the cap. What is
 * ever held in memory is the cap plus at most one arriving chunk. Reading the
 * whole body and checking its length afterwards would buffer exactly the bytes
 * this exists to refuse.
 *
 * Never truncates: the caller gets the whole body or a refusal.
 */

export type CappedRead = { ok: true; bytes: Uint8Array } | { ok: false; reason: "too_large" };

/** A cancel that fails has nothing left to tell us: the read is already refused. */
const ignore = (): undefined => undefined;

export async function readCapped(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
  declaredLength: string | null = null,
): Promise<CappedRead> {
  const declared = declaredLength === null ? Number.NaN : Number(declaredLength);
  if (Number.isFinite(declared) && declared > maxBytes) {
    await body?.cancel().catch(ignore);
    return { ok: false, reason: "too_large" };
  }
  if (body === null) return { ok: true, bytes: new Uint8Array(0) };
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(ignore);
      return { ok: false, reason: "too_large" };
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, bytes: out };
}
