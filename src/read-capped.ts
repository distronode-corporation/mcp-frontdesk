/**
 * The capped reader for untrusted bodies (a token request, a client metadata
 * document fetched through the unsafe fetch option).
 *
 * The cap is enforced on the stream: a declared Content-Length over the cap is
 * refused before a byte is read, and a missing or lying one is caught chunk by
 * chunk, cancelling the stream at the first chunk that crosses the cap. Each
 * chunk is copied into one buffer of the cap's size as it arrives and then let
 * go, so what is ever held in memory is that buffer plus at most one arriving
 * chunk, however many chunks the body is cut into (and a source that reuses its
 * own buffer cannot change bytes already read). Reading the whole body and
 * checking its length afterwards would buffer exactly the bytes this exists to
 * refuse.
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
  const buffer = new Uint8Array(maxBytes);
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (total + value.byteLength > maxBytes) {
      await reader.cancel().catch(ignore);
      return { ok: false, reason: "too_large" };
    }
    buffer.set(value, total);
    total += value.byteLength;
  }
  return { ok: true, bytes: buffer.subarray(0, total) };
}
