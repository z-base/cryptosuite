import { ZeyraError } from "../.errors/class.js";

export function getBufferSourceLength(
  source: BufferSource,
  context = "value",
): number {
  if (source instanceof ArrayBuffer) return source.byteLength;
  if (ArrayBuffer.isView(source)) return source.byteLength;

  throw new ZeyraError(
    "BUFFER_SOURCE_EXPECTED",
    `${context}: expected a BufferSource.`,
  );
}
