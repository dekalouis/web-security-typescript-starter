import { createHmac, timingSafeEqual } from "node:crypto";

const SIGNED_DOWNLOAD_TTL_SECONDS = 5 * 60;

export function createSignedDownloadPath(
  signingKey: Buffer,
  fileId: number,
  nowSeconds: number = currentUnixTime(),
): string {
  const expires = nowSeconds + SIGNED_DOWNLOAD_TTL_SECONDS;
  const signature = signDownload(signingKey, fileId, expires);
  return `/files/${fileId}/signed-download?expires=${expires}&signature=${signature}`;
}

export function verifySignedDownload(
  signingKey: Buffer,
  fileId: number,
  expiresValue: string,
  signature: string,
  nowSeconds: number = currentUnixTime(),
): boolean {

  if (!/^\d+$/.test(expiresValue) || !/^[a-f0-9]{64}$/.test(signature)) {
    return false;
  }

  const expires = Number(expiresValue);
  if (!Number.isSafeInteger(expires) || expires <= nowSeconds) {
    return false;
  }

  const providedSigBuffer = Buffer.from(signature, "hex");
  const expectedSignatureHex = signDownload(signingKey, fileId, expires);
  const expectedSigBuffer = Buffer.from(expectedSignatureHex, "hex");

  if (expectedSigBuffer.length !== providedSigBuffer.length) {
    return false;
  }

  return timingSafeEqual(expectedSigBuffer, providedSigBuffer);
}

function signDownload(
  signingKey: Buffer,
  fileId: number,
  expires: number,
): string {
  const payload = `GET\n/files/${fileId}/signed-download\n${expires}`;
  const signature = createHmac("sha256", signingKey)
    .update(payload)
    .digest("hex");
  // return "0".repeat(64);
  return signature;
}

function currentUnixTime(): number {
  return Math.floor(Date.now() / 1000);
}
