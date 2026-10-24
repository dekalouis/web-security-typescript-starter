import { createHmac, timingSafeEqual } from "node:crypto";

// const pawPalApiKey = "pawpal_test_insecure_hardcoded_key";

export function createPawPalReference(
  orderId: number,
  totalCents: number,
  pawPalApiKey: string,
): string {
  const payload = `${orderId}:${totalCents}`;
  const signature = createHmac("sha256", pawPalApiKey)
    .update(payload)
    .digest("hex")
    .slice(0, 16);
  return `pawpal_${orderId}_${signature}`;
}

export function createPawPalCheckoutUrl(orderId: number): string {
  const checkoutUrl = new URL("https://pawpal.example/checkout");
  checkoutUrl.searchParams.set("orderId", String(orderId));
  return checkoutUrl.toString();
}

export type PawPalWebhookVerification =
  | { outcome: "unauthorized" }
  | { outcome: "malformed" }
  | { outcome: "approved"; orderId: number };

export function verifyPawPalWebhook(
  providedKey: string | undefined,
  expectedKey: string,
  payload: unknown,
): PawPalWebhookVerification {
  if (!providedKey || typeof providedKey !== "string") {
    return { outcome: "unauthorized" };
  }

  const providedBuf = Buffer.from(providedKey, "utf8");
  const expectedBuf = Buffer.from(expectedKey, "utf8");

  if (
    providedBuf.length !== expectedBuf.length ||
    !timingSafeEqual(providedBuf, expectedBuf)
  ) {
    return { outcome: "unauthorized" };
  }

  const payloadRecord =
    typeof payload === "object" && payload !== null
      ? (payload as Record<string, unknown>)
      : {};

  const orderId = payloadRecord.orderId;
  const status = payloadRecord.status;

  if (
    typeof orderId !== "number" ||
    !Number.isInteger(orderId) ||
    orderId <= 0 ||
    status !== "approved"
  ) {
    return { outcome: "malformed" };
  }

  return { outcome: "approved", orderId };
}
