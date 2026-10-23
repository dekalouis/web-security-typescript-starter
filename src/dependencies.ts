import { randomBytes } from "node:crypto";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { openDatabase } from "./db/index.ts";
import { loadOptionalKeyring, type Keyring } from "./storage/keyring.ts";

export type Dependencies = {
  appOrigin: string;
  port: number;
  databasePath: string;
  acornFulfillmentDelayMs: number;
  maxRequestBodyBytes: number;
  maxUploadBytes: number;
  maxPublicProductResults: number;
  downloadSigningKey: Buffer;
  keyring: Keyring | undefined;
  db: DatabaseSync;
  pawPalApiKey: string;
  trustedProxyHops: number;
};

function parseNonNegativeInteger(value: string, name: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }
  return parsed;
}

export function initDependencies(
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): Dependencies {
  const port = parseNonNegativeInteger(env.PORT ?? "3000", "PORT");
  if (port > 65_535) {
    throw new Error("PORT must be no greater than 65535");
  }

  const acornFulfillmentDelayMs = Number(env.ACORN_FULFILLMENT_DELAY_MS ?? "0");
  if (
    !Number.isFinite(acornFulfillmentDelayMs) ||
    acornFulfillmentDelayMs < 0
  ) {
    throw new Error("ACORN_FULFILLMENT_DELAY_MS must be a non-negative number");
  }

  const signingKey = requireEnv("DOWNLOAD_SIGNING_KEY");
  if (typeof signingKey !== "string" || !/^[a-fA-F0-9]{64}$/.test(signingKey)) {
    throw new Error("DOWNLOAD_SIGNING_KEY must be exactly 64 hexadecimal characters");
  }
  const signingKeyBuffer = Buffer.from(signingKey, "hex");

  const values = {
    appOrigin: new URL(env.APP_ORIGIN ?? "http://localhost:3000").origin,
    port,
    databasePath: env.DATABASE_URL ?? join(cwd, "data", "bearly-secure.sqlite"),
    acornFulfillmentDelayMs,
    maxRequestBodyBytes: 32 * 1024,
    maxUploadBytes: 1024 * 1024,
    maxPublicProductResults: 50,
    downloadSigningKey: signingKeyBuffer,
    keyring: loadOptionalKeyring(env),
    pawPalApiKey: requireEnv("PAWPAL_API_KEY"),
    trustedProxyHops: parseNonNegativeInteger(
      env.TRUST_PROXY_HOPS ?? "0",
      "TRUST_PROXY_HOPS",
    ),
  };

  return { ...values, db: openDatabase(values.databasePath) };
}

export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}
