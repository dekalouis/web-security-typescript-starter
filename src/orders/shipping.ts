import { decryptStringWithKeyring, encryptStringWithKeyring, type Keyring } from "../storage/keyring.ts";

export type ShippingDetails = {
  name: string;
  address: string;
  city: string;
  region: string;
  postalCode: string;
};

export function encryptShippingDetails(
  details: ShippingDetails,
  keyring: Keyring | undefined,
): string {
  const json = JSON.stringify(details);
  return encryptStringWithKeyring(json, keyring);
}

export function decryptShippingDetails(
  serialized: string,
  keyring: Keyring | undefined,
): ShippingDetails {
  const dectyptedString = decryptStringWithKeyring(serialized, keyring);
  let details: unknown;
  try {
    details = JSON.parse(dectyptedString);
  } catch {
    throw new Error("Invalid shipping details");
  }

  if (!isShippingDetails(details)) {
    throw new Error("Invalid shipping details");
  }

  return details;
}

function isShippingDetails(details: unknown): details is ShippingDetails {
  if (!details || typeof details !== "object") {
    return false;
  }

  const candidate = details as Record<string, unknown>;
  return (
    typeof candidate.name === "string" &&
    typeof candidate.address === "string" &&
    typeof candidate.city === "string" &&
    typeof candidate.region === "string" &&
    typeof candidate.postalCode === "string"
  );
}
