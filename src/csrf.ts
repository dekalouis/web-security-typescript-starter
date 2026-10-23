import type { RequestHandler } from "express";
import { sendErrorPage } from "./errors.ts";
import { timingSafeEqual } from "node:crypto";

export function validateRequestOrigin(appOrigin: string): RequestHandler {
  return (req, res, next) => {
    if (req.method !== "POST") {
      next();
      return;
    }

    const origin = req.header("Origin");
    if (origin) {
      if (origin === appOrigin) {
        next();
        return;
      }

      sendErrorPage(
        res,
        403,
        "Forbidden",
        "This request did not come from Bearly Secure",
      );
      return;
    }

    const referer = req.header("Referer");
    if (referer) {
      try {
        if (new URL(referer).origin === appOrigin) {
          next();
          return;
        }
      } catch {
        sendErrorPage(
          res,
          403,
          "Forbidden",
          "This request did not come from Bearly Secure",
        );
        return
      }
    }

    sendErrorPage(
      res,
      403,
      "Forbidden",
      "This request did not come from Bearly Secure",
    );
  };
}

export function csrfTokensMatch(expected: string, actual: unknown): boolean {
  if (typeof actual !== "string") {
    return false;
  }
  const bufferExpected = Buffer.from(expected);
  const bufferActual = Buffer.from(actual);

  if (bufferActual.length !== bufferExpected.length) {
    return false;
  }

  if (timingSafeEqual(bufferActual, bufferExpected)) {
    return true;
  }
  return false;
}
