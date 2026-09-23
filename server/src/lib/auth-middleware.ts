import { createVerify, createPublicKey } from "crypto";
import type { NextFunction, Request, Response } from "express";
import { getFirebaseAdmin } from "./firebase-admin.js";

declare module "express-serve-static-core" {
  interface Request {
    firebaseUid?: string;
  }
}

const FIREBASE_CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken%40system.gserviceaccount.com";
let cachedCerts: Record<string, string> | null = null;
let certsExpiry = 0;

async function getFirebaseCerts(): Promise<Record<string, string>> {
  const now = Date.now();
  if (cachedCerts && now < certsExpiry) {
    return cachedCerts;
  }
  const certsRes = await fetch(FIREBASE_CERTS_URL);
  if (!certsRes.ok) {
    throw new Error("Unable to load Firebase signing keys");
  }
  cachedCerts = (await certsRes.json()) as Record<string, string>;
  certsExpiry = now + 60 * 60 * 1000; // Cache for 1 hour
  return cachedCerts;
}

async function verifyWithPublicKeys(idToken: string) {
  const [headerSegment, payloadSegment, signatureSegment] = idToken.split(".");
  if (!headerSegment || !payloadSegment || !signatureSegment) {
    throw new Error("Invalid token format");
  }

  const header = JSON.parse(Buffer.from(headerSegment, "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(payloadSegment, "base64url").toString("utf8"));
  const projectId = process.env.FIREBASE_PROJECT_ID ?? "privacyguard-e9f0c";
  const expectedIssuer = `https://securetoken.google.com/${projectId}`;

  if (payload.iss !== expectedIssuer) {
    throw new Error("Unexpected issuer");
  }
  if (payload.aud !== projectId) {
    throw new Error("Unexpected audience");
  }
  if (typeof payload.exp !== "number" || payload.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error("Expired token");
  }

  const certs = await getFirebaseCerts();
  const signingKey = certs[header.kid as string];
  if (!signingKey) {
    throw new Error("No matching signing key found");
  }

  const verifier = createVerify("RSA-SHA256");
  verifier.update(`${headerSegment}.${payloadSegment}`);
  const isValid = verifier.verify(createPublicKey(signingKey), Buffer.from(signatureSegment, "base64url"));
  if (!isValid) {
    throw new Error("Invalid signature");
  }

  return { uid: payload.user_id ?? payload.sub };
}

export async function requireFirebaseAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.header("Authorization") ?? "";
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (!match) {
      res.status(401).json({ error: "Missing or invalid Authorization header" });
      return;
    }

    const idToken = match[1];

    let decoded: { uid?: string } | null = null;
    try {
      const admin = getFirebaseAdmin();
      decoded = await (admin as any).auth().verifyIdToken(idToken);
    } catch (adminError) {
      decoded = await verifyWithPublicKeys(idToken);
    }

    req.firebaseUid = decoded?.uid;
    if (!req.firebaseUid) {
      throw new Error("Missing uid in token");
    }
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}
