import { Router } from "express";
import { createHash } from "crypto";
import { z } from "zod";
import { requireFirebaseAuth } from "../lib/auth-middleware.js";
import { passwordRateLimiter } from "../lib/rate-limiter.js";

const router = Router();
router.use(requireFirebaseAuth);
router.use(passwordRateLimiter);
const CheckPasswordBody = z.object({ password: z.string().min(1) });

function sha1(input: string): string {
  return createHash("sha1").update(input).digest("hex").toUpperCase();
}

function getSeverity(count: number): "safe" | "low" | "medium" | "high" | "critical" {
  if (count === 0) return "safe";
  if (count <= 10) return "low";
  if (count <= 1000) return "medium";
  if (count <= 100000) return "high";
  return "critical";
}

router.post("/passwords/check", async (req, res) => {
  const parsed = CheckPasswordBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: "Invalid input" }); return; }
  const { password } = parsed.data;
  try {
    const hash = sha1(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    const hibpRes = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "User-Agent": "PrivacyGuard/1.0", "Add-Padding": "true" },
      signal: AbortSignal.timeout(8000),
    });

    if (!hibpRes.ok) throw new Error(`HIBP API error: ${hibpRes.status}`);

    const text = await hibpRes.text();
    let count = 0;
    for (const line of text.split("\r\n")) {
      const [lineSuffix, lineCount] = line.split(":");
      if (lineSuffix?.toUpperCase() === suffix) { count = parseInt(lineCount ?? "0", 10); break; }
    }

    res.json({ pwned: count > 0, count, severity: getSeverity(count), hashPrefix: prefix });
  } catch (err) {
    console.error("Password check error:", err);
    res.status(500).json({ error: "Password check failed. Please try again." });
  }
});

export default router;
