import { Router } from "express";
import { ai } from "../lib/gemini.js";
import { requireFirebaseAuth } from "../lib/auth-middleware.js";
import { aiRateLimiter } from "../lib/rate-limiter.js";

const router = Router();
router.use(requireFirebaseAuth);
router.use(aiRateLimiter);

router.post("/", async (req, res) => {
  try {
    const { riskScore, breaches, exposedData } = req.body;

    const prompt = `
You are Privacy Guard AI, a cybersecurity assistant.

Analyze the following breach information and generate a practical remediation plan for an individual user.

Risk Score: ${riskScore}/100
Breaches: ${breaches.join(", ")}
Exposed Data: ${exposedData.join(", ")}

Return the response ONLY in Markdown format.

Use this exact structure:

# 🚨 Immediate Actions (Within 24 Hours)
- Action item
- Action item

# 🔐 Short-Term Actions (Within 7 Days)
- Action item
- Action item

# 🛡️ Long-Term Security Practices
- Action item
- Action item

Rules:
- Keep the response under 250 words.
- Give specific, actionable advice.
- Prioritize MFA, password changes, and phishing prevention when relevant.
- Mention credit monitoring only if financial data is exposed.
- Do not provide generic enterprise recommendations.
- Focus on the scanned user's personal security.
`;
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
    });

    res.json({
        plan: response.text ?? "No response generated",
      });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "Failed to generate plan",
    });
  }
});

export default router;
