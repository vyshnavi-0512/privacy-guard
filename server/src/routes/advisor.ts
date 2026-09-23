import { Router } from "express";
import { ai } from "../lib/gemini.js";
import { z } from "zod";
import { requireFirebaseAuth } from "../lib/auth-middleware.js";
import { aiRateLimiter } from "../lib/rate-limiter.js";

const router = Router();
router.use(requireFirebaseAuth);
router.use(aiRateLimiter);

const BreachSchema = z.object({
  name: z.string(),
  breachDate: z.string(),
  dataClasses: z.array(z.string()),
  riskLevel: z.string(),
});

const AdvisorBody = z.object({
  scanId: z.string(),
  breaches: z.array(BreachSchema),
  exposedDataTypes: z.array(z.string()),
});

router.post("/advisor/recommend", async (req, res) => {
  const parsed = AdvisorBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: "Invalid input" }); return; }
  const { scanId, breaches, exposedDataTypes } = parsed.data;

  const exposedText = [...exposedDataTypes, ...breaches.flatMap((b) => b.dataClasses)]
    .join(" ")
    .toLowerCase();

  const isPhoneScan = exposedText.includes("sms") ||
    exposedText.includes("phone") ||
    exposedText.includes("spam call") ||
    exposedText.includes("spam call lists") ||
    exposedText.includes("sim swap") ||
    exposedText.includes("account recovery") ||
    exposedText.includes("telephony");

  try {
    const breachSummary = breaches.length === 0
      ? "No breaches were found for this scan."
      : breaches.map((b) => `- ${b.name} (${b.breachDate}): exposed ${b.dataClasses.join(", ")} — risk level: ${b.riskLevel}`).join("\n");
    const exposedSummary = exposedDataTypes.length > 0 ? `Exposed data types: ${exposedDataTypes.join(", ")}` : "No data types exposed.";

    const phoneSpecificAdvice = isPhoneScan
      ? `
PHONE-SCAN REQUIREMENTS (must be reflected in recommendations):
- Include phone-related threats: SMS phishing (smishing), SIM swap indicators, spam/robocall exposure, and account recovery abuse.
- Include at least 2 actions from this set where applicable:
  1) Enable carrier account PIN protection
  2) Watch for SIM swap indicators
  3) Avoid replying to unknown SMS links
  4) Review account recovery methods tied to this number
  5) Enable MFA using an authenticator app instead of SMS where possible
- If breaches are present, tailor recommendations to the specific SMS/telephony/account recovery signals indicated above.
`
      : "";

    const prompt = `You are a cybersecurity expert AI. A user ran a privacy scan and here are the results:

${breachSummary}

${exposedSummary}

${phoneSpecificAdvice}

Provide a concise, actionable security assessment. Return a JSON object with this exact structure:
{
  "overallAssessment": "2-3 sentences summarizing the overall risk situation",
  "riskSummary": "1 sentence risk level summary",
  "recommendations": [
    {
      "priority": "urgent|high|medium|low",
      "category": "password|account|monitoring|financial|identity|device",
      "title": "Short action title",
      "description": "1-2 sentence description of why this matters",
      "actionSteps": ["Step 1", "Step 2", "Step 3"]
    }
  ]
}

Provide 3-6 recommendations. Make them specific to the actual breaches found. If no breaches, provide general privacy hardening advice. Be direct and practical — no fluff.`;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
      },
    });

    const content = response.text;
    if (!content) { res.status(500).json({ error: "No response from AI" }); return; }

    const parsed_response = JSON.parse(content);
    res.json({
      scanId,
      overallAssessment: parsed_response.overallAssessment ?? "",
      riskSummary: parsed_response.riskSummary ?? "",
      recommendations: parsed_response.recommendations ?? [],
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error("Advisor error:", err);
    res.status(500).json({ error: "Failed to generate recommendations" });
  }
});

export default router;
