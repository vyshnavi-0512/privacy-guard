import { Router, type Request, type Response } from "express";
import { db, scansTable, monitorsTable, alertsTable } from "../db/index.js";
import { sql, desc, eq, and } from "drizzle-orm";
import { requireFirebaseAuth } from "../lib/auth-middleware.js";
console.log("Dashboard router loaded");
const router = Router();
router.use(requireFirebaseAuth);

router.get("/dashboard/summary", async (req: Request, res: Response) => {
  const firebaseUid = req.firebaseUid;
  if (!firebaseUid) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  try {
    const [stats] = await db.select({
      totalScans: sql<number>`count(*)::int`,
      totalBreachesFound: sql<number>`sum(breach_count)::int`,
      uniqueEmailsScanned: sql<number>`count(distinct query)::int`,
      averageRiskScore: sql<number>`round(avg(risk_score)::numeric, 1)`,
      criticalCount: sql<number>`count(*) filter (where risk_level = 'critical')::int`,
      highCount: sql<number>`count(*) filter (where risk_level = 'high')::int`,
      mediumCount: sql<number>`count(*) filter (where risk_level = 'medium')::int`,
      lowCount: sql<number>`count(*) filter (where risk_level = 'low')::int`,
      safeCount: sql<number>`count(*) filter (where risk_level = 'safe')::int`,
      emailCount: sql<number>`count(*) filter (where type = 'email')::int`,
      usernameCount: sql<number>`count(*) filter (where type = 'username')::int`,
      phoneCount: sql<number>`count(*) filter (where type = 'phone')::int`,
    }).from(scansTable).where(eq(scansTable.firebaseUid, firebaseUid));

    const [recent] = await db.select({ scannedAt: scansTable.scannedAt }).from(scansTable).where(eq(scansTable.firebaseUid, firebaseUid)).orderBy(desc(scansTable.scannedAt)).limit(1);
    const allScans = await db.select({ exposedDataTypes: scansTable.exposedDataTypes }).from(scansTable).where(eq(scansTable.firebaseUid, firebaseUid));

    const dataTypeCounts: Record<string, number> = {};
    for (const scan of allScans) {
      const types = scan.exposedDataTypes as string[];
      for (const t of types) { dataTypeCounts[t] = (dataTypeCounts[t] ?? 0) + 1; }
    }
    const topExposedDataTypes = Object.entries(dataTypeCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([type]) => type);

    const [monitorStats] = await db.select({ count: sql<number>`count(*)::int` }).from(monitorsTable).where(and(eq(monitorsTable.firebaseUid, firebaseUid), eq(monitorsTable.status, "active")));
    const alertStats = { count: 0 };

    res.json({
      totalScans: stats?.totalScans ?? 0,
      totalBreachesFound: stats?.totalBreachesFound ?? 0,
      uniqueEmailsScanned: stats?.uniqueEmailsScanned ?? 0,
      averageRiskScore: stats?.averageRiskScore ?? 0,
      criticalCount: stats?.criticalCount ?? 0,
      highCount: stats?.highCount ?? 0,
      mediumCount: stats?.mediumCount ?? 0,
      lowCount: stats?.lowCount ?? 0,
      safeCount: stats?.safeCount ?? 0,
      emailCount: stats?.emailCount ?? 0,
      usernameCount: stats?.usernameCount ?? 0,
      phoneCount: stats?.phoneCount ?? 0,
      mostRecentScan: recent?.scannedAt?.toISOString() ?? null,
      topExposedDataTypes,
      monitoredCount: monitorStats?.count ?? 0,
      activeAlerts: alertStats?.count ?? 0,
    });
  } catch (err) {
    console.error("Dashboard summary error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/dashboard/breach-categories", async (req: Request, res: Response) => {
  const firebaseUid = req.firebaseUid;
  if (!firebaseUid) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  try {
    const allScans = await db.select({ breaches: scansTable.breaches }).from(scansTable).where(eq(scansTable.firebaseUid, firebaseUid));
    const categoryCounts: Record<string, number> = {};
    let total = 0;
    for (const scan of allScans) {
      const breaches = scan.breaches as Array<{ dataClasses: string[] }>;
      for (const breach of breaches) {
        for (const dataClass of breach.dataClasses) {
          categoryCounts[dataClass] = (categoryCounts[dataClass] ?? 0) + 1;
          total++;
        }
      }
    }
    const categories = Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([category, count]) => ({ category, count, percentage: total > 0 ? Math.round((count / total) * 100 * 10) / 10 : 0 }));
    res.json(categories);
  } catch (err) {
    console.error("Categories error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
