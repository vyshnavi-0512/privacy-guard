import React from "react";
import { Link } from "wouter";
import { 
  useGetDashboardSummary, 
  useGetBreachCategories, 
  useGetScanHistory 
} from "@/lib/api-client";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert, AlertTriangle, AlertCircle, CheckCircle, Database, Activity, Fingerprint, History, ArrowRight } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";
import { formatDistanceToNow } from "date-fns";
import { auth } from "../../firebase";

export default function DashboardPage() {
  const user = auth.currentUser;
  const { data: summary, isLoading: isLoadingSummary } =useGetDashboardSummary({
    enabled: !!user,
  });;
  const { data: categories, isLoading: isLoadingCategories } = useGetBreachCategories({
    enabled: !!user,
  });;
  const { data: history, isLoading: isLoadingHistory } = useGetScanHistory({
    enabled: !!user,
  });;

  const COLORS = [
    "hsl(var(--chart-1))", 
    "hsl(var(--chart-2))", 
    "hsl(var(--chart-3))", 
    "hsl(var(--chart-4))", 
    "hsl(var(--chart-5))"
  ];

  if (isLoadingSummary || isLoadingCategories || isLoadingHistory) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-32" />)}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Skeleton className="h-[400px]" />
          <Skeleton className="h-[400px]" />
        </div>
      </div>
    );
  }

  const recentScans = history?.slice(0, 5) || [];

  return (
    <div className="space-y-8 pb-12">
      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Scans"
          value={summary?.totalScans || 0}
          icon={Activity}
          description="Monitored queries"
        />
        <MetricCard
          title="Breaches Found"
          value={summary?.totalBreachesFound || 0}
          icon={Database}
          description="Total exposed records"
          trend="bad"
        />
        <MetricCard
          title="Avg Risk Score"
          value={summary?.averageRiskScore ? Math.round(summary.averageRiskScore) : 0}
          icon={Fingerprint}
          description="Out of 100"
        />
        <MetricCard
          title="Critical Alerts"
          value={summary?.criticalCount || 0}
          icon={ShieldAlert}
          description="Immediate action required"
          trend="bad"
        />
      </div>

      {/* Target Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="bg-card/40 border-border/50 backdrop-blur lg:col-span-1">
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <CardTitle className="font-display font-semibold text-lg tracking-wide flex items-center">
              <ShieldAlert className="w-5 h-5 mr-2 text-primary" />
              Target Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 font-mono">
              <TargetRow label="Email" count={summary?.emailCount ?? 0} colorClass="text-primary" />
              <TargetRow label="Username" count={summary?.usernameCount ?? 0} colorClass="text-muted-foreground" />
              <TargetRow label="Phone" count={summary?.phoneCount ?? 0} colorClass="text-primary" />
            </div>
          </CardContent>
        </Card>

        {/* Keep existing charts layout */}
        <div className="lg:col-span-2 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="col-span-1 bg-card/40 border-border/50 backdrop-blur">
              <CardHeader>
                <CardTitle className="font-display font-semibold text-lg tracking-wide flex items-center">
                  <AlertTriangle className="w-5 h-5 mr-2 text-primary" />
                  Risk Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4 font-mono text-sm">
                  <RiskBar label="Critical" count={summary?.criticalCount || 0} total={summary?.totalScans || 1} color="text-destructive" bg="bg-destructive" />
                  <RiskBar label="High" count={summary?.highCount || 0} total={summary?.totalScans || 1} color="text-orange-500" bg="bg-orange-500" />
                  <RiskBar label="Medium" count={summary?.mediumCount || 0} total={summary?.totalScans || 1} color="text-yellow-500" bg="bg-yellow-500" />
                  <RiskBar label="Low" count={summary?.lowCount || 0} total={summary?.totalScans || 1} color="text-blue-500" bg="bg-blue-500" />
                  <RiskBar label="Safe" count={summary?.safeCount || 0} total={summary?.totalScans || 1} color="text-primary" bg="bg-primary" />
                </div>
              </CardContent>
            </Card>

            <Card className="col-span-1 bg-card/40 border-border/50 backdrop-blur lg:col-span-1">
              <CardHeader>
                <CardTitle className="font-display font-semibold text-lg tracking-wide flex items-center">
                  <Database className="w-5 h-5 mr-2 text-primary" />
                  Exposed Data Categories
                </CardTitle>
              </CardHeader>
              <CardContent className="h-[300px] flex items-center justify-center">
                {categories && categories.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={categories}
                        dataKey="count"
                        nameKey="category"
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={100}
                        stroke="none"
                        paddingAngle={2}
                      >
                        {categories.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))', borderRadius: '0', fontFamily: 'var(--font-mono)', fontSize: '12px' }}
                        itemStyle={{ color: 'hsl(var(--foreground))' }}
                      />
                      <Legend wrapperStyle={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-muted-foreground font-mono text-sm flex flex-col items-center">
                    <CheckCircle className="w-8 h-8 text-primary mb-2 opacity-50" />
                    No data breaches logged.
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>


      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Exposed Data Types */}
        <Card className="bg-card/40 border-border/50 backdrop-blur">
          <CardHeader>
            <CardTitle className="font-display font-semibold text-lg tracking-wide">Top Exposed Vectors</CardTitle>
            <CardDescription className="font-mono">Most frequently compromised information types</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {summary?.topExposedDataTypes?.map((type, i) => (
                <div key={i} className="px-3 py-1 bg-secondary border border-border text-foreground font-mono text-xs rounded-sm uppercase tracking-wider">
                  {type}
                </div>
              ))}
              {(!summary?.topExposedDataTypes || summary.topExposedDataTypes.length === 0) && (
                <span className="text-muted-foreground font-mono text-sm">NO VECTORS DETECTED</span>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Recent Scans */}
        <Card className="bg-card/40 border-border/50 backdrop-blur">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <CardTitle className="font-display font-semibold text-lg tracking-wide">Recent Scans</CardTitle>
              <CardDescription className="font-mono mt-1">Latest threat intelligence queries</CardDescription>
            </div>
            <Link href="/history" className="text-primary hover:text-primary/80 font-mono text-xs flex items-center transition-colors">
              View All <ArrowRight className="w-3 h-3 ml-1" />
            </Link>
          </CardHeader>
          <CardContent>
            {recentScans.length > 0 ? (
              <div className="space-y-4 mt-2">
                {recentScans.map(scan => (
                  <div key={scan.id} className="flex items-center justify-between border-b border-border/50 pb-3 last:border-0 last:pb-0">
                    <div>
                      <div className="font-mono text-sm font-medium">{scan.query}</div>
                      <div className="font-mono text-[10px] text-muted-foreground flex items-center gap-2 mt-1">
                        <span className="uppercase">{scan.type}</span>
                        <span>•</span>
                        <span>{formatDistanceToNow(new Date(scan.scannedAt), { addSuffix: true })}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className={`font-mono text-xs font-bold ${scan.breachCount > 0 ? 'text-destructive' : 'text-primary'}`}>
                        {scan.breachCount} {scan.breachCount === 1 ? 'Breach' : 'Breaches'}
                      </div>
                      <Badge variant="outline" className={`font-mono text-[10px] uppercase ${
                        scan.riskScore >= 75 ? "border-destructive text-destructive bg-destructive/10" :
                        scan.riskScore >= 50 ? "border-orange-500 text-orange-500 bg-orange-500/10" :
                        scan.riskScore >= 25 ? "border-yellow-500 text-yellow-500 bg-yellow-500/10" :
                        "border-primary text-primary bg-primary/10"
                      }`}>
                        {scan.riskLevel}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-6 text-center text-muted-foreground font-mono text-sm">
                No recent scans found.
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function MetricCard({ title, value, icon: Icon, description, trend }: any) {
  return (
    <Card className="bg-card/40 border-border/50 backdrop-blur relative overflow-hidden group">
      <div className="absolute top-0 right-0 w-32 h-32 bg-primary/5 rounded-full blur-3xl -mr-10 -mt-10 transition-opacity group-hover:bg-primary/10" />
      <CardContent className="p-6 relative z-10">
        <div className="flex justify-between items-start mb-4">
          <div className="p-2 bg-secondary rounded-sm">
            <Icon className={`w-5 h-5 ${trend === 'bad' && value > 0 ? 'text-destructive' : 'text-primary'}`} />
          </div>
          <span className="font-display font-medium text-xs tracking-widest text-muted-foreground uppercase">{title}</span>
        </div>
        <div>
          <div className="text-4xl font-mono font-bold tracking-tight mb-1">{value}</div>
          <p className="text-xs font-mono text-muted-foreground">{description}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function TargetRow({ label, count, colorClass }: { label: string; count: number; colorClass: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground text-xs uppercase tracking-wider">{label}</span>
      <span className={`text-sm font-bold ${colorClass}`}>{count}</span>
    </div>
  );
}

function RiskBar({ label, count, total, color, bg }: any) {
  const percentage = total > 0 ? (count / total) * 100 : 0;
  return (
    <div>
      <div className="flex justify-between mb-1">
        <span className={`${color} uppercase tracking-wider text-xs font-bold`}>{label}</span>
        <span className="text-muted-foreground">{count}</span>
      </div>
      <div className="h-1.5 w-full bg-secondary rounded-full overflow-hidden">
        <div className={`h-full ${bg}`} style={{ width: `${percentage}%` }} />
      </div>
    </div>
  );
}
