import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { 
  useCreateScan, 
  useGetAiRecommendations,
  getGetScanHistoryQueryKey,
  getGetDashboardSummaryQueryKey,
  getGetBreachCategoriesQueryKey,
  apiFetch,
  API_URL
} from "@/lib/api-client";
import type { ScanResult, AdvisorResponse } from "@/lib/api-client";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Search, ShieldAlert, Cpu, AlertTriangle, CheckCircle, ArrowRight, Shield, Printer, FileText, X } from "lucide-react";
import { trackEvent } from "@/lib/analytics";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const phoneRegex = /^\+?[1-9]\d{7,14}$/;


const scanSchema = z
  .object({
    query: z.string().min(1, "Query is required"),
    type: z.enum(["email", "username", "phone"]),
  })
  .superRefine((val, ctx) => {
    if (val.type !== "phone") return;
    if (!phoneRegex.test(val.query.trim())) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Enter a valid international phone number (E.164 style, e.g. +919876543210).",
        path: ["query"],
      });
    }
  });


export default function ScanPage() {
  const [aiPlan, setAiPlan] = useState("");
  const [isGeneratingPlan, setIsGeneratingPlan] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const generateRemediationPlan = async () => {
    if (!scanResult) return;
  
    try {
      setIsGeneratingPlan(true);
  
      const data = await apiFetch<{ plan: string }>(
        `${API_URL}/api/remediation`,
        {
          method: "POST",
          body: JSON.stringify({
            riskScore: scanResult.riskScore,
            breaches: scanResult.breaches.map(
              (b: any) => b.name
            ),
            exposedData: scanResult.exposedDataTypes,
          }),
        }
      );
  
      setAiPlan(data.plan);
    } catch (error) {
      console.error(error);
    } finally {
      setIsGeneratingPlan(false);
    }
  };

  const [location] = useLocation();
  const searchParams = new URLSearchParams(window.location.search);
  const initialQuery = searchParams.get("query") || "";
  const initialType = (searchParams.get("type") as "email" | "username" | "phone") || "email";

  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [advisorResponse, setAdvisorResponse] = useState<AdvisorResponse | null>(null);

  const queryClient = useQueryClient();
  const createScan = useCreateScan();
  const getAdvisor = useGetAiRecommendations();

  const form = useForm<z.infer<typeof scanSchema>>({
    resolver: zodResolver(scanSchema),
    defaultValues: {
      query: initialQuery,
      type: initialType,
      
    },
  });
  const onSubmit = (values: z.infer<typeof scanSchema>) => {
    setScanResult(null);
    setAdvisorResponse(null);
    setAiPlan("");
    setIsGeneratingPlan(false);
    trackEvent("scan_started", "/scan", {
      source: "privacyguard",
    });
    createScan.mutate(
      { data: values },
      {
        onSuccess: (result) => {
          setScanResult(result);
    
          queryClient.invalidateQueries({
            queryKey: getGetScanHistoryQueryKey(),
          });
    
          queryClient.invalidateQueries({
            queryKey: getGetDashboardSummaryQueryKey(),
          });
    
          queryClient.invalidateQueries({
            queryKey: getGetBreachCategoriesQueryKey(),
          });
    
          trackEvent("scan_completed", "/scan", {
            source: "privacyguard",
          });
        },
    
        onError: (error) => {
          trackEvent("error", "/scan", {
            source: "privacyguard",
            message:
              error instanceof Error
                ? error.message
                : "Scan failed",
          });
        },
      }
    );
  };

  const handleGetAdvice = () => {
    if (!scanResult) return;
    getAdvisor.mutate(
      {
        data: {
          scanId: scanResult.id,
          breaches: scanResult.breaches,
          exposedDataTypes: scanResult.exposedDataTypes,
        },
      },
      {
        onSuccess: (res) => {
          setAdvisorResponse(res);
        },
      }
    );
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto pb-12">
      <Card className="bg-card/40 border-border/50 backdrop-blur">
        <CardHeader className="border-b border-border/50 pb-6">
          <CardTitle className="font-display font-semibold text-2xl tracking-wide flex items-center">
            <Search className="w-6 h-6 mr-3 text-primary" />
            Threat Scan Initialization
          </CardTitle>
          <CardDescription className="font-mono text-muted-foreground mt-2">
            Enter an email address, username, or phone number to cross-reference against known data breaches.
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-6">
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div className="md:col-span-3">
                  <FormField
                    control={form.control}
                    name="query"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Target Identifier</FormLabel>
                        <FormControl>
                          <Input 
                            placeholder={form.watch("type") === "phone" ? "+919876543210" : form.watch("type") === "username" ? "example_user" : "target@example.com"}
                            className="bg-secondary/50 font-mono border-primary/20 focus-visible:border-primary h-12"
                            {...field}
                          />
                        </FormControl>
                        <FormMessage className="font-mono text-xs" />
                      </FormItem>
                    )}
                  />
                </div>
                <div className="md:col-span-1">
                  <FormField
                    control={form.control}
                    name="type"
                    render={({ field }) => (
                      <FormItem className="space-y-3">
                        <FormLabel className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Target Type</FormLabel>
                        <FormControl>
                          <RadioGroup
                            onValueChange={field.onChange}
                            defaultValue={field.value}
                            className="flex flex-col space-y-1"
                          >
                            <FormItem className="flex items-center space-x-3 space-y-0">
                              <FormControl>
                                <RadioGroupItem value="email" className="border-primary/50 text-primary" />
                              </FormControl>
                              <FormLabel className="font-mono font-normal">Email</FormLabel>
                            </FormItem>
                            <FormItem className="flex items-center space-x-3 space-y-0">
                              <FormControl>
                                <RadioGroupItem value="username" className="border-primary/50 text-primary" />
                              </FormControl>
                              <FormLabel className="font-mono font-normal">Username</FormLabel>
                            </FormItem>

                            <FormItem className="flex items-center space-x-3 space-y-0">
                              <FormControl>
                                <RadioGroupItem value="phone" className="border-primary/50 text-primary" />
                              </FormControl>
                              <FormLabel className="font-mono font-normal">Phone Number</FormLabel>
                            </FormItem>
                          </RadioGroup>
                        </FormControl>
                      </FormItem>
                    )}
                  />
                </div>
              </div>
              <Button 
                type="submit" 
                disabled={createScan.isPending}
                className="w-full font-display uppercase tracking-widest h-12"
              >
                {createScan.isPending ? (
                  <span className="flex items-center">
                    <span className="animate-pulse mr-2">Scanning</span>
                    <span className="w-1.5 h-1.5 bg-primary-foreground rounded-full animate-bounce mx-0.5" />
                    <span className="w-1.5 h-1.5 bg-primary-foreground rounded-full animate-bounce mx-0.5 delay-75" />
                    <span className="w-1.5 h-1.5 bg-primary-foreground rounded-full animate-bounce mx-0.5 delay-150" />
                  </span>
                ) : (
                  <span className="flex items-center">
                    Initiate Scan <ArrowRight className="ml-2 w-4 h-4" />
                  </span>
                )}
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>

      {scanResult && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-xl font-bold tracking-wide flex items-center">
              <ShieldAlert className="w-5 h-5 mr-2 text-primary" />
              Scan Results
            </h2>
            <div className="flex items-center space-x-4">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowReportModal(true)}
                className="font-mono text-xs border-primary/40 hover:bg-primary/10 text-primary"
              >
                <FileText className="w-4 h-4 mr-2" />
                Export PDF Report
              </Button>
              <div className="text-right">
                <div className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Risk Score</div>
                <div className="font-mono font-bold text-2xl text-primary">{scanResult.riskScore}/100</div>
              </div>
              <Badge variant={scanResult.breachCount > 0 ? "destructive" : "default"} className="font-mono py-1 px-3">
                {scanResult.riskLevel.toUpperCase()}
              </Badge>
            </div>
          </div>

          {scanResult.type === "phone" ? (
            <div className="space-y-4">
              <p className="font-mono text-sm text-primary flex items-center bg-primary/10 p-3 rounded border border-primary/20">
                <ShieldAlert className="w-4 h-4 mr-2" />
                Telephony Risk Profile — Assessed {scanResult.breaches.length} security factors and hygiene indicators for {scanResult.query}.
              </p>

              <div className="grid grid-cols-1 gap-4">
                {scanResult.breaches.map((breach, idx) => (
                  <Card key={idx} className="bg-card/60 border-primary/20 relative overflow-hidden">
                    <div className="absolute left-0 top-0 bottom-0 w-1 bg-primary/50" />
                    <CardHeader className="py-4">
                      <div className="flex justify-between items-start">
                        <div>
                          <CardTitle className="font-display font-semibold text-lg">{breach.name}</CardTitle>
                          <CardDescription className="font-mono text-xs mt-1">
                            Category: {breach.domain}
                            {breach.breachDate && breach.breachDate !== "1970-01-01" && breach.breachDate !== new Date().toISOString().split("T")[0]
                              ? ` | Date: ${new Date(breach.breachDate).toLocaleDateString()}`
                              : ""}
                          </CardDescription>
                        </div>
                        <Badge variant="outline" className="font-mono text-xs border-primary/30 text-primary bg-primary/10">
                          {breach.riskLevel.toUpperCase()} RISK
                        </Badge>
                      </div>
                    </CardHeader>
                    <Separator className="bg-border/50" />
                    <CardContent className="py-4">
                      <p className="text-sm text-muted-foreground mb-4 line-clamp-2">{breach.description}</p>
                      <div className="flex flex-wrap gap-2">
                        {breach.dataClasses.map((dc, i) => (
                          <Badge key={i} variant="secondary" className="font-mono text-[10px] bg-secondary/80">
                            {dc}
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          ) : scanResult.breachCount === 0 ? (
            <Card className="bg-primary/5 border-primary/20">
              <CardContent className="py-12 flex flex-col items-center justify-center text-center">
                <CheckCircle className="w-16 h-16 text-primary mb-4 opacity-80" />
                <h3 className="font-display text-2xl font-semibold mb-2">No Breaches Detected</h3>
                <p className="font-mono text-muted-foreground max-w-md">
                  The target identifier ({scanResult.query}) does not appear in any known data breaches in our database.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              <p className="font-mono text-sm text-destructive flex items-center bg-destructive/10 p-3 rounded border border-destructive/20">
                <AlertTriangle className="w-4 h-4 mr-2" />
                Detected in {scanResult.breachCount} known data breaches exposing {scanResult.exposedDataTypes.length} unique data types.
              </p>
              
              <div className="grid grid-cols-1 gap-4">
                {scanResult.breaches.map((breach, idx) => (
                  <Card key={idx} className="bg-card/60 border-destructive/20 relative overflow-hidden">
                    <div className="absolute left-0 top-0 bottom-0 w-1 bg-destructive/50" />
                    <CardHeader className="py-4">
                      <div className="flex justify-between items-start">
                        <div>
                          <CardTitle className="font-display font-semibold text-lg">{breach.name}</CardTitle>
                          <CardDescription className="font-mono text-xs mt-1">Domain: {breach.domain} | Date: {new Date(breach.breachDate).toLocaleDateString()}</CardDescription>
                        </div>
                        <Badge variant="outline" className="font-mono text-xs border-destructive/30 text-destructive bg-destructive/10">
                          {breach.riskLevel.toUpperCase()} RISK
                        </Badge>
                      </div>
                    </CardHeader>
                    <Separator className="bg-border/50" />
                    <CardContent className="py-4">
                      <p className="text-sm text-muted-foreground mb-4 line-clamp-2">{breach.description}</p>
                      <div className="flex flex-wrap gap-2">
                        {breach.dataClasses.map((dc, i) => (
                          <Badge key={i} variant="secondary" className="font-mono text-[10px] bg-secondary/80">
                            {dc}
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {!advisorResponse && scanResult.breachCount > 0 && (
            <div className="flex justify-center pt-8">
              <Button 
                onClick={generateRemediationPlan}
                disabled={isGeneratingPlan}
                size="lg"
                className="font-display uppercase tracking-widest bg-accent text-accent-foreground hover:bg-accent/90"
              >
                {isGeneratingPlan ? (
                  <span className="flex items-center">
                    <Cpu className="w-4 h-4 mr-2 animate-spin" />
                    Generating AI Plan...
                  </span>
                ) : (
                  <span className="flex items-center">
                    <Cpu className="w-4 h-4 mr-2" />
                    Generate AI Remediation Plan
                  </span>
                )}
              </Button>
            </div>
          )}
{aiPlan && (
  <Card className="mt-6 border-accent/20">
    <CardHeader>
      <CardTitle className="text-accent">
        AI Remediation Plan
      </CardTitle>
    </CardHeader>
    <CardContent className="prose prose-invert max-w-none">
  <ReactMarkdown remarkPlugins={[remarkGfm]}>
    {aiPlan}
  </ReactMarkdown>
</CardContent>
  </Card>
)}
          {advisorResponse && (
            <div className="mt-12 space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <h2 className="font-display text-xl font-bold tracking-wide flex items-center text-accent">
                <Shield className="w-5 h-5 mr-2" />
                AI Security Advisor Plan
              </h2>

              <Card className="bg-accent/5 border-accent/20">
                <CardHeader>
                  <CardTitle className="font-display text-lg text-accent">Threat Assessment</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4 font-mono text-sm leading-relaxed">
                  <p>{advisorResponse.overallAssessment}</p>
                  <p className="text-muted-foreground border-l-2 border-accent/30 pl-4 py-1">{advisorResponse.riskSummary}</p>
                </CardContent>
              </Card>

              <div className="space-y-4">
                <h3 className="font-display font-semibold text-lg mt-8 mb-4">Recommended Actions</h3>
                {advisorResponse.recommendations.map((rec, idx) => (
                  <Card key={idx} className="bg-card/40 border-border/50">
                    <CardHeader className="pb-3">
                      <div className="flex justify-between items-start">
                        <div className="flex items-center gap-3">
                          <Badge variant="outline" className={`font-mono text-[10px] uppercase
                            ${rec.priority === 'urgent' ? 'border-destructive text-destructive bg-destructive/10' : ''}
                            ${rec.priority === 'high' ? 'border-orange-500 text-orange-500 bg-orange-500/10' : ''}
                            ${rec.priority === 'medium' ? 'border-yellow-500 text-yellow-500 bg-yellow-500/10' : ''}
                            ${rec.priority === 'low' ? 'border-primary text-primary bg-primary/10' : ''}
                          `}>
                            {rec.priority}
                          </Badge>
                          <Badge variant="secondary" className="font-mono text-[10px] uppercase">
                            {rec.category}
                          </Badge>
                        </div>
                      </div>
                      <CardTitle className="font-display text-md mt-3">{rec.title}</CardTitle>
                      <CardDescription className="font-mono mt-1">{rec.description}</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ul className="space-y-2 mt-2">
                        {rec.actionSteps.map((step, i) => (
                          <li key={i} className="flex items-start font-mono text-sm">
                            <span className="text-accent mr-2 mt-0.5">›</span>
                            <span className="text-muted-foreground">{step}</span>
                          </li>
                        ))}
                      </ul>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {showReportModal && scanResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="bg-[#0b101d] border border-primary/30 rounded-xl max-w-3xl w-full p-8 space-y-6 text-foreground shadow-2xl relative my-8">
            <button
              onClick={() => setShowReportModal(false)}
              className="absolute top-4 right-4 text-muted-foreground hover:text-foreground p-2 rounded-lg"
            >
              <X className="w-5 h-5" />
            </button>

            <div id="executive-security-report" className="space-y-6">
              <div className="border-b border-primary/20 pb-4 flex justify-between items-start">
                <div>
                  <div className="flex items-center gap-2">
                    <Shield className="w-7 h-7 text-primary" />
                    <span className="font-display font-bold text-2xl tracking-wider text-primary">PRIVACY GUARD</span>
                  </div>
                  <p className="text-xs font-mono text-muted-foreground uppercase tracking-widest mt-1">
                    Executive Cybersecurity Audit Report
                  </p>
                </div>
                <div className="text-right font-mono text-xs text-muted-foreground">
                  <div>Report ID: PG-AUDIT-{scanResult.id}</div>
                  <div>Date: {new Date(scanResult.scannedAt).toLocaleString()}</div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 p-4 rounded-lg bg-secondary/30 border border-border/50">
                <div>
                  <span className="text-xs font-mono uppercase text-muted-foreground">Target Identifier</span>
                  <div className="font-mono text-lg font-semibold text-foreground">{scanResult.query}</div>
                  <span className="text-xs font-mono text-primary uppercase">Target Type: {scanResult.type}</span>
                </div>
                <div className="text-right">
                  <span className="text-xs font-mono uppercase text-muted-foreground">Risk Assessment</span>
                  <div className="font-mono text-2xl font-bold text-primary">{scanResult.riskScore} / 100</div>
                  <Badge variant={scanResult.breachCount > 0 ? "destructive" : "default"} className="font-mono text-xs mt-1">
                    {scanResult.riskLevel.toUpperCase()} RISK
                  </Badge>
                </div>
              </div>

              <div className="space-y-3">
                <h4 className="font-display text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                  Detected Breach Exposures ({scanResult.breachCount})
                </h4>
                {scanResult.breaches.length === 0 ? (
                  <p className="font-mono text-sm text-primary">✓ No data breach exposures detected for this identifier.</p>
                ) : (
                  <div className="border border-border/50 rounded-lg overflow-hidden">
                    <table className="w-full text-left font-mono text-xs">
                      <thead className="bg-secondary/50 border-b border-border/50 text-muted-foreground uppercase">
                        <tr>
                          <th className="p-3">Source / Breach Name</th>
                          <th className="p-3">Breach Date</th>
                          <th className="p-3">Risk Level</th>
                          <th className="p-3">Exposed Data</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/30">
                        {scanResult.breaches.map((b, i) => (
                          <tr key={i} className="hover:bg-secondary/20">
                            <td className="p-3 font-semibold text-foreground">{b.name}</td>
                            <td className="p-3 text-muted-foreground">{new Date(b.breachDate).toLocaleDateString()}</td>
                            <td className="p-3">
                              <span className="text-destructive font-bold uppercase">{b.riskLevel}</span>
                            </td>
                            <td className="p-3 text-muted-foreground">{b.dataClasses.join(", ")}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {(aiPlan || advisorResponse) && (
                <div className="space-y-3 border-t border-primary/20 pt-4">
                  <h4 className="font-display text-sm font-semibold uppercase tracking-wider text-accent">
                    AI Security Recommendations & Remediation Plan
                  </h4>
                  {advisorResponse?.overallAssessment && (
                    <p className="font-mono text-xs text-muted-foreground leading-relaxed">
                      {advisorResponse.overallAssessment}
                    </p>
                  )}
                  {aiPlan && (
                    <div className="font-mono text-xs text-slate-300 bg-secondary/20 p-3 rounded border border-border/30 max-h-48 overflow-y-auto">
                      <ReactMarkdown remarkPlugins={[remarkGfm]}>{aiPlan}</ReactMarkdown>
                    </div>
                  )}
                </div>
              )}

              <div className="border-t border-border/40 pt-4 text-center font-mono text-[10px] text-muted-foreground">
                Privacy Guard Automated Threat Intelligence Report • Generated for Security Compliance
              </div>
            </div>

            <div className="flex justify-end space-x-3 border-t border-border/50 pt-4">
              <Button variant="secondary" onClick={() => setShowReportModal(false)} className="font-mono text-xs">
                Close
              </Button>
              <Button onClick={() => window.print()} className="font-mono text-xs bg-primary text-primary-foreground">
                <Printer className="w-4 h-4 mr-2" /> Print / Save as PDF
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
