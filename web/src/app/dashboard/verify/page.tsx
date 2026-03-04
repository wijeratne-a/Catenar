"use client";

import { useState } from "react";
import { useForm, useFieldArray } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useVerifyTrace } from "@/lib/api";
import { toast } from "sonner";
import type { VerifyResponse, PotReceipt } from "@/lib/types";

const traceEntrySchema = z.object({
  action: z.string().min(1),
  target: z.string().min(1),
  amount: z.union([z.coerce.number(), z.literal("")]).optional(),
  table: z.string().optional(),
});

const verifyFormSchema = z.object({
  domain: z.enum(["defi", "enterprise"]),
  policy_commitment: z.string().min(1),
  trace_entries: z.array(traceEntrySchema),
  max_spend: z.union([z.coerce.number().positive(), z.literal("")]).optional(),
  restricted_endpoints_str: z.string(),
});

type VerifyForm = z.infer<typeof verifyFormSchema>;

function formatTimestamp(ns: number) {
  const ms = ns / 1e6;
  return new Date(ms).toISOString();
}

function PotReceiptCard({ proof }: { proof: PotReceipt }) {
  return (
    <Card className="border-emerald-500/30 bg-emerald-500/5">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-emerald-400">
          <Badge variant="success">Valid</Badge>
          Digital Certificate (PoT Receipt)
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 font-mono text-sm">
        <div>
          <span className="text-muted-foreground">policy_commitment:</span>
          <pre className="mt-1 break-all rounded bg-muted/50 p-2">{proof.policy_commitment}</pre>
        </div>
        <div>
          <span className="text-muted-foreground">trace_hash:</span>
          <pre className="mt-1 break-all rounded bg-muted/50 p-2">{proof.trace_hash}</pre>
        </div>
        <div>
          <span className="text-muted-foreground">timestamp_ns:</span>
          <pre className="mt-1 rounded bg-muted/50 p-2">{proof.timestamp_ns}</pre>
        </div>
        <div>
          <span className="text-muted-foreground">signature:</span>
          <pre className="mt-1 break-all rounded bg-muted/50 p-2">{proof.signature}</pre>
        </div>
        <div>
          <span className="text-muted-foreground">public_key:</span>
          <pre className="mt-1 break-all rounded bg-muted/50 p-2">{proof.public_key}</pre>
        </div>
      </CardContent>
    </Card>
  );
}

export default function VerifyPlaygroundPage() {
  const [recentResults, setRecentResults] = useState<VerifyResponse[]>([]);
  const verifyMutation = useVerifyTrace();

  const {
    register,
    control,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
  } = useForm<VerifyForm>({
    resolver: zodResolver(verifyFormSchema),
    defaultValues: {
      domain: "defi",
      policy_commitment: "",
      trace_entries: [{ action: "api_call", target: "https://dex.api/swap", amount: 500 }],
      max_spend: 1000,
      restricted_endpoints_str: "/admin",
    },
  });

  const { fields, append, remove } = useFieldArray({ control, name: "trace_entries" });
  const domain = watch("domain");

  async function onSubmit(data: VerifyForm) {
    const entries = data.trace_entries.map((e) => ({
      action: e.action,
      target: e.target,
      amount: e.amount !== "" && !isNaN(Number(e.amount)) ? Number(e.amount) : undefined,
      table: e.table || undefined,
    }));

    const payload = {
      agent_metadata: { domain: data.domain, version: "1.0" },
      policy_commitment: data.policy_commitment,
      execution_trace: entries,
      public_values: {
        max_spend:
          data.domain === "defi" && data.max_spend && !isNaN(Number(data.max_spend))
            ? Number(data.max_spend)
            : undefined,
        restricted_endpoints:
          data.restricted_endpoints_str.trim()
            ? data.restricted_endpoints_str.split(",").map((s) => s.trim()).filter(Boolean)
            : undefined,
      },
    };

    try {
      const result = await verifyMutation.mutateAsync(payload);
      setRecentResults((prev) => [result, ...prev].slice(0, 10));
      if (result.valid) {
        toast.success("Verification succeeded");
      } else {
        toast.error(result.reason ?? "Verification failed");
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Verification failed");
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold">Verification Playground</h1>
      <p className="mt-2 text-muted-foreground">
        Build a trace, submit for verification, and view the PoT receipt or violation reason.
      </p>

      <Card className="mt-8">
        <CardHeader>
          <CardTitle>Build a Trace</CardTitle>
          <CardDescription>
            Add trace entries. For DeFi use action/target/amount. For Enterprise use table.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
            <div className="space-y-2">
              <Label>Domain</Label>
              <div className="flex gap-4">
                {(["defi", "enterprise"] as const).map((d) => (
                  <label key={d} className="flex items-center gap-2">
                    <input type="radio" value={d} {...register("domain")} className="rounded border-input" />
                    <span className="capitalize">{d}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="policy_commitment">Policy Commitment</Label>
              <Input
                id="policy_commitment"
                placeholder="0x..."
                className="font-mono"
                {...register("policy_commitment")}
              />
              {errors.policy_commitment && (
                <p className="text-sm text-destructive">{errors.policy_commitment.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label>Public Values (must match registered policy)</Label>
              <div className="grid gap-2 md:grid-cols-2">
                {domain === "defi" && (
                  <div>
                    <Label className="text-xs">max_spend</Label>
                    <Input type="number" step="0.01" {...register("max_spend")} />
                  </div>
                )}
                <div>
                  <Label className="text-xs">restricted_endpoints (comma-separated)</Label>
                  <Input
                    placeholder="/admin,salary"
                    {...register("restricted_endpoints_str")}
                  />
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Trace Entries</Label>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => append({ action: "", target: "", amount: "", table: "" })}
                >
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              <div className="space-y-4">
                {fields.map((_, idx) => (
                  <div key={idx} className="rounded-lg border border-border/50 p-4 space-y-2">
                    <div className="flex justify-between">
                      <span className="text-sm font-medium">Entry {idx + 1}</span>
                      <Button type="button" variant="ghost" size="sm" onClick={() => remove(idx)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                    <div className="grid gap-2 sm:grid-cols-2 md:grid-cols-4">
                      <div>
                        <Label className="text-xs">action</Label>
                        <Input placeholder="api_call" {...register(`trace_entries.${idx}.action`)} />
                      </div>
                      <div>
                        <Label className="text-xs">target</Label>
                        <Input placeholder="https://dex.api/swap" {...register(`trace_entries.${idx}.target`)} />
                      </div>
                      {domain === "defi" && (
                        <div>
                          <Label className="text-xs">amount</Label>
                          <Input type="number" step="0.01" {...register(`trace_entries.${idx}.amount`)} />
                        </div>
                      )}
                      {domain === "enterprise" && (
                        <div>
                          <Label className="text-xs">table</Label>
                          <Input placeholder="inventory" {...register(`trace_entries.${idx}.table`)} />
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <Button type="submit" disabled={verifyMutation.isPending}>
              {verifyMutation.isPending ? "Verifying..." : "Verify Trace"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {verifyMutation.isPending && (
        <Card className="mt-8">
          <CardHeader>
            <CardTitle>Verifying</CardTitle>
          </CardHeader>
          <CardContent>
            <Skeleton className="h-24 w-full" />
            <Skeleton className="mt-2 h-16 w-full" />
          </CardContent>
        </Card>
      )}

      {verifyMutation.isSuccess && verifyMutation.data && !verifyMutation.data.valid && (
        <Card className="mt-8 border-destructive/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Badge variant="destructive">Security Violation</Badge>
            </CardTitle>
            <CardDescription>{verifyMutation.data.reason}</CardDescription>
          </CardHeader>
        </Card>
      )}

      {verifyMutation.isSuccess && verifyMutation.data?.valid && verifyMutation.data.proof && (
        <div className="mt-8">
          <PotReceiptCard proof={verifyMutation.data.proof} />
        </div>
      )}

      <section className="mt-8">
        <h2 className="text-lg font-semibold">Live Feed (Recent Verifications)</h2>
        <p className="text-sm text-muted-foreground">Last 10 verification results</p>
        <div className="mt-4 space-y-4">
          {recentResults.length === 0 ? (
            <p className="text-sm text-muted-foreground">No verifications yet.</p>
          ) : (
            recentResults.map((r, i) => (
              <Card key={i} className={r.valid ? "border-emerald-500/20" : "border-destructive/30"}>
                <CardContent className="pt-6">
                  {r.valid && r.proof ? (
                    <div className="space-y-2">
                      <Badge variant="success">Valid</Badge>
                      <pre className="font-mono text-xs text-muted-foreground">
                        trace_hash: {r.proof.trace_hash}
                      </pre>
                    </div>
                  ) : (
                    <div>
                      <Badge variant="destructive">Violation</Badge>
                      <p className="mt-2 text-sm">{r.reason}</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
