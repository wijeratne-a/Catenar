"use client";

import Link from "next/link";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useReceipts, useSession } from "@/lib/api";
import { getHumanContext, formatAgentIdFallback } from "@/lib/demo-identity-labels";
import { sanitizeForDisplay } from "@/lib/sanitize";
import type { PotReceipt } from "@/lib/types";

const SSN_RE = /\b(\d{3})-(\d{2})-(\d{4})\b/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g;

function maskSensitiveData(value: string): string {
  return value
    .replace(SSN_RE, (_match, _g1, _g2, last4) => `***-**-${last4}`)
    .replace(EMAIL_RE, (_match, domain) => `***@${domain}`);
}

function formatTimestamp(ns: number) {
  const ms = ns / 1e6;
  return new Date(ms).toISOString();
}

function MaskedText({ text, masked }: { text: string; masked: boolean }) {
  const display = masked ? maskSensitiveData(text) : text;
  return <pre className="mt-1 break-all rounded bg-muted/50 p-2">{sanitizeForDisplay(display)}</pre>;
}

function PotReceiptCard({
  proof,
  masked,
  receivedAt,
  sameAgentCount,
}: {
  proof: PotReceipt;
  masked: boolean;
  receivedAt?: string;
  sameAgentCount?: number;
}) {
  const hasIdentity = proof.agent_id != null || proof.identity_hash != null;
  const humanContext = proof.agent_id ? getHumanContext(proof.agent_id) : null;
  const actorDisplay = humanContext
    ? `${humanContext.displayName} (${humanContext.role})`
    : proof.agent_id
      ? formatAgentIdFallback(proof.agent_id)
      : null;
  const sessionTime = receivedAt ?? (proof.timestamp_ns ? formatTimestamp(proof.timestamp_ns) : null);

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <Badge variant="secondary">Receipt</Badge>
          <Badge className="bg-green-600/15 text-green-700 border border-green-600/30">Verified</Badge>
          <MaskedText text={proof.receipt_id} masked={masked} />
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 font-mono text-sm">
        {sameAgentCount != null && sameAgentCount > 0 && (
          <p className="text-xs text-muted-foreground">
            Activity: {sameAgentCount} receipt{sameAgentCount !== 1 ? "s" : ""} from this agent in this view
          </p>
        )}
        {actorDisplay && (
          <div className="rounded border border-blue-500/30 bg-blue-50/50 p-3 dark:border-blue-500/20 dark:bg-blue-950/20">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Human Context
            </span>
            <div className="mt-2 flex flex-wrap gap-4">
              <div>
                <span className="text-xs text-muted-foreground">Actor</span>
                <p className="mt-0.5 font-medium">{sanitizeForDisplay(actorDisplay)}</p>
              </div>
              {sessionTime && (
                <div>
                  <span className="text-xs text-muted-foreground">Session</span>
                  <p className="mt-0.5 text-sm">{sanitizeForDisplay(sessionTime)}</p>
                </div>
              )}
              {humanContext && (
                <div>
                  <span className="text-xs text-muted-foreground">Authorization level</span>
                  <p className="mt-0.5 text-sm">{sanitizeForDisplay(humanContext.tierOrTeam)}</p>
                </div>
              )}
            </div>
          </div>
        )}
        {hasIdentity && (
          <div className="rounded border border-border/50 bg-accent/20 p-3">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Identity Context
            </span>
            <p className="mt-1 text-xs text-muted-foreground">
              Human identity cryptographically bound to this receipt
            </p>
            <div className="mt-2 space-y-2">
              {proof.agent_id && (
                <div>
                  <span className="flex items-center gap-2 text-muted-foreground">
                    agent_id:
                    <Badge variant="outline" className="text-xs">
                      Agent
                    </Badge>
                  </span>
                  <pre className="mt-1 break-all rounded bg-muted/50 p-2">{sanitizeForDisplay(proof.agent_id)}</pre>
                </div>
              )}
              {proof.identity_hash && (
                <div>
                  <span className="flex items-center gap-2 text-muted-foreground">
                    identity_hash:
                    <Badge variant="outline" className="text-xs">
                      BLAKE3-bound
                    </Badge>
                  </span>
                  <pre className="mt-1 break-all rounded bg-muted/50 p-2">{sanitizeForDisplay(proof.identity_hash)}</pre>
                </div>
              )}
            </div>
          </div>
        )}
        {proof.reasoning_summary && (
          <div className="rounded border border-border/50 bg-accent/20 p-3">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Agent Reasoning
            </span>
            <p className="mt-1 text-sm">{sanitizeForDisplay(proof.reasoning_summary)}</p>
          </div>
        )}
        <div>
          <span className="text-muted-foreground">policy_commitment:</span>
          <pre className="mt-1 break-all rounded bg-muted/50 p-2">{sanitizeForDisplay(proof.policy_commitment)}</pre>
        </div>
        <div>
          <span className="flex items-center gap-2 text-muted-foreground">
            trace_hash:
            <Badge variant="outline" className="text-xs">BLAKE3</Badge>
          </span>
          <pre className="mt-1 break-all rounded bg-muted/50 p-2">{sanitizeForDisplay(proof.trace_hash)}</pre>
        </div>
        {proof.identity_hash && !hasIdentity && (
          <div>
            <span className="text-muted-foreground">identity_hash:</span>
            <pre className="mt-1 break-all rounded bg-muted/50 p-2">{sanitizeForDisplay(proof.identity_hash)}</pre>
          </div>
        )}
        {proof.combined_hash && (
          <div>
            <span className="text-muted-foreground">combined_hash:</span>
            <pre className="mt-1 break-all rounded bg-muted/50 p-2">{sanitizeForDisplay(proof.combined_hash)}</pre>
          </div>
        )}
        <div>
          <span className="text-muted-foreground">timestamp_ns:</span>
          <pre className="mt-1 rounded bg-muted/50 p-2">{formatTimestamp(proof.timestamp_ns)}</pre>
        </div>
        <div>
          <span className="flex items-center gap-2 text-muted-foreground">
            signature:
            <Badge variant="outline" className="text-xs">Ed25519</Badge>
          </span>
          <pre className="mt-1 break-all rounded bg-muted/50 p-2">{sanitizeForDisplay(proof.signature)}</pre>
        </div>
        <div>
          <span className="text-muted-foreground">public_key:</span>
          <pre className="mt-1 break-all rounded bg-muted/50 p-2">{sanitizeForDisplay(proof.public_key)}</pre>
        </div>
      </CardContent>
    </Card>
  );
}

export default function ReceiptsPage() {
  const receiptsQuery = useReceipts();
  const sessionQuery = useSession();
  const isAdmin = sessionQuery.data?.role === "admin";
  const [showRaw, setShowRaw] = useState(false);
  const masked = !showRaw;

  return (
    <div>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Proof Receipts</h1>
          <p className="mt-2 text-muted-foreground">
            Control plane view of proof receipts reported by local sidecars. Raw traces never enter the dashboard.
          </p>
        </div>
        {isAdmin && (
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setShowRaw((prev) => !prev)}
          >
            {showRaw ? "Mask PII" : "Show raw"}
          </Button>
        )}
      </div>

      {receiptsQuery.isLoading && (
        <Card className="mt-8">
          <CardHeader>
            <CardTitle>Loading Receipts</CardTitle>
          </CardHeader>
          <CardContent>
            <Skeleton className="h-24 w-full" />
            <Skeleton className="mt-2 h-16 w-full" />
          </CardContent>
        </Card>
      )}

      {receiptsQuery.isError && (
        <Card className="mt-8 border-destructive/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Badge variant="destructive">Load Error</Badge>
            </CardTitle>
            <CardDescription>
              {receiptsQuery.error instanceof Error ? receiptsQuery.error.message : "Failed to load receipts."}
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      <p className="mt-4 text-sm text-muted-foreground">
        <Link href="/dashboard/alerts" className="underline hover:text-foreground">
          View policy alerts
        </Link>{" "}
        | Recent incidents
      </p>

      <section className="mt-8">
        <h2 className="text-lg font-semibold">Live Feed</h2>
        <p className="text-sm text-muted-foreground">Recent sidecar receipts (auto-refresh every 5s)</p>
        <div className="mt-4 space-y-4">
          {!receiptsQuery.data || receiptsQuery.data.length === 0 ? (
            <p className="text-sm text-muted-foreground">No receipts yet.</p>
          ) : (
            receiptsQuery.data.map((entry) => {
              const sameAgentCount =
                entry.value.agent_id != null
                  ? receiptsQuery.data!.filter((e) => e.value.agent_id === entry.value.agent_id).length
                  : undefined;
              return (
                <div key={entry.value.receipt_id} className="space-y-2">
                  <p className="text-xs text-muted-foreground">
                    received_at: {masked ? maskSensitiveData(entry.received_at) : entry.received_at}
                  </p>
                  <PotReceiptCard
                    proof={entry.value}
                    masked={masked}
                    receivedAt={entry.received_at}
                    sameAgentCount={sameAgentCount}
                  />
                </div>
              );
            })
          )}
        </div>
      </section>
    </div>
  );
}
