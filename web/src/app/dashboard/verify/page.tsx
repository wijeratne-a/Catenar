"use client";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useReceipts } from "@/lib/api";
import type { PotReceipt } from "@/lib/types";

function formatTimestamp(ns: number) {
  const ms = ns / 1e6;
  return new Date(ms).toISOString();
}

function PotReceiptCard({ proof }: { proof: PotReceipt }) {
  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Badge variant="secondary">Receipt</Badge>
          {proof.receipt_id}
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
        {proof.identity_hash && (
          <div>
            <span className="text-muted-foreground">identity_hash:</span>
            <pre className="mt-1 break-all rounded bg-muted/50 p-2">{proof.identity_hash}</pre>
          </div>
        )}
        <div>
          <span className="text-muted-foreground">timestamp_ns:</span>
          <pre className="mt-1 rounded bg-muted/50 p-2">{formatTimestamp(proof.timestamp_ns)}</pre>
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

export default function ReceiptViewerPage() {
  const receiptsQuery = useReceipts();
  return (
    <div>
      <h1 className="text-2xl font-bold">Receipts</h1>
      <p className="mt-2 text-muted-foreground">
        Control plane view of proof receipts reported by local sidecars. Raw traces never enter the dashboard.
      </p>

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

      <section className="mt-8">
        <h2 className="text-lg font-semibold">Live Feed</h2>
        <p className="text-sm text-muted-foreground">Recent sidecar receipts (auto-refresh every 5s)</p>
        <div className="mt-4 space-y-4">
          {!receiptsQuery.data || receiptsQuery.data.length === 0 ? (
            <p className="text-sm text-muted-foreground">No receipts yet.</p>
          ) : (
            receiptsQuery.data.map((entry) => (
              <div key={entry.value.receipt_id} className="space-y-2">
                <p className="text-xs text-muted-foreground">received_at: {entry.received_at}</p>
                <PotReceiptCard proof={entry.value} />
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
