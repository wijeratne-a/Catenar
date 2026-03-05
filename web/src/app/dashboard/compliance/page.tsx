"use client";

import { Download, History } from "lucide-react";
import { useSession, usePolicyHistory } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

function ExportButton({ format, label }: { format: "json" | "csv"; label: string }) {
  const href = `/api/audit/export?format=${format}`;
  return (
    <a href={href} target="_blank" rel="noreferrer">
      <Button variant="outline" className="w-full justify-start sm:w-auto">
        <Download className="mr-2 h-4 w-4" />
        {label}
      </Button>
    </a>
  );
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function truncateHash(hash: string, len = 16): string {
  if (hash.length <= len) return hash;
  return `${hash.slice(0, len)}...`;
}

export default function CompliancePage() {
  const sessionQuery = useSession();
  const historyQuery = usePolicyHistory();
  const orgId = sessionQuery.data?.org_id ?? "default";

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Compliance Dashboard</h1>
        <p className="mt-2 text-muted-foreground">
          Export proof receipt audit trails and view policy registration history scoped to your organization.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Audit Export</CardTitle>
          <CardDescription>
            Current scope: <code className="font-mono">{orgId}</code>
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 sm:flex-row">
          <ExportButton format="json" label="Download JSON export" />
          <ExportButton format="csv" label="Download CSV export" />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <History className="h-5 w-5" />
            Policy History
          </CardTitle>
          <CardDescription>
            Recent policy registrations for <code className="font-mono">{orgId}</code>
          </CardDescription>
        </CardHeader>
        <CardContent>
          {historyQuery.isLoading && (
            <Skeleton className="h-24 w-full" />
          )}
          {historyQuery.isError && (
            <p className="text-sm text-muted-foreground">Failed to load policy history.</p>
          )}
          {historyQuery.data?.history && historyQuery.data.history.length === 0 && (
            <p className="text-sm text-muted-foreground">No policy registrations yet.</p>
          )}
          {historyQuery.data?.history && historyQuery.data.history.length > 0 && (
            <div className="space-y-2">
              {historyQuery.data.history.slice(0, 10).map((h) => (
                <div
                  key={`${h.policy_commitment}-${h.created_at}`}
                  className="flex flex-wrap items-center gap-2 rounded border border-border/50 bg-muted/20 px-3 py-2 text-sm"
                >
                  <span className="font-mono text-xs">{truncateHash(h.policy_commitment)}</span>
                  <span className="text-muted-foreground">{formatTime(h.created_at)}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
