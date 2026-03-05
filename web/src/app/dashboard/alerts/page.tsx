"use client";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useAlerts } from "@/lib/api";
import { sanitizeForDisplay } from "@/lib/sanitize";
import { severityColor, ViolationSeverity } from "@/lib/severity";

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function truncateHash(hash: string, len = 16): string {
  if (hash.length <= len) return hash;
  return `${hash.slice(0, len)}...`;
}

export default function AlertsPage() {
  const { data, isLoading, isError } = useAlerts();

  if (isLoading) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Policy Alerts</h1>
        <p className="mt-2 text-muted-foreground">
          Policy violations reported by the verifier via webhook.
        </p>
        <Card className="mt-8">
          <CardHeader>
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-64" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-24 w-full" />
            <Skeleton className="mt-2 h-24 w-full" />
            <Skeleton className="mt-2 h-24 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isError) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Policy Alerts</h1>
        <Card className="mt-8 border-destructive/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Badge variant="destructive">Load Error</Badge>
            </CardTitle>
            <CardDescription>
              Failed to load alerts. Ensure you are authenticated.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const alerts = data?.alerts ?? [];
  const total = data?.total ?? 0;

  return (
    <div>
      <h1 className="text-2xl font-bold">Policy Alerts</h1>
      <p className="mt-2 text-muted-foreground">
        Policy violations reported by the verifier via webhook. Configure WEBHOOK_URL and WEBHOOK_SECRET
        in the verifier to send events to <code className="font-mono text-xs">/api/alerts/ingest</code>.
      </p>

      <Card className="mt-8">
        <CardHeader>
          <CardTitle>Recent Violations</CardTitle>
          <CardDescription>
            {total} alert{total !== 1 ? "s" : ""} (auto-refresh every 10s)
          </CardDescription>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <p className="text-sm text-muted-foreground">No alerts yet.</p>
          ) : (
            <div className="space-y-4">
              {alerts.map((a) => (
                <div
                  key={a.id}
                  className="rounded-lg border border-border/50 bg-muted/20 p-4"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className={severityColor(a.severity as ViolationSeverity)}>
                      {a.severity}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {formatTime(a.received_at)}
                    </span>
                  </div>
                  <p className="mt-2 font-mono text-sm">{sanitizeForDisplay(a.reason)}</p>
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    <span>
                      <span className="font-medium">domain:</span> {sanitizeForDisplay(a.domain)}
                    </span>
                    <span>
                      <span className="font-medium">policy:</span> {sanitizeForDisplay(truncateHash(a.policy_commitment))}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
