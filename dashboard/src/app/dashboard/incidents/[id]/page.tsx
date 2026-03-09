"use client";

import { useParams, useRouter } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useIncident } from "@/lib/api";
import { sanitizeForDisplay } from "@/lib/sanitize";
import { severityColor, ViolationSeverity } from "@/lib/severity";
import { ArrowLeft, CheckCircle, Copy, Download, ShieldOff, AlertTriangle } from "lucide-react";
import Link from "next/link";

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const incidentId = typeof params.id === "string" ? params.id : null;

  const { data: incident, isLoading, isError } = useIncident(incidentId);

  if (!incidentId) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Incident Not Found</h1>
        <p className="mt-2 text-muted-foreground">No incident ID provided.</p>
        <Button asChild variant="outline" className="mt-4">
          <Link href="/dashboard/alerts">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Alerts
          </Link>
        </Button>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Incident Details</h1>
        <Card className="mt-8">
          <CardHeader>
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-64" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-24 w-full" />
            <Skeleton className="mt-2 h-24 w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isError || !incident) {
    return (
      <div>
        <h1 className="text-2xl font-bold">Incident Not Found</h1>
        <p className="mt-2 text-muted-foreground">
          Incident {sanitizeForDisplay(incidentId)} could not be found or may have expired.
        </p>
        <Button asChild variant="outline" className="mt-4">
          <Link href="/dashboard/alerts">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Alerts
          </Link>
        </Button>
      </div>
    );
  }

  const handleMarkResolved = () => {
    window.alert("Demo: Incident marked as resolved. In production, this would update the SOC ticket.");
  };

  const handleExportToSOC = () => {
    const exportData = {
      incident_id: incident.incident_id,
      event: incident.event,
      domain: incident.domain,
      reason: incident.reason,
      policy_commitment: incident.policy_commitment,
      received_at: incident.received_at,
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegis-incident-${incident.incident_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyIncidentId = () => {
    void navigator.clipboard.writeText(incident.incident_id ?? "");
    window.alert("Demo: Incident ID copied to clipboard.");
  };

  const handleQuarantineAgent = () => {
    window.alert("Demo: Agent quarantine requested. In production, this would revoke the agent certificate.");
  };

  const handleEscalateToSOC = () => {
    const incidentUrl = window.location.href;
    void navigator.clipboard.writeText(incidentUrl);
    window.alert("Demo: Incident URL copied to clipboard. Ready to paste into SOC ticket.");
  };

  const policyLabel =
    incident.reason?.toLowerCase().includes("instruction") ||
    incident.reason?.toLowerCase().includes("injection")
      ? "Response injection"
      : incident.reason?.toLowerCase().includes("restricted") ||
        incident.reason?.toLowerCase().includes("endpoint")
        ? "Restricted endpoint"
        : incident.reason ?? "Policy violation";

  return (
    <div>
      <div className="mb-4 flex items-center gap-2">
        <Button asChild variant="ghost" size="sm">
          <Link href="/dashboard/alerts">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Alerts
          </Link>
        </Button>
      </div>

      <h1 className="text-2xl font-bold">Incident Details</h1>
      <p className="mt-2 text-muted-foreground">
        Full forensic context for incident {sanitizeForDisplay(incident.incident_id)}. Use this view to investigate and
        remediate policy violations.
      </p>

      <Card className="mt-8">
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="font-mono">
              {incident.incident_id}
            </Badge>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={handleCopyIncidentId}
              title="Copy incident ID"
            >
              <Copy className="h-3.5 w-3.5" />
            </Button>
            <Badge className={severityColor(incident.severity as ViolationSeverity)}>
              {incident.severity}
            </Badge>
          </CardTitle>
          <CardDescription>
            Detected {formatTime(incident.received_at)}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Reason</span>
            <p className="mt-1 font-mono text-sm">{sanitizeForDisplay(incident.reason)}</p>
          </div>
          <div>
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Domain</span>
            <p className="mt-1 font-mono text-sm">{sanitizeForDisplay(incident.domain)}</p>
          </div>
          <div>
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Event</span>
            <p className="mt-1 font-mono text-sm">{sanitizeForDisplay(incident.event)}</p>
          </div>
          <div>
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Policy Commitment
            </span>
            <pre className="mt-1 break-all rounded bg-muted/50 p-2 font-mono text-xs">
              {sanitizeForDisplay(incident.policy_commitment)}
            </pre>
          </div>
          <div>
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Timestamp (ns)
            </span>
            <p className="mt-1 font-mono text-sm">{incident.timestamp_ns}</p>
          </div>
        </CardContent>
      </Card>

      <Card className="mt-6 border-amber-500/30 bg-amber-50/50 dark:border-amber-500/20 dark:bg-amber-950/20">
        <CardHeader>
          <CardTitle className="text-base">Policy & Evidence</CardTitle>
          <CardDescription>Summary of what was blocked and where</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Violated rule
            </span>
            <p className="mt-1 text-sm">{policyLabel}</p>
          </div>
          <div>
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Evidence
            </span>
            <p className="mt-1 text-sm">
              Blocked request to {sanitizeForDisplay(incident.domain)} at {formatTime(incident.received_at)}.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card className="mt-6 border-blue-500/30 bg-blue-50/50 dark:border-blue-500/20 dark:bg-blue-950/20">
        <CardHeader>
          <CardTitle className="text-base">Recommended Next Steps</CardTitle>
          <CardDescription>Quick actions for this incident</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button onClick={handleQuarantineAgent} variant="destructive" size="sm">
            <ShieldOff className="mr-2 h-4 w-4" />
            Quarantine Agent (Revoke Cert)
          </Button>
          <Button onClick={handleExportToSOC} variant="outline" size="sm">
            <Download className="mr-2 h-4 w-4" />
            Download Forensic Package
          </Button>
          <Button onClick={handleEscalateToSOC} variant="outline" size="sm">
            <AlertTriangle className="mr-2 h-4 w-4" />
            Escalate to SOC
          </Button>
        </CardContent>
      </Card>

      <div className="mt-6 flex flex-wrap gap-2">
        <Button onClick={handleMarkResolved} variant="default">
          <CheckCircle className="mr-2 h-4 w-4" />
          Mark Resolved
        </Button>
        <Button onClick={handleExportToSOC} variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Export to SOC Ticket
        </Button>
      </div>
    </div>
  );
}
