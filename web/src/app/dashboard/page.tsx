"use client";

import Link from "next/link";
import { Shield, FileCode, Terminal, Activity, User, FileSpreadsheet, AlertTriangle, Users, Plug } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useReceipts } from "@/lib/api";
import type { PotReceipt } from "@/lib/types";

const quickLinks = [
  { href: "/dashboard/policy", label: "Policy Builder", icon: Shield, desc: "Register policies and get policy commitments" },
  { href: "/dashboard/receipts", label: "Receipts", icon: FileCode, desc: "View proof receipts from sidecar proxies" },
  { href: "/dashboard/alerts", label: "Alerts", icon: AlertTriangle, desc: "Policy violations reported via webhook" },
  { href: "/dashboard/agents", label: "Agents", icon: Users, desc: "Registered agent registry (admin)" },
  { href: "/dashboard/compliance", label: "Compliance", icon: FileSpreadsheet, desc: "Export org-scoped audit logs in JSON or CSV" },
  { href: "/dashboard/integrations", label: "Integrations", icon: Terminal, desc: "SDK snippets and webhook configuration" },
];

function truncateHash(hash: string, len = 12): string {
  if (hash.length <= len) return hash;
  return `${hash.slice(0, len)}...`;
}

function formatReceiptTime(ns: number): string {
  const ms = ns / 1e6;
  const date = new Date(ms);
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function CompactReceiptCard({ receipt }: { receipt: PotReceipt }) {
  return (
    <Card className="border-border/50">
      <CardContent className="flex items-center gap-4 py-3">
        <Activity className="h-4 w-4 shrink-0 text-primary" />
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">
              {formatReceiptTime(receipt.timestamp_ns)}
            </span>
            {receipt.identity_hash && (
              <Badge variant="outline" className="gap-1 px-1.5 py-0 text-[10px]">
                <User className="h-3 w-3" />
                ID
              </Badge>
            )}
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-xs">
            <span>
              <span className="text-muted-foreground">policy:</span>{" "}
              {truncateHash(receipt.policy_commitment)}
            </span>
            <span>
              <span className="text-muted-foreground">trace:</span>{" "}
              {truncateHash(receipt.trace_hash)}
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function RecentInterceptions() {
  const { data, isLoading, isError } = useReceipts();

  const now = Date.now();
  const dayAgoMs = now - 24 * 60 * 60 * 1000;
  const recentCount = data?.filter((entry) => {
    const entryMs = entry.value.timestamp_ns / 1e6;
    return entryMs >= dayAgoMs;
  }).length ?? 0;

  const latest = data?.slice(0, 5) ?? [];

  if (isLoading) {
    return (
      <section className="mt-8 space-y-3">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </section>
    );
  }

  if (isError) {
    return null;
  }

  return (
    <section className="mt-8">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Recent Interceptions</h2>
        <Badge variant="secondary" className="font-mono text-xs">
          {recentCount} receipt{recentCount !== 1 ? "s" : ""} in last 24h
        </Badge>
      </div>
      <p className="mt-1 text-sm text-muted-foreground">
        Live feed from sidecar proxies (auto-refresh every 5s)
      </p>
      <div className="mt-4 space-y-2">
        {latest.length === 0 ? (
          <p className="text-sm text-muted-foreground">No receipts yet.</p>
        ) : (
          latest.map((entry) => (
            <CompactReceiptCard key={entry.value.receipt_id} receipt={entry.value} />
          ))
        )}
      </div>
      {data && data.length > 5 && (
        <Link
          href="/dashboard/receipts"
          className="mt-3 inline-block text-sm text-primary underline underline-offset-4"
        >
          View all {data.length} receipts
        </Link>
      )}
    </section>
  );
}

export default function DashboardPage() {
  return (
    <div>
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <p className="mt-2 text-muted-foreground">
        Welcome to the Aegis Playground. Choose a tool to get started.
      </p>

      <RecentInterceptions />

      <div className="mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {quickLinks.map(({ href, label, icon: Icon, desc }) => (
          <Link key={href} href={href}>
            <Card className="transition-colors hover:bg-accent/50">
              <CardHeader>
                <Icon className="h-8 w-8 text-primary" />
                <CardTitle>{label}</CardTitle>
                <CardDescription>{desc}</CardDescription>
              </CardHeader>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
