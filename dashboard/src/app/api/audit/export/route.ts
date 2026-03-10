import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/auth";
import { computeExportHash, listReceiptsByOrg } from "@/lib/receipt-store";
import { ensureStartupValidation } from "@/lib/startup";

function toCsv(rows: Array<Record<string, unknown>>): string {
  if (rows.length === 0) {
    return "received_at,org_id,receipt_id,policy_commitment,trace_hash,timestamp_ns\n";
  }
  const headers = [
    "received_at",
    "org_id",
    "receipt_id",
    "policy_commitment",
    "trace_hash",
    "timestamp_ns",
  ];
  const escape = (value: unknown) => {
    const text = value == null ? "" : String(value);
    if (text.includes(",") || text.includes('"') || text.includes("\n")) {
      return `"${text.replaceAll('"', '""')}"`;
    }
    return text;
  };
  const lines = rows.map((row) => headers.map((h) => escape(row[h])).join(","));
  return `${headers.join(",")}\n${lines.join("\n")}\n`;
}

export async function GET(request: NextRequest) {
  ensureStartupValidation();

  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if ((session as { role?: string }).role !== "admin") {
    return NextResponse.json(
      { error: "Admin role required for audit export" },
      { status: 403 }
    );
  }

  const formatParam = (request.nextUrl.searchParams.get("format") ?? "json").toLowerCase();
  if (formatParam !== "json" && formatParam !== "csv") {
    return NextResponse.json({ error: "format must be json or csv" }, { status: 400 });
  }

  const rangeParam = request.nextUrl.searchParams.get("range") ?? "all";
  const sinceParam = request.nextUrl.searchParams.get("since");
  const untilParam = request.nextUrl.searchParams.get("until");

  let since: Date | null = null;
  let until: Date | null = null;
  if (rangeParam === "24h") {
    until = new Date();
    since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  } else if (rangeParam === "7d") {
    until = new Date();
    since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  } else if (sinceParam || untilParam) {
    if (sinceParam) since = new Date(sinceParam);
    if (untilParam) until = new Date(untilParam);
  }

  const orgId = session.org_id || "default";
  let entries = listReceiptsByOrg(orgId);
  if (since || until) {
    entries = entries.filter((entry) => {
      const t = new Date(entry.received_at).getTime();
      if (since && t < since.getTime()) return false;
      if (until && t > until.getTime()) return false;
      return true;
    });
  }

  const rows = entries.map((entry) => {
    const receipt = (entry.value ?? {}) as Record<string, unknown>;
    return {
      received_at: entry.received_at,
      org_id: entry.org_id,
      receipt_id: receipt.receipt_id,
      policy_commitment: receipt.policy_commitment,
      trace_hash: receipt.trace_hash,
      timestamp_ns: receipt.timestamp_ns,
    };
  });

  if (formatParam === "csv") {
    const csv = toCsv(rows);
    const hash = computeExportHash(csv);
    return new NextResponse(csv, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="audit-export-${orgId}.csv"`,
        "X-Catenar-Export-Hash": hash,
      },
    });
  }

  const payload = { org_id: orgId, exported_at: new Date().toISOString(), rows };
  const hash = computeExportHash(payload);
  return NextResponse.json(payload, {
    headers: {
      "X-Catenar-Export-Hash": hash,
    },
  });
}
