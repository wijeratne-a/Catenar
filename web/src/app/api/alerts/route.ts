import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/auth";
import { listAlerts } from "@/lib/alert-store";
import { classifyViolation } from "@/lib/severity";
import { ensureStartupValidation } from "@/lib/startup";

export async function GET(request: NextRequest) {
  ensureStartupValidation();

  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const limit = Math.min(
    Math.max(1, Number.parseInt(request.nextUrl.searchParams.get("limit") ?? "50", 10) || 50),
    200
  );
  const offset = Math.max(0, Number.parseInt(request.nextUrl.searchParams.get("offset") ?? "0", 10) || 0);
  const domain = request.nextUrl.searchParams.get("domain") ?? undefined;

  const { items, total } = listAlerts({ limit, offset, domain });
  const alerts = items.map((a) => ({
    ...a,
    severity: classifyViolation(a.reason).toString(),
  }));

  return NextResponse.json({
    alerts,
    total,
    nextOffset: offset + limit < total ? offset + limit : undefined,
  });
}
