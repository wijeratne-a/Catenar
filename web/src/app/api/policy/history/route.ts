import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/auth";
import { listPolicyHistory } from "@/lib/policy-history";
import { ensureStartupValidation } from "@/lib/startup";

export async function GET(request: NextRequest) {
  ensureStartupValidation();

  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const orgId = session.org_id || "default";
  const limit = Math.min(
    Math.max(1, Number.parseInt(request.nextUrl.searchParams.get("limit") ?? "50", 10) || 50),
    200
  );
  const offset = Math.max(0, Number.parseInt(request.nextUrl.searchParams.get("offset") ?? "0", 10) || 0);

  const items = listPolicyHistory({ limit, offset, org_id: orgId });

  return NextResponse.json({
    history: items,
    nextOffset: offset + limit,
  });
}
