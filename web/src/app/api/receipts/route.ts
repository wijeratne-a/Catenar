import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/auth";
import { potReceiptSchema } from "@/lib/schemas";
import { checkReceiptIngestLimit } from "@/lib/rate-limit";
import { createHash, timingSafeEqual } from "crypto";

type StoredReceipt = {
  received_at: string;
  tenant_id: string;
  value: unknown;
};

const receipts: StoredReceipt[] = [];
const MAX_RECEIPTS = 1000;
const MAX_BODY_BYTES = 64 * 1024; // 64 KB

type AuthResult =
  | { ok: true }
  | { ok: false; status: 401 }
  | { ok: false; status: 503 };

function isAuthorizedSidecar(request: NextRequest): AuthResult {
  const expected = process.env.SIDECAR_INGEST_TOKEN;
  if (!expected || expected.length < 32) {
    return { ok: false, status: 503 };
  }
  const token = request.headers.get("x-aegis-ingest-token") ?? "";
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(token, "utf8");
  if (a.length !== b.length) {
    return { ok: false, status: 401 };
  }
  try {
    const ok = timingSafeEqual(a, b);
    return ok ? { ok: true } : { ok: false, status: 401 };
  } catch {
    return { ok: false, status: 401 };
  }
}

function getTenantId(request: NextRequest): string {
  const tenant = request.headers.get("x-aegis-tenant-id") ?? request.headers.get("x-aegis-user-id");
  return tenant?.trim() || "default";
}

function getReceiptRateLimitKey(request: NextRequest, tenantId: string): string {
  const token = request.headers.get("x-aegis-ingest-token");
  if (token) {
    const hash = createHash("sha256").update(token).digest("hex").slice(0, 16);
    return `receipt:${tenantId}:${hash}`;
  }
  const forwarded = request.headers.get("x-forwarded-for");
  const ip = forwarded ? forwarded.split(",")[0]?.trim() : request.headers.get("x-real-ip");
  return `receipt:${tenantId}:${ip ?? "unknown"}`;
}

export async function POST(request: NextRequest) {
  const auth = isAuthorizedSidecar(request);
  if (!auth.ok) {
    const msg =
      auth.status === 503
        ? "Receipt ingest not configured (SIDECAR_INGEST_TOKEN required, min 32 chars)"
        : "Unauthorized sidecar ingest";
    return NextResponse.json({ error: msg }, { status: auth.status });
  }

  const tenantId = getTenantId(request);
  const rateKey = getReceiptRateLimitKey(request, tenantId);
  const { allowed } = checkReceiptIngestLimit(rateKey);
  if (!allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again later." },
      { status: 429 }
    );
  }

  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) {
    return NextResponse.json(
      { error: "Payload too large (max 64 KB)" },
      { status: 413 }
    );
  }

  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const parsed = potReceiptSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid receipt payload" }, { status: 400 });
  }

  receipts.unshift({
    received_at: new Date().toISOString(),
    tenant_id: tenantId,
    value: parsed.data,
  });
  if (receipts.length > MAX_RECEIPTS) {
    receipts.length = MAX_RECEIPTS;
  }
  return NextResponse.json({ status: "ok" });
}

export async function GET(request: NextRequest) {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const tenantId = session.username;
  const filtered = receipts.filter((r) => r.tenant_id === tenantId);

  const limit = Math.min(
    Math.max(1, parseInt(request.nextUrl.searchParams.get("limit") ?? "50", 10)),
    200
  );
  const offset = Math.max(0, parseInt(request.nextUrl.searchParams.get("offset") ?? "0", 10));
  const paginated = filtered.slice(offset, offset + limit);

  return NextResponse.json({
    receipts: paginated,
    total: filtered.length,
    nextOffset: offset + limit < filtered.length ? offset + limit : undefined,
  });
}
