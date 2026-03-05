import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/auth";
import { potReceiptSchema } from "@/lib/schemas";
import { checkReceiptIngestLimit, getTrustedIp } from "@/lib/rate-limit";
import { createHash, timingSafeEqual } from "crypto";
import { listReceiptsByOrg, pushReceipt } from "@/lib/receipt-store";
import { ensureStartupValidation } from "@/lib/startup";
const MAX_BODY_BYTES = 64 * 1024; // 64 KB

type AuthResult =
  | { ok: true }
  | { ok: false; status: 401 }
  | { ok: false; status: 503 };

/** Parse optional per-org tokens: SIDECAR_INGEST_TOKENS='{"org1":"token1","org2":"token2"}' */
function getPerOrgTokens(): Record<string, string> | null {
  const raw = process.env.SIDECAR_INGEST_TOKENS;
  if (!raw || raw.length < 10) return null;
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const result: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (typeof v === "string" && v.length >= 32) result[k] = v;
    }
    return Object.keys(result).length > 0 ? result : null;
  } catch {
    return null;
  }
}

function isAuthorizedSidecar(request: NextRequest): AuthResult & { orgId?: string } {
  const token = request.headers.get("x-aegis-ingest-token") ?? "";
  const orgFromHeader =
    request.headers.get("x-aegis-org-id") ??
    request.headers.get("x-aegis-tenant-id") ??
    null;

  const perOrg = getPerOrgTokens();
  if (perOrg && orgFromHeader) {
    const expected = perOrg[orgFromHeader.trim()];
    if (expected) {
      const a = Buffer.from(expected, "utf8");
      const b = Buffer.from(token, "utf8");
      if (a.length === b.length) {
        try {
          if (timingSafeEqual(a, b)) return { ok: true, orgId: orgFromHeader.trim() };
        } catch {
          /* fall through */
        }
      }
      return { ok: false, status: 401 };
    }
  }

  const expected = process.env.SIDECAR_INGEST_TOKEN;
  if (!expected || expected.length < 32) {
    return { ok: false, status: 503 };
  }
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

function getOrgIdFromToken(token: string): string | null {
  if (!token || !token.includes(".")) return null;
  const b64Part = token.split(".")[0]?.trim();
  if (!b64Part) return null;
  try {
    const decoded = Buffer.from(b64Part, "base64url").toString("utf8");
    return decoded || null;
  } catch {
    return null;
  }
}

function getOrgIdFromIngestHeaders(request: NextRequest, token: string | null): string {
  if (token) {
    const orgIdFromToken = getOrgIdFromToken(token);
    if (orgIdFromToken != null) return orgIdFromToken;
  }
  const orgId =
    request.headers.get("x-aegis-org-id") ??
    request.headers.get("x-aegis-tenant-id") ??
    request.headers.get("x-aegis-user-id");
  return orgId?.trim() || "default";
}

function getReceiptRateLimitKey(request: NextRequest, orgId: string): string {
  const token = request.headers.get("x-aegis-ingest-token");
  if (token) {
    const hash = createHash("sha256").update(token).digest("hex").slice(0, 16);
    return `receipt:${orgId}:${hash}`;
  }
  const ip = getTrustedIp(request);
  return `receipt:${orgId}:${ip}`;
}

export async function POST(request: NextRequest) {
  ensureStartupValidation();

  const auth = isAuthorizedSidecar(request);
  if (!auth.ok) {
    const msg =
      auth.status === 503
        ? "Receipt ingest not configured (SIDECAR_INGEST_TOKEN required, min 32 chars)"
        : "Unauthorized sidecar ingest";
    return NextResponse.json({ error: msg }, { status: auth.status });
  }

  const token = request.headers.get("x-aegis-ingest-token");
  const orgId =
    auth.orgId ?? getOrgIdFromIngestHeaders(request, token);
  const rateKey = getReceiptRateLimitKey(request, orgId);
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

  pushReceipt(orgId, parsed.data);
  return NextResponse.json({ status: "ok" });
}

export async function GET(request: NextRequest) {
  ensureStartupValidation();

  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const orgId = session.org_id || "default";
  const filtered = listReceiptsByOrg(orgId);

  const limit = Math.min(
    Math.max(1, Number.parseInt(request.nextUrl.searchParams.get("limit") ?? "50", 10) || 50),
    200
  );
  const offset = Math.max(0, Number.parseInt(request.nextUrl.searchParams.get("offset") ?? "0", 10) || 0);
  const paginated = filtered.slice(offset, offset + limit);

  return NextResponse.json({
    receipts: paginated,
    total: filtered.length,
    nextOffset: offset + limit < filtered.length ? offset + limit : undefined,
  });
}
