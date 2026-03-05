import { NextRequest, NextResponse } from "next/server";
import { registerPolicySchema } from "@/lib/schemas";
import { getSession } from "@/lib/auth";
import { checkRateLimit } from "@/lib/rate-limit";
import { blake3Commitment, publishCommitment } from "@/lib/anchor";

const MAX_PAYLOAD_BYTES = 1024 * 1024; // 1MB
const policies = new Map<string, unknown>();

function getRateLimitKey(request: NextRequest, session: { username: string } | null): string {
  if (session?.username) return `register:${session.username}`;
  const forwarded = request.headers.get("x-forwarded-for");
  const ip = forwarded ? forwarded.split(",")[0]?.trim() : request.headers.get("x-real-ip");
  return `register:${ip ?? "unknown"}`;
}

export async function POST(request: NextRequest) {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const identifier = getRateLimitKey(request, session);
  const { allowed } = checkRateLimit(identifier);
  if (!allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again later." },
      { status: 429 }
    );
  }

  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf8") > MAX_PAYLOAD_BYTES) {
    return NextResponse.json(
      { error: "Payload too large (max 1MB)" },
      { status: 413 }
    );
  }

  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const parsed = registerPolicySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request" },
      { status: 400 }
    );
  }

  try {
    const commitment = await blake3Commitment(parsed.data);
    const anchor = await publishCommitment(commitment, {
      username: session.username,
      source: "dashboard-policy-builder",
    });

    policies.set(commitment, parsed.data);
    return NextResponse.json({
      policy_commitment: commitment,
      anchor_url: anchor.anchor_url,
      anchored_at: anchor.anchored_at,
    });
  } catch (err) {
    console.error("[api/register] failed:", err);
    return NextResponse.json(
      { error: "Failed to register policy commitment" },
      { status: 502 }
    );
  }
}
