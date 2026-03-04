import { NextRequest, NextResponse } from "next/server";
import { registerPolicySchema } from "@/lib/schemas";
import { getSession } from "@/lib/auth";
import { checkRateLimit } from "@/lib/rate-limit";

const MAX_PAYLOAD_BYTES = 1024 * 1024; // 1MB

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

  const baseUrl = process.env.VERIFIER_API_URL ?? "http://127.0.0.1:3000";
  const url = `${baseUrl.replace(/\/$/, "")}/v1/register`;

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed.data),
    });
    const data = await res.json();

    if (!res.ok) {
      return NextResponse.json(
        data ?? { error: "Verifier error" },
        { status: res.status }
      );
    }

    return NextResponse.json(data);
  } catch (err) {
    console.error("[api/register] proxy error:", err);
    return NextResponse.json(
      { error: "Failed to reach verifier" },
      { status: 502 }
    );
  }
}
