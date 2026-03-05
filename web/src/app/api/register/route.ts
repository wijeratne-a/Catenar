import { NextRequest, NextResponse } from "next/server";
import { registerPolicySchema } from "@/lib/schemas";
import { getSession } from "@/lib/auth";
import { checkRateLimit, getTrustedIdentifier } from "@/lib/rate-limit";
import { blake3Commitment, publishCommitment } from "@/lib/anchor";
import { pushPolicyHistory } from "@/lib/policy-history";
import { ensureStartupValidation } from "@/lib/startup";

const MAX_PAYLOAD_BYTES = 1024 * 1024; // 1MB
const policies = new Map<string, unknown>();

function policyStorageKey(orgId: string, commitment: string): string {
  return `${orgId}:${commitment}`;
}

function getRateLimitKey(request: NextRequest, session: { username: string } | null): string {
  if (session?.username) return `register:${session.username}`;
  return getTrustedIdentifier(request, "register");
}

export async function POST(request: NextRequest) {
  ensureStartupValidation();

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

  if (parsed.data.rego_policy !== undefined) {
    const rego = parsed.data.rego_policy;
    if (rego.length > 100000) {
      return NextResponse.json(
        { error: "Rego policy exceeds maximum size of 100KB" },
        { status: 400 }
      );
    }
    const forbidden =
      /http\.send/.test(rego) ||
      /crypto\.x509\.parse_certificates?/.test(rego) ||
      /walk\s*\(/.test(rego);
    if (forbidden) {
      return NextResponse.json(
        { error: "Rego policy contains forbidden pattern" },
        { status: 400 }
      );
    }
  }

  try {
    const commitment = await blake3Commitment(parsed.data);
    const verifierUrl =
      (process.env.VERIFIER_URL ?? "http://127.0.0.1:3000").replace(/\/$/, "") +
      "/v1/register";
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (process.env.VERIFIER_API_KEY) {
      headers["Authorization"] = `Bearer ${process.env.VERIFIER_API_KEY}`;
    }
    try {
      const verifierRes = await fetch(verifierUrl, {
        method: "POST",
        headers,
        body: JSON.stringify(parsed.data),
        signal: AbortSignal.timeout(5000),
      });
      if (!verifierRes.ok) {
        throw new Error("Verifier policy registration failed");
      }
    } catch (verifierErr) {
      console.error("[api/register] verifier failed:", verifierErr);
      return NextResponse.json(
        { error: "Verifier policy registration failed" },
        { status: 502 }
      );
    }
    const orgId = session.org_id || "default";
    const key = policyStorageKey(orgId, commitment);
    const anchor = await publishCommitment(commitment, {
      username: session.username,
      org_id: orgId,
      policy_storage_key: key,
      source: "dashboard-policy-builder",
    });

    policies.set(key, parsed.data);
    pushPolicyHistory({
      policy_commitment: commitment,
      policy_storage_key: key,
      org_id: orgId,
    });
    return NextResponse.json({
      policy_commitment: commitment,
      policy_storage_key: key,
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
