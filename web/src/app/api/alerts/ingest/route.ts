import { NextRequest, NextResponse } from "next/server";
import { createHmac, timingSafeEqual } from "crypto";
import { policyViolationWebhookSchema } from "@/lib/schemas";
import { pushAlert } from "@/lib/alert-store";
import { ensureStartupValidation } from "@/lib/startup";

const MAX_BODY_BYTES = 16 * 1024; // 16 KB

function validateWebhookSignature(request: NextRequest, body: Buffer): boolean {
  const secret = process.env.WEBHOOK_SECRET;
  if (!secret || secret.length < 32) {
    return false;
  }
  const signature = request.headers.get("x-aegis-signature");
  if (!signature || !signature.startsWith("sha256=")) {
    return false;
  }
  const expectedHex = signature.slice(7).trim();
  if (expectedHex.length !== 64 || !/^[a-f0-9]+$/i.test(expectedHex)) {
    return false;
  }
  const mac = createHmac("sha256", secret);
  mac.update(body);
  const computed = mac.digest();
  const expected = Buffer.from(expectedHex, "hex");
  if (expected.length !== computed.length) return false;
  try {
    return timingSafeEqual(expected, computed);
  } catch {
    return false;
  }
}

export async function POST(request: NextRequest) {
  ensureStartupValidation();

  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) {
    return NextResponse.json({ error: "Payload too large" }, { status: 413 });
  }

  const body = Buffer.from(raw, "utf8");
  if (!validateWebhookSignature(request, body)) {
    return NextResponse.json({ error: "Invalid webhook signature" }, { status: 401 });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const result = policyViolationWebhookSchema.safeParse(parsed);
  if (!result.success) {
    return NextResponse.json({ error: "Invalid webhook payload" }, { status: 400 });
  }

  pushAlert({
    event: result.data.event,
    policy_commitment: result.data.policy_commitment,
    domain: result.data.domain,
    reason: result.data.reason,
    timestamp_ns: result.data.timestamp_ns,
  });

  return NextResponse.json({ status: "ok" }, { status: 202 });
}
