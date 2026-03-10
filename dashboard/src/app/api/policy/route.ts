import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/auth";

const PROXY_URL =
  process.env.CATENAR_PROXY_URL || "http://127.0.0.1:8080";

export async function GET() {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const res = await fetch(`${PROXY_URL}/policy/current`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      return NextResponse.json(
        { error: "Proxy returned non-OK status" },
        { status: res.status }
      );
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json(
      { error: "Failed to reach proxy" },
      { status: 502 }
    );
  }
}

export async function POST(request: NextRequest) {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const role = (session as { role?: string }).role ?? "auditor";
  if (role !== "admin") {
    return NextResponse.json(
      { error: "Only admins can push policy reloads" },
      { status: 403 }
    );
  }

  void request;

  try {
    const res = await fetch(`${PROXY_URL}/policy/reload`, {
      method: "POST",
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      return NextResponse.json(
        { error: "Proxy reload failed" },
        { status: res.status }
      );
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json(
      { error: "Failed to reach proxy for reload" },
      { status: 502 }
    );
  }
}
