import { NextResponse } from "next/server";
import { getSession } from "@/lib/auth";
import { ensureStartupValidation } from "@/lib/startup";

export async function GET() {
  ensureStartupValidation();

  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (session.role !== "admin") {
    return NextResponse.json({ error: "Admin role required" }, { status: 403 });
  }

  const verifierUrl =
    (process.env.VERIFIER_URL ?? "http://127.0.0.1:3000").replace(/\/$/, "") + "/v1/agents";

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Aegis-Role": "admin",
  };
  if (process.env.VERIFIER_API_KEY) {
    headers["Authorization"] = `Bearer ${process.env.VERIFIER_API_KEY}`;
  }

  try {
    const res = await fetch(verifierUrl, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      const text = await res.text();
      console.error("[api/agents] verifier error:", res.status, text);
      return NextResponse.json(
        { error: "Failed to fetch agents from verifier" },
        { status: res.status >= 500 ? 502 : res.status }
      );
    }

    const agents = await res.json();
    return NextResponse.json({ agents });
  } catch (err) {
    console.error("[api/agents] fetch failed:", err);
    return NextResponse.json(
      { error: "Verifier unavailable" },
      { status: 502 }
    );
  }
}
