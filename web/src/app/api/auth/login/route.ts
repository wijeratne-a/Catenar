import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { createSession, getSessionCookieConfig } from "@/lib/auth";
import { checkLoginLimit } from "@/lib/rate-limit";

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

function getLoginRateLimitKey(request: NextRequest): string {
  const forwarded = request.headers.get("x-forwarded-for");
  const ip = forwarded ? forwarded.split(",")[0]?.trim() : request.headers.get("x-real-ip");
  return `login:${ip ?? "unknown"}`;
}

export async function POST(request: NextRequest) {
  const rateKey = getLoginRateLimitKey(request);
  const { allowed } = checkLoginLimit(rateKey);
  if (!allowed) {
    return NextResponse.json(
      { error: "Too many login attempts. Try again later." },
      { status: 429 }
    );
  }

  const body = await request.json().catch(() => ({}));
  const parsed = loginSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request. username and password required." },
      { status: 400 }
    );
  }

  const { username, password } = parsed.data;

  const allowDemo = process.env.ALLOW_DEMO_LOGIN === "true" || process.env.ALLOW_DEMO_LOGIN === "1";
  if (!allowDemo) {
    return NextResponse.json(
      {
        error:
          "Configure real auth. Production must use IdP or credential store. Set ALLOW_DEMO_LOGIN=true only for local demo.",
      },
      { status: 401 }
    );
  }

  // Simulated auth: accept any non-empty credentials for demo (only when ALLOW_DEMO_LOGIN)
  if (!username || !password) {
    return NextResponse.json(
      { error: "Invalid credentials" },
      { status: 401 }
    );
  }

  const token = await createSession(username);
  const { name, options } = getSessionCookieConfig();

  const response = NextResponse.json({ ok: true, username });
  response.cookies.set(name, token, options);
  return response;
}
