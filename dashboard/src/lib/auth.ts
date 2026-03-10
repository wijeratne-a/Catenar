import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";
import { auth as getOidcSession } from "@/auth";
import { resolveOrgFromUsername, resolveRoleFromUsername } from "./auth-claims";

const COOKIE_NAME = "catenar_session";
const MAX_AGE = 60 * 60 * 24; // 24 hours

function getSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET is not set");
  return new TextEncoder().encode(secret);
}

export type UserRole = "admin" | "auditor";

export interface JwtPayload {
  sub: string;
  username: string;
  role: UserRole;
  org_id: string;
  auth_source?: "demo" | "oidc";
  iat: number;
  exp: number;
}

export function resolveRole(username: string): UserRole {
  return resolveRoleFromUsername(username);
}

export function resolveOrgId(username: string): string {
  return resolveOrgFromUsername(username);
}

export async function createSession(username: string, role?: UserRole, orgId?: string): Promise<string> {
  const effectiveRole = role ?? resolveRole(username);
  const effectiveOrgId = orgId ?? resolveOrgId(username);
  const token = await new SignJWT({ username, role: effectiveRole, org_id: effectiveOrgId, auth_source: "demo" })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(username)
    .setIssuedAt()
    .setExpirationTime(`${MAX_AGE}s`)
    .sign(getSecret());
  return token;
}

export async function verifySession(token: string): Promise<JwtPayload | null> {
  try {
    const { payload } = await jwtVerify(token, getSecret(), { algorithms: ["HS256"] });
    return payload as unknown as JwtPayload;
  } catch {
    return null;
  }
}

export async function getSession(): Promise<JwtPayload | null> {
  const cookieStore = await cookies();
  const token = cookieStore.get(COOKIE_NAME)?.value;
  if (token) {
    const local = await verifySession(token);
    if (local) return local;
  }

  const oidcSession = await getOidcSession();
  if (!oidcSession) return null;

  const sessionRecord = oidcSession as unknown as Record<string, unknown>;
  const usernameCandidate =
    (sessionRecord.username as string | undefined) ??
    oidcSession.user?.name ??
    oidcSession.user?.email ??
    undefined;
  if (!usernameCandidate) return null;

  const roleCandidate = sessionRecord.role === "admin" ? "admin" : "auditor";
  const orgCandidate =
    typeof sessionRecord.org_id === "string" && sessionRecord.org_id.trim()
      ? sessionRecord.org_id
      : resolveOrgId(usernameCandidate);

  const now = Math.floor(Date.now() / 1000);
  return {
    sub: usernameCandidate,
    username: usernameCandidate,
    role: roleCandidate,
    org_id: orgCandidate,
    auth_source: "oidc",
    iat: now,
    exp: now + MAX_AGE,
  };
}

export function getSessionCookieConfig() {
  return {
    name: COOKIE_NAME,
    options: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict" as const,
      maxAge: MAX_AGE,
      path: "/",
    },
  };
}
