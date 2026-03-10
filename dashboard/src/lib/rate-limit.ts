import type { NextRequest } from "next/server";

/**
 * Returns the trusted client IP, mitigating X-Forwarded-For spoofing.
 * When TRUST_PROXY=true, use the LAST entry in x-forwarded-for (trusted proxy appends real IP).
 * Otherwise use x-real-ip or "unknown".
 */
export function getTrustedIp(request: NextRequest): string {
  if (process.env.TRUST_PROXY === "true" || process.env.TRUST_PROXY === "1") {
    const forwarded = request.headers.get("x-forwarded-for");
    if (forwarded) {
      const parts = forwarded.split(",").map((p) => p.trim()).filter(Boolean);
      const last = parts[parts.length - 1];
      if (last) return last;
    }
  }
  const ip =
    request.headers.get("x-real-ip") ??
    (typeof (request as { ip?: string }).ip === "string" ? (request as { ip?: string }).ip : undefined);
  return ip ?? "unknown";
}

/**
 * Returns a rate-limit key with trusted IP identifier.
 */
export function getTrustedIdentifier(request: NextRequest, prefix: string): string {
  const ip = getTrustedIp(request);
  return `${prefix}:${ip}`;
}

/**
 * In-memory sliding-window rate limiter.
 *
 * PRODUCTION NOTE -- Distributed Rate Limiting with Redis
 * -------------------------------------------------------
 * This in-memory implementation works for single-instance deployments. For
 * production clusters with multiple replicas, replace with a Redis-backed
 * sliding window using MULTI/EXEC + ZRANGEBYSCORE (sorted-set pattern) or
 * the token-bucket Lua script approach.
 *
 * When REDIS_URL is set in the environment, install `ioredis` and swap the
 * Map-based store below for Redis sorted sets keyed by identifier. Example:
 *
 *   import Redis from "ioredis";
 *   const redis = new Redis(process.env.REDIS_URL);
 *   // ZADD <key> <now> <now>   -- add timestamp
 *   // ZREMRANGEBYSCORE <key> 0 <now - windowMs>  -- trim old
 *   // ZCARD <key>              -- count in window
 *   // EXPIRE <key> <windowSec> -- auto-cleanup
 *
 * The docker-compose stack and Helm chart include a Redis service gated
 * behind `redis.enabled`. Set REDIS_URL=redis://catenar-redis:6379 in the
 * deployment environment to activate it.
 *
 * When behind a trusted proxy, configure trust proxy and use a single
 * forwarded header only (e.g. X-Forwarded-For) to mitigate spoofing.
 */

const windowMs = 60 * 1000; // 1 minute
const MAX_TRACKED_KEYS = 50_000;
const MAX_ENTRIES_PER_KEY = 60;

const timestamps = new Map<string, number[]>();

function cleanup(now: number) {
  for (const [key, times] of timestamps.entries()) {
    const within = times.filter((t) => now - t < windowMs);
    if (within.length === 0) {
      timestamps.delete(key);
    } else {
      timestamps.set(key, within);
    }
  }
}

setInterval(() => cleanup(Date.now()), 30_000);

function checkLimit(
  identifier: string,
  maxRequests: number
): { allowed: boolean; remaining: number } {
  const now = Date.now();

  const times = timestamps.get(identifier) ?? [];
  const withinWindow = times.filter((t) => now - t < windowMs);

  if (withinWindow.length >= maxRequests) {
    return { allowed: false, remaining: 0 };
  }

  if (timestamps.size >= MAX_TRACKED_KEYS && !timestamps.has(identifier)) {
    return { allowed: false, remaining: 0 };
  }

  if (withinWindow.length >= MAX_ENTRIES_PER_KEY) {
    withinWindow.shift();
  }
  withinWindow.push(now);
  timestamps.set(identifier, withinWindow);
  return { allowed: true, remaining: maxRequests - withinWindow.length };
}

/** 30/min per identifier (register, verify). */
export function checkRateLimit(identifier: string): { allowed: boolean; remaining: number } {
  return checkLimit(identifier, 30);
}

/** 60/min per identifier (receipt ingest). */
export function checkReceiptIngestLimit(identifier: string): {
  allowed: boolean;
  remaining: number;
} {
  return checkLimit(identifier, 60);
}

/** 5/min per IP (login). */
export function checkLoginLimit(identifier: string): { allowed: boolean; remaining: number } {
  return checkLimit(identifier, 5);
}
