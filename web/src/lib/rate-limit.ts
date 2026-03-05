/**
 * In-memory sliding-window rate limiter.
 * In production, use Redis or Upstash for distributed rate limiting across
 * instances. When behind a trusted proxy, configure trust proxy and use a
 * single forwarded header only (e.g. X-Forwarded-For) to mitigate spoofing.
 */

const windowMs = 60 * 1000; // 1 minute

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

function checkLimit(
  identifier: string,
  maxRequests: number
): { allowed: boolean; remaining: number } {
  const now = Date.now();
  cleanup(now);

  const times = timestamps.get(identifier) ?? [];
  const withinWindow = times.filter((t) => now - t < windowMs);

  if (withinWindow.length >= maxRequests) {
    return { allowed: false, remaining: 0 };
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
