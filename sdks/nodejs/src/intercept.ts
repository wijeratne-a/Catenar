/**
 * Aegis intercept module - monkey-patches http.request, https.request, and axios
 * to emit trace entries to the Aegis verifier.
 *
 * Import this module before any HTTP client to enable automatic tracing.
 * Set HTTP_PROXY and HTTPS_PROXY for proxy routing.
 */

import * as http from "http";
import * as https from "https";
import { Aegis } from "./index";
import type { ClientRequest, IncomingMessage, RequestOptions } from "http";

const AEGIS_BASE_URL = process.env.AEGIS_BASE_URL ?? "http://127.0.0.1:3000";
const DEFAULT_PROXY = process.env.AEGIS_PROXY ?? "http://127.0.0.1:8080";

// Set proxy from env if not already set
if (!process.env.HTTP_PROXY && !process.env.http_proxy) {
  process.env.HTTP_PROXY = DEFAULT_PROXY;
}
if (!process.env.HTTPS_PROXY && !process.env.https_proxy) {
  process.env.HTTPS_PROXY = DEFAULT_PROXY;
}

let aegisInstance: Aegis | null = null;

function getAegis(): Aegis {
  if (!aegisInstance) {
    aegisInstance = new Aegis({ baseUrl: AEGIS_BASE_URL });
  }
  return aegisInstance;
}

export function getAegisInstance(): Aegis {
  return getAegis();
}

function buildUrl(options: string | RequestOptions | URL, defaultProtocol = "https:"): string {
  if (typeof options === "string") {
    return options;
  }
  if (options instanceof URL) {
    return options.toString();
  }
  const protocol = (options as RequestOptions & { protocol?: string }).protocol ?? defaultProtocol;
  const hostname = (options as RequestOptions).hostname ?? (options as RequestOptions).host ?? "localhost";
  const port = (options as RequestOptions).port;
  const path = (options as RequestOptions).path ?? "/";
  const host = hostname.toString();
  const portPart = port ? `:${port}` : "";
  const base = `${protocol}//${host}${portPart}`;
  const pathStr = typeof path === "string" ? path : "/";
  return pathStr.startsWith("http") ? pathStr : `${base}${pathStr.startsWith("/") ? pathStr : "/" + pathStr}`;
}

function getMethod(options: string | RequestOptions | URL): string {
  if (typeof options === "string" || options instanceof URL) {
    return "GET";
  }
  return ((options as RequestOptions).method ?? "GET").toUpperCase();
}

function wrapRequest(
  original: typeof http.request,
  protocol: string
): typeof http.request {
  return function (
    options: string | RequestOptions | URL,
    callback?: (res: IncomingMessage) => void
  ): ClientRequest {
    const url = buildUrl(options, protocol === "http" ? "http:" : "https:");
    const method = getMethod(options);
    const start = Date.now();

    const wrappedCallback = callback
      ? (res: IncomingMessage) => {
          const statusCode = res.statusCode ?? 0;
          const elapsedMs = Date.now() - start;
          try {
            getAegis().trace("api_call", url, {
              details: {
                method,
                url,
                status_code: statusCode,
                execution_ms: elapsedMs,
              },
            });
          } catch {
            // ignore
          }
          callback(res);
        }
      : undefined;

    const req = original(options, wrappedCallback);

    if (!callback && req) {
      req.on("response", (res: IncomingMessage) => {
        const statusCode = res.statusCode ?? 0;
        const elapsedMs = Date.now() - start;
        try {
          getAegis().trace("api_call", url, {
            details: {
              method,
              url,
              status_code: statusCode,
              execution_ms: elapsedMs,
            },
          });
        } catch {
          // ignore
        }
      });
      req.on("error", () => {
        const elapsedMs = Date.now() - start;
        try {
          getAegis().trace("api_call", url, {
            details: {
              method,
              url,
              status_code: null,
              execution_ms: elapsedMs,
              error: "request failed",
            },
          });
        } catch {
          // ignore
        }
      });
    }

    return req;
  } as typeof http.request;
}

function patchHttp(): void {
  const origHttpRequest = http.request;
  (http as Record<string, unknown>).request = wrapRequest(origHttpRequest, "http");
}

function patchHttps(): void {
  const origHttpsRequest = https.request;
  (https as Record<string, unknown>).request = wrapRequest(origHttpsRequest, "https");
}

function patchAxios(): void {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const axios = require("axios");
    if (!axios.interceptors) return;

    axios.interceptors.request.use(
      (config: { method?: string; url?: string }) => {
        (config as Record<string, unknown>).__aegis_start = Date.now();
        return config;
      },
      (err: unknown) => Promise.reject(err)
    );

    axios.interceptors.response.use(
      (response: { config?: { url?: string; method?: string }; status?: number }) => {
        const config = response.config;
        const start = (config as Record<string, unknown>)?.__aegis_start as number | undefined;
        if (config && typeof start === "number") {
          const url = config.url ?? "";
          const method = (config.method ?? "get").toUpperCase();
          const statusCode = response.status ?? 200;
          const elapsedMs = Date.now() - start;
          try {
            getAegis().trace("api_call", url, {
              details: {
                method,
                url,
                status_code: statusCode,
                execution_ms: elapsedMs,
              },
            });
          } catch {
            // ignore
          }
        }
        return response;
      },
      (err: { config?: { url?: string; method?: string }; message?: string }) => {
        const config = err?.config;
        const start = config ? (config as Record<string, unknown>).__aegis_start as number | undefined : undefined;
        if (config && typeof start === "number") {
          const url = config.url ?? "";
          const method = (config.method ?? "get").toUpperCase();
          const elapsedMs = Date.now() - start;
          try {
            getAegis().trace("api_call", url, {
              details: {
                method,
                url,
                status_code: null,
                execution_ms: elapsedMs,
                error: err?.message ?? "request failed",
              },
            });
          } catch {
            // ignore
          }
        }
        return Promise.reject(err);
      }
    );
  } catch {
    // axios not installed
  }
}

export function install(): void {
  patchHttp();
  patchHttps();
  patchAxios();
}

// Auto-install on import
install();
