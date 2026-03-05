import DOMPurify from "isomorphic-dompurify";

/**
 * Sanitize user-controlled strings before display to prevent XSS.
 * Strips all HTML tags; use for displaying trace logs, reasons, hashes.
 */
export function sanitizeForDisplay(text: string): string {
  if (typeof text !== "string") return "";
  return DOMPurify.sanitize(text, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
}
