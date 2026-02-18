export function apiBase(): string {
  // Browser should call localhost
  if (typeof window !== "undefined") {
    return process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
  }

  // Server-side (inside container) should call the docker service name
  return process.env.INTERNAL_API_BASE_URL
    || process.env.NEXT_PUBLIC_API_BASE_URL
    || "http://api:8000";
}
