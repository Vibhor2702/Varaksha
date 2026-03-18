/**
 * determine the API base URL at runtime based on the current environment
 * Works in static exports without relying on Cloudflare env vars at build time
 */
export function getApiBase(): string {
  // Only in browser context (not during build)
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    
    // Production: Cloudflare Pages -> Railway backend
    if (hostname === 'varaksha.pages.dev') {
      return 'https://varaksha-production.up.railway.app';
    }
    
    // Local development
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
      return 'http://localhost:8000';
    }
  }

  // Fallback: check env var (set at build time if available)
  const envUrl = process.env.NEXT_PUBLIC_API_URL;
  if (envUrl) {
    return envUrl.endsWith('/') ? envUrl.slice(0, -1) : envUrl;
  }

  // Final fallback: Railway production
  return 'https://varaksha-production.up.railway.app';
}

/**
 * Get normalized API base URL (no trailing slash)
 */
export function getApiBaseNormalized(): string {
  const base = getApiBase();
  return base.endsWith('/') ? base.slice(0, -1) : base;
}
