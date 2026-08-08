import axios from "axios";

export const API_KEY_STORAGE_KEY = "complychain_api_key";

export function getStoredApiKey(): string | null {
  return localStorage.getItem(API_KEY_STORAGE_KEY);
}

export function setStoredApiKey(key: string): void {
  localStorage.setItem(API_KEY_STORAGE_KEY, key);
}

export function clearStoredApiKey(): void {
  localStorage.removeItem(API_KEY_STORAGE_KEY);
}

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
});

api.interceptors.request.use((config) => {
  const key = getStoredApiKey();
  if (key) {
    config.headers["X-ComplyChain-API-Key"] = key;
  }
  return config;
});

let onUnauthorized: (() => void) | null = null;

export function registerUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler;
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    // Requests made with responseType:"blob" (sign, SAR, report, evidence)
    // also receive their ERROR bodies as a Blob, so `data.detail` is always
    // undefined and every caller silently fell back to a generic message.
    // Re-read the blob as text and parse it here, once, so the server's real
    // detail reaches getApiErrorMessage below.
    const data = error.response?.data;
    if (data instanceof Blob) {
      try {
        error.response.data = JSON.parse(await data.text());
      } catch {
        // Not JSON (an HTML error page, say) — leave it and let the caller's
        // fallback message apply.
      }
    }

    if (error.response?.status === 401 || error.response?.status === 403) {
      clearStoredApiKey();
      onUnauthorized?.();
    }
    return Promise.reject(error);
  }
);

export function getApiErrorMessage(err: unknown, fallback: string): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === "string") return detail;
  }
  return fallback;
}
