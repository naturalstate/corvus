// ===================
// ©AngelaMos | 2026
// config.ts
// ===================

// The base the axum server mounts its API under, shared with the dashboard's
// own origin. The event stream is reached directly through an EventSource, so
// it needs the absolute path rather than the axios base.
export const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined) ?? '/api'

export const STREAM_URL = `${API_BASE}/stream`

export const API_ENDPOINTS = {
  STATS: '/stats',
  ALERTS: '/alerts',
  SEARCH: '/search',
  EXPORT: '/export',
  HEALTH: '/health',
} as const

export const QUERY_KEYS = {
  STATS: ['stats'] as const,
  ALERTS: (limit: number) => ['alerts', limit] as const,
  SEARCH: (query: string, kind: string) => ['search', query, kind] as const,
} as const

export const ROUTES = {
  HOME: '/',
  SCOPE: '/scope',
  INTEL: '/intel',
} as const

export const STORAGE_KEYS = {
  UI: 'ui-storage',
} as const

export const QUERY_CONFIG = {
  STALE_TIME: {
    USER: 1000 * 60 * 5,
    STATIC: Number.POSITIVE_INFINITY,
    FREQUENT: 1000 * 4,
  },
  GC_TIME: {
    DEFAULT: 1000 * 60 * 30,
    LONG: 1000 * 60 * 60,
  },
  RETRY: {
    DEFAULT: 3,
    NONE: 0,
  },
} as const

// How many live lines the stream view holds before the oldest scroll off, and
// how many alerts the feed and export pull by default.
export const LIVE = {
  STREAM_BUFFER: 140,
  ALERT_PAGE: 60,
  SEARCH_PAGE: 40,
} as const

export const HTTP_STATUS = {
  OK: 200,
  BAD_REQUEST: 400,
  NOT_FOUND: 404,
  INTERNAL_SERVER: 500,
} as const

export type ApiEndpoint = typeof API_ENDPOINTS
export type Route = typeof ROUTES
