// ===================
// ©AngelaMos | 2026
// index.ts
// ===================

import { type UseQueryResult, useQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import {
  API_BASE,
  API_ENDPOINTS,
  LIVE,
  QUERY_CONFIG,
  QUERY_KEYS,
  STREAM_URL,
} from '@/config'
import { apiClient } from '@/core/api'
import {
  type Alert,
  alertSchema,
  type CatalogEntry,
  catalogEntrySchema,
  type FpKind,
  isLiveMessage,
  type LiveMessage,
  type StatsResponse,
  statsResponseSchema,
} from '../types'

async function getStats(): Promise<StatsResponse> {
  const { data } = await apiClient.get(API_ENDPOINTS.STATS)
  return statsResponseSchema.parse(data)
}

async function getAlerts(limit: number): Promise<Alert[]> {
  const { data } = await apiClient.get(API_ENDPOINTS.ALERTS, {
    params: { limit },
  })
  return alertSchema.array().parse(data)
}

async function getSearch(
  query: string,
  kind: string,
  limit: number
): Promise<CatalogEntry[]> {
  const { data } = await apiClient.get(API_ENDPOINTS.SEARCH, {
    params: { q: query, kind: kind || undefined, limit },
  })
  return catalogEntrySchema.array().parse(data)
}

export function useStats(): UseQueryResult<StatsResponse> {
  return useQuery({
    queryKey: QUERY_KEYS.STATS,
    queryFn: getStats,
    refetchInterval: QUERY_CONFIG.STALE_TIME.FREQUENT,
  })
}

export function useRecentAlerts(
  limit: number = LIVE.ALERT_PAGE
): UseQueryResult<Alert[]> {
  return useQuery({
    queryKey: QUERY_KEYS.ALERTS(limit),
    queryFn: () => getAlerts(limit),
    refetchInterval: QUERY_CONFIG.STALE_TIME.FREQUENT,
  })
}

export function useSearch(
  query: string,
  kind: FpKind | ''
): UseQueryResult<CatalogEntry[]> {
  return useQuery({
    queryKey: QUERY_KEYS.SEARCH(query, kind),
    queryFn: () => getSearch(query, kind, LIVE.SEARCH_PAGE),
    placeholderData: (previous) => previous,
  })
}

// The href for a streamed export download, used directly by an anchor so the
// browser handles the file rather than buffering it through fetch.
export function exportHref(format: 'json' | 'csv', limit = 1000): string {
  return `${API_BASE}${API_ENDPOINTS.EXPORT}?format=${format}&limit=${limit}`
}

export interface LiveItem {
  seq: number
  message: LiveMessage
}

export interface LiveState {
  feed: LiveItem[]
  connected: boolean
  flowCount: number
  alertCount: number
}

const EMPTY_LIVE: LiveState = {
  feed: [],
  connected: false,
  flowCount: 0,
  alertCount: 0,
}

function parseMessage(data: string): LiveMessage | null {
  try {
    const parsed: unknown = JSON.parse(data)
    return isLiveMessage(parsed) ? parsed : null
  } catch {
    return null
  }
}

// Subscribes to the Server-Sent Events stream and keeps a bounded, newest-first
// window of what has come over the wire, plus running counts for the masthead.
// EventSource reconnects on its own, so a dropped link recovers without help.
export function useLiveStream(maxItems: number = LIVE.STREAM_BUFFER): LiveState {
  const [state, setState] = useState<LiveState>(EMPTY_LIVE)
  const max = useRef(maxItems)
  max.current = maxItems
  const seq = useRef(0)

  useEffect(() => {
    const source = new EventSource(STREAM_URL)

    source.onopen = () => {
      setState((prev) => ({ ...prev, connected: true }))
    }

    source.onerror = () => {
      setState((prev) => ({ ...prev, connected: false }))
    }

    source.onmessage = (event) => {
      const message = parseMessage(event.data)
      if (!message) return
      seq.current += 1
      const item: LiveItem = { seq: seq.current, message }
      setState((prev) => {
        const feed = [item, ...prev.feed].slice(0, max.current)
        const flowCount = prev.flowCount + (message.type === 'flow' ? 1 : 0)
        const inlineAlerts =
          message.type === 'flow' ? (message.alerts?.length ?? 0) : 0
        const standalone = message.type === 'alert' ? 1 : 0
        return {
          feed,
          connected: true,
          flowCount,
          alertCount: prev.alertCount + inlineAlerts + standalone,
        }
      })
    }

    return () => {
      source.close()
    }
  }, [])

  return state
}
