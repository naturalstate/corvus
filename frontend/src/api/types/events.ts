// ===================
// ©AngelaMos | 2026
// events.ts
// ===================

import type { Verdict } from './common.types'
import type { MatchReport } from './intel.types'
import type { NamedFingerprint, StreamEvent } from './stream.types'

export function fingerprintOf(event: StreamEvent): NamedFingerprint {
  switch (event.kind) {
    case 'client_hello':
      return { kind: 'ja4', value: event.ja4.hash }
    case 'server_hello':
      return { kind: 'ja4s', value: event.ja4s.hash }
    case 'certificate':
      return { kind: 'ja4x', value: event.ja4x }
    case 'http_request':
      return { kind: 'ja4h', value: event.ja4h.hash }
    case 'tcp_syn':
      return { kind: 'ja4t', value: event.ja4t }
    case 'tcp_syn_ack':
      return { kind: 'ja4ts', value: event.ja4ts }
  }
}

export function worstVerdict(reports?: MatchReport[]): Verdict | undefined {
  if (!reports || reports.length === 0) return undefined
  const rank: Record<Verdict, number> = {
    malicious: 3,
    suspicious: 2,
    benign: 1,
    unknown: 0,
  }
  return reports.reduce<Verdict>(
    (worst, report) =>
      rank[report.verdict] > rank[worst] ? report.verdict : worst,
    'unknown'
  )
}

export function splitAddr(addr: string): { host: string; port: string } {
  if (addr.startsWith('[')) {
    const close = addr.indexOf(']')
    return { host: addr.slice(1, close), port: addr.slice(close + 2) }
  }
  const colon = addr.lastIndexOf(':')
  if (colon === -1) return { host: addr, port: '' }
  return { host: addr.slice(0, colon), port: addr.slice(colon + 1) }
}

export function formatClock(tsNanos: number): string {
  const date = new Date(tsNanos / 1_000_000)
  const pad = (n: number, width = 2): string => String(n).padStart(width, '0')
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(
    date.getSeconds()
  )}.${pad(date.getMilliseconds(), 3)}`
}
