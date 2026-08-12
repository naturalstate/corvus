// ===================
// ©AngelaMos | 2026
// stream.types.ts
// ===================

import { z } from 'zod'
import { alertSchema } from './alert.types'
import { type FpKind, ja4FamilySchema } from './common.types'
import { matchReportSchema } from './intel.types'

const baseEventSchema = z.object({
  ts_nanos: z.number(),
  src: z.string(),
  dst: z.string(),
})

export const streamEventSchema = z.discriminatedUnion('kind', [
  baseEventSchema.extend({
    kind: z.literal('client_hello'),
    ja3: z.string(),
    ja3_raw: z.string(),
    ja4: ja4FamilySchema,
    sni: z.string().optional(),
    alpn: z.string().optional(),
  }),
  baseEventSchema.extend({
    kind: z.literal('server_hello'),
    ja3s: z.string(),
    ja3s_raw: z.string(),
    ja4s: ja4FamilySchema,
  }),
  baseEventSchema.extend({
    kind: z.literal('certificate'),
    ja4x: z.string(),
  }),
  baseEventSchema.extend({
    kind: z.literal('http_request'),
    ja4h: ja4FamilySchema,
    method: z.string(),
    host: z.string().optional(),
    user_agent: z.string().optional(),
  }),
  baseEventSchema.extend({
    kind: z.literal('tcp_syn'),
    ja4t: z.string(),
  }),
  baseEventSchema.extend({
    kind: z.literal('tcp_syn_ack'),
    ja4ts: z.string(),
  }),
])

export type StreamEvent = z.infer<typeof streamEventSchema>

export type EventKind = StreamEvent['kind']

export const liveMessageSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('flow'),
    event: streamEventSchema,
    intel: z.array(matchReportSchema).optional(),
    alerts: z.array(alertSchema).optional(),
  }),
  z.object({
    type: z.literal('alert'),
    alert: alertSchema,
  }),
])

export type LiveMessage = z.infer<typeof liveMessageSchema>

export type NamedFingerprint = {
  kind: FpKind
  value: string
}

export const isLiveMessage = (data: unknown): data is LiveMessage => {
  return liveMessageSchema.safeParse(data).success
}
