// ===================
// ©AngelaMos | 2026
// alert.types.ts
// ===================

import { z } from 'zod'
import { fpKindSchema, ruleSchema, severitySchema } from './common.types'
import { intelStatsSchema } from './intel.types'

export const alertSchema = z.object({
  ts_nanos: z.number(),
  rule: ruleSchema,
  severity: severitySchema,
  ip: z.string().optional(),
  fp_kind: fpKindSchema.optional(),
  fp_value: z.string().optional(),
  title: z.string(),
  detail: z.string(),
  score: z.number().optional(),
})

export type Alert = z.infer<typeof alertSchema>

export const ruleCountSchema = z.object({
  rule: ruleSchema,
  count: z.number(),
})

export type RuleCount = z.infer<typeof ruleCountSchema>

export const statsResponseSchema = z.object({
  intel: intelStatsSchema,
  alerts_by_rule: z.array(ruleCountSchema),
  alert_total: z.number(),
})

export type StatsResponse = z.infer<typeof statsResponseSchema>

export const isValidAlert = (data: unknown): data is Alert => {
  return alertSchema.safeParse(data).success
}

export const isValidStatsResponse = (data: unknown): data is StatsResponse => {
  return statsResponseSchema.safeParse(data).success
}
