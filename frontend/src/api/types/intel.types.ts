// ===================
// ©AngelaMos | 2026
// intel.types.ts
// ===================

import { z } from 'zod'
import {
  categorySchema,
  fpKindSchema,
  matchStrengthSchema,
  verdictSchema,
} from './common.types'

export const intelHitSchema = z.object({
  kind: fpKindSchema,
  value: z.string(),
  label: z.string(),
  category: categorySchema,
  source: z.string(),
  reference: z.string().optional(),
  strength: matchStrengthSchema,
})

export type IntelHit = z.infer<typeof intelHitSchema>

export const matchReportSchema = z.object({
  kind: fpKindSchema,
  observed: z.string(),
  verdict: verdictSchema,
  threat_score: z.number(),
  confidence: z.number(),
  hits: z.array(intelHitSchema),
})

export type MatchReport = z.infer<typeof matchReportSchema>

export const catalogEntrySchema = z.object({
  kind: fpKindSchema,
  value: z.string(),
  label: z.string(),
  category: categorySchema,
  source: z.string(),
  reference: z.string().optional(),
})

export type CatalogEntry = z.infer<typeof catalogEntrySchema>

export const sourceStatSchema = z.object({
  name: z.string(),
  kind: z.string(),
  license: z.string().optional(),
  records: z.number(),
})

export type SourceStat = z.infer<typeof sourceStatSchema>

export const categoryStatSchema = z.object({
  category: z.string(),
  records: z.number(),
})

export type CategoryStat = z.infer<typeof categoryStatSchema>

export const intelStatsSchema = z.object({
  sources: z.array(sourceStatSchema),
  by_category: z.array(categoryStatSchema),
  total: z.number(),
})

export type IntelStats = z.infer<typeof intelStatsSchema>

export const isValidCatalogEntry = (data: unknown): data is CatalogEntry => {
  return catalogEntrySchema.safeParse(data).success
}
