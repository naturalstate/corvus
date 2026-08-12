// ===================
// ©AngelaMos | 2026
// common.types.ts
// ===================

import { z } from 'zod'

export const FP_KIND_VALUES = [
  'ja3',
  'ja3s',
  'ja4',
  'ja4s',
  'ja4h',
  'ja4x',
  'ja4t',
  'ja4ts',
] as const

export const fpKindSchema = z.enum(FP_KIND_VALUES)

export type FpKind = z.infer<typeof fpKindSchema>

export const CATEGORY_VALUES = [
  'malware',
  'c2',
  'tool',
  'benign',
  'os',
  'unknown',
] as const

export const categorySchema = z.enum(CATEGORY_VALUES)

export type Category = z.infer<typeof categorySchema>

export const VERDICT_VALUES = [
  'malicious',
  'suspicious',
  'benign',
  'unknown',
] as const

export const verdictSchema = z.enum(VERDICT_VALUES)

export type Verdict = z.infer<typeof verdictSchema>

export const MATCH_STRENGTH_VALUES = [
  'exact',
  'cipher_and_prefix',
  'cipher_only',
] as const

export const matchStrengthSchema = z.enum(MATCH_STRENGTH_VALUES)

export type MatchStrength = z.infer<typeof matchStrengthSchema>

export const RULE_VALUES = [
  'known_bad',
  'ua_mismatch',
  'os_mismatch',
  'first_seen',
  'fp_rotation',
  'monoculture',
] as const

export const ruleSchema = z.enum(RULE_VALUES)

export type Rule = z.infer<typeof ruleSchema>

export const SEVERITY_VALUES = [
  'info',
  'low',
  'medium',
  'high',
  'critical',
] as const

export const severitySchema = z.enum(SEVERITY_VALUES)

export type Severity = z.infer<typeof severitySchema>

export const ja4FamilySchema = z.object({
  hash: z.string(),
  raw: z.string(),
})

export type Ja4Family = z.infer<typeof ja4FamilySchema>
