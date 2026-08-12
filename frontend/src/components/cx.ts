// ===================
// ©AngelaMos | 2026
// cx.ts
// ===================

export function cx(...parts: Array<string | false | undefined | null>): string {
  return parts.filter(Boolean).join(' ')
}
