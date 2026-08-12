/**
 * ©AngelaMos | 2026
 * atoms.tsx
 */

import type { Category, FpKind, Rule, Severity, Verdict } from '@/api/types'
import styles from './atoms.module.scss'
import { cx } from './cx'

export function SeverityTag({
  severity,
  className,
}: {
  severity: Severity
  className?: string
}): React.ReactElement {
  return (
    <span className={cx(styles.sev, className)} data-sev={severity}>
      {severity}
    </span>
  )
}

export function VerdictBadge({
  verdict,
}: {
  verdict: Verdict
}): React.ReactElement {
  return (
    <span className={styles.verdict} data-verdict={verdict}>
      {verdict}
    </span>
  )
}

export function CategoryTag({
  category,
}: {
  category: Category
}): React.ReactElement {
  return (
    <span className={styles.cat} data-cat={category}>
      {category}
    </span>
  )
}

export function RuleTag({ rule }: { rule: Rule }): React.ReactElement {
  return <span className={styles.rule}>{rule}</span>
}

export function KindTag({ kind }: { kind: FpKind }): React.ReactElement {
  return <span className={styles.kind}>{kind}</span>
}
