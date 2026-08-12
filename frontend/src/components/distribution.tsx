/**
 * ©AngelaMos | 2026
 * distribution.tsx
 */

import { useStats } from '@/api/hooks'
import { cx } from './cx'
import styles from './distribution.module.scss'
import { CropFrame } from './marks'

function Bar({
  label,
  value,
  max,
  attr,
}: {
  label: string
  value: number
  max: number
  attr: Record<string, string>
}): React.ReactElement {
  const pct = max > 0 ? Math.max(2.5, (value / max) * 100) : 0
  return (
    <div className={styles.bar} {...attr}>
      <span className={styles.barLabel}>{label}</span>
      <span className={styles.track}>
        <span className={styles.fill} style={{ width: `${pct}%` }} />
      </span>
      <span className={styles.value}>{value.toLocaleString()}</span>
    </div>
  )
}

export function Distribution({
  className,
}: {
  className?: string
}): React.ReactElement {
  const { data } = useStats()
  const categories = data?.intel.by_category ?? []
  const rules = data?.alerts_by_rule ?? []
  const catMax = Math.max(1, ...categories.map((row) => row.records))
  const ruleMax = Math.max(1, ...rules.map((row) => row.count))

  return (
    <CropFrame
      label="distribution // census"
      className={cx(styles.frame, className)}
    >
      <div className={styles.body}>
        <div className={styles.group}>
          <div className={styles.groupHead}>intel corpus / category</div>
          {categories.map((row) => (
            <Bar
              key={row.category}
              label={row.category}
              value={row.records}
              max={catMax}
              attr={{ 'data-cat': row.category }}
            />
          ))}
        </div>

        <div className={styles.group}>
          <div className={styles.groupHead}>alerts raised / rule</div>
          {rules.length === 0 ? (
            <div className={styles.empty}>no rules have fired on this link</div>
          ) : (
            rules.map((row) => (
              <Bar
                key={row.rule}
                label={row.rule}
                value={row.count}
                max={ruleMax}
                attr={{ 'data-rule': row.rule }}
              />
            ))
          )}
        </div>
      </div>
    </CropFrame>
  )
}
