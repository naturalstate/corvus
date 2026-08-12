/**
 * ©AngelaMos | 2026
 * stat-cluster.tsx
 */

import { useStats } from '@/api/hooks'
import { cx } from './cx'
import styles from './stat-cluster.module.scss'

export function StatCluster({
  flowCount,
  className,
}: {
  flowCount: number
  className?: string
}): React.ReactElement {
  const { data } = useStats()
  const stats = [
    {
      value: data?.intel.total ?? 0,
      label: 'intel corpus',
      sub: 'fingerprints held',
    },
    { value: data?.alert_total ?? 0, label: 'alerts', sub: 'rules tripped' },
    {
      value: data?.intel.sources.length ?? 0,
      label: 'feeds',
      sub: 'sources fused',
    },
    { value: flowCount, label: 'live flows', sub: 'seen this session' },
  ]

  return (
    <div className={cx(styles.cluster, className)}>
      {stats.map((stat) => (
        <div key={stat.label} className={styles.stat}>
          <span className={styles.value}>{stat.value.toLocaleString()}</span>
          <span className={styles.label}>{stat.label}</span>
          <span className={styles.sub}>{stat.sub}</span>
        </div>
      ))}
    </div>
  )
}
