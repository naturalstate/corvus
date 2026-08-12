/**
 * ©AngelaMos | 2026
 * alert-feed.tsx
 */

import { useRecentAlerts } from '@/api/hooks'
import { type Alert, formatClock } from '@/api/types'
import styles from './alert-feed.module.scss'
import { RuleTag, SeverityTag } from './atoms'
import { cx } from './cx'
import { CropFrame } from './marks'

function AlertEntry({ alert }: { alert: Alert }): React.ReactElement {
  return (
    <li className={styles.entry} data-sev={alert.severity}>
      <div className={styles.head}>
        <SeverityTag severity={alert.severity} />
        <RuleTag rule={alert.rule} />
        <span className={styles.time}>{formatClock(alert.ts_nanos)}</span>
        {alert.ip && <span className={styles.ip}>{alert.ip}</span>}
      </div>
      <div className={styles.title}>{alert.title}</div>
      <p className={styles.detail}>{alert.detail}</p>
    </li>
  )
}

export function AlertFeed({
  className,
}: {
  className?: string
}): React.ReactElement {
  const { data, isLoading } = useRecentAlerts()
  const alerts = data ?? []

  const aside = (
    <span className={styles.aside}>{alerts.length.toLocaleString()} signed</span>
  )

  return (
    <CropFrame
      label="alert ledger // provenance"
      aside={aside}
      className={cx(styles.frame, className)}
    >
      <div className={styles.scroll}>
        {isLoading ? (
          <div className={styles.idle}>reading the ledger</div>
        ) : alerts.length === 0 ? (
          <div className={styles.idle}>the ledger is clean</div>
        ) : (
          <ul className={styles.list}>
            {alerts.map((alert, index) => (
              <AlertEntry
                key={`${alert.ts_nanos}-${alert.rule}-${alert.fp_value ?? index}`}
                alert={alert}
              />
            ))}
          </ul>
        )}
      </div>
    </CropFrame>
  )
}
