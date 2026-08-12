/**
 * ©AngelaMos | 2026
 * anomaly.tsx
 */

import { useRecentAlerts } from '@/api/hooks'
import { type Alert, formatClock, type Rule } from '@/api/types'
import styles from './anomaly.module.scss'
import { SeverityTag } from './atoms'
import { cx } from './cx'
import { CropFrame, Reticle } from './marks'

// The rules that mean a fingerprint caught a client in a lie, the ones worth
// pulling to the top of the console out of the ledger's noise.
const LOUD: Rule[] = ['ua_mismatch', 'known_bad', 'os_mismatch']

const HEADLINE: Record<Rule, string> = {
  ua_mismatch: 'the user-agent is lying',
  known_bad: 'known-bad fingerprint',
  os_mismatch: 'the stack betrays the os',
  first_seen: 'first sighting',
  fp_rotation: 'identity rotation',
  monoculture: 'one toolkit, many hosts',
}

export function AnomalyHighlights({
  className,
}: {
  className?: string
}): React.ReactElement {
  const { data } = useRecentAlerts()
  const loud = (data ?? [])
    .filter((alert) => LOUD.includes(alert.rule))
    .slice(0, 4)

  return (
    <CropFrame
      label="anomaly // the lie the scan caught"
      tone={loud.length > 0 ? 'hot' : 'cold'}
      className={cx(styles.frame, className)}
    >
      <div className={cx(styles.body, loud.length > 0 && styles.armed)}>
        {loud.length === 0 ? (
          <div className={styles.clean}>
            <Reticle className={styles.reticle} />
            <div className={styles.cleanLine}>no contradiction on the wire</div>
            <div className={styles.cleanSub}>
              every handshake agrees with what it claims to be
            </div>
          </div>
        ) : (
          loud.map((alert, index) => (
            <AnomalyCard key={`${alert.ts_nanos}-${index}`} alert={alert} />
          ))
        )}
      </div>
    </CropFrame>
  )
}

function AnomalyCard({ alert }: { alert: Alert }): React.ReactElement {
  return (
    <article className={styles.card} data-sev={alert.severity}>
      <div className={styles.top}>
        <span className={styles.headline}>{HEADLINE[alert.rule]}</span>
        <SeverityTag severity={alert.severity} />
      </div>
      <div className={styles.subject}>{alert.ip ?? 'no source address'}</div>
      <p className={styles.evidence}>{alert.detail}</p>
      <div className={styles.foot}>
        <span className={styles.rule}>{alert.rule}</span>
        <span className={styles.time}>{formatClock(alert.ts_nanos)}</span>
      </div>
    </article>
  )
}
