/**
 * ©AngelaMos | 2026
 * live-stream.tsx
 */

import type { LiveItem } from '@/api/hooks'
import {
  type Alert,
  fingerprintOf,
  formatClock,
  type MatchReport,
  type Severity,
  type StreamEvent,
  splitAddr,
  worstVerdict,
} from '@/api/types'
import { SeverityTag } from './atoms'
import { cx } from './cx'
import styles from './live-stream.module.scss'
import { CropFrame } from './marks'

const SEV_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const KIND_CODE: Record<StreamEvent['kind'], string> = {
  client_hello: 'CLT',
  server_hello: 'SRV',
  certificate: 'CRT',
  http_request: 'HTP',
  tcp_syn: 'SYN',
  tcp_syn_ack: 'SYK',
}

function topSeverity(alerts: Alert[]): Severity | undefined {
  if (alerts.length === 0) return undefined
  return alerts.reduce<Severity>(
    (worst, alert) =>
      SEV_ORDER[alert.severity] > SEV_ORDER[worst] ? alert.severity : worst,
    'info'
  )
}

function FlowRow({
  event,
  intel,
  alerts,
}: {
  event: StreamEvent
  intel?: MatchReport[]
  alerts?: Alert[]
}): React.ReactElement {
  const fingerprint = fingerprintOf(event)
  const src = splitAddr(event.src)
  const dst = splitAddr(event.dst)
  const verdict = worstVerdict(intel)
  const severity = topSeverity(alerts ?? [])
  const hot = severity === 'high' || severity === 'critical'

  return (
    <div
      className={cx(styles.row, styles.enter, hot && styles.rowHot)}
      data-verdict={verdict ?? 'unknown'}
    >
      <span className={styles.time}>{formatClock(event.ts_nanos)}</span>
      <span className={styles.code}>{KIND_CODE[event.kind]}</span>
      <span className={styles.route}>
        <span className={styles.host}>{src.host}</span>
        <span className={styles.arrow}>-&gt;</span>
        <span className={styles.host}>{dst.host}</span>
      </span>
      <span className={styles.fp} title={fingerprint.value}>
        <span className={styles.fpKind}>{fingerprint.kind}</span>
        <span className={styles.fpValue}>{fingerprint.value}</span>
      </span>
      <span className={styles.marks}>
        {verdict && verdict !== 'unknown' && (
          <span className={styles.dot} data-verdict={verdict} />
        )}
        {severity && <SeverityTag severity={severity} />}
      </span>
    </div>
  )
}

function AlertRow({ alert }: { alert: Alert }): React.ReactElement {
  return (
    <div
      className={cx(styles.row, styles.enter, styles.alertRow)}
      data-sev={alert.severity}
    >
      <span className={styles.time}>{formatClock(alert.ts_nanos)}</span>
      <span className={cx(styles.code, styles.codeAlert)}>ALR</span>
      <span className={styles.alertTitle}>{alert.title}</span>
      <span className={styles.marks}>
        <SeverityTag severity={alert.severity} />
      </span>
    </div>
  )
}

export function LiveStream({
  feed,
  connected,
  flowCount,
  className,
}: {
  feed: LiveItem[]
  connected: boolean
  flowCount: number
  className?: string
}): React.ReactElement {
  const aside = (
    <span className={styles.aside}>
      <span className={cx(styles.live, connected && styles.liveOn)}>
        {connected ? 'rec' : 'down'}
      </span>
      <span className={styles.count}>{flowCount.toLocaleString()} flows</span>
    </span>
  )

  return (
    <CropFrame
      label="live // passive wire-tap"
      aside={aside}
      className={cx(styles.frame, className)}
    >
      <div className={styles.scroll}>
        {feed.length === 0 ? (
          <div className={styles.idle}>
            <span className={styles.idleLine}>
              awaiting handshakes on the wire
            </span>
            <span className={styles.idleSub}>
              the scope is open; nothing has crossed it yet
            </span>
          </div>
        ) : (
          feed.map((item) =>
            item.message.type === 'flow' ? (
              <FlowRow
                key={item.seq}
                event={item.message.event}
                intel={item.message.intel}
                alerts={item.message.alerts}
              />
            ) : (
              <AlertRow key={item.seq} alert={item.message.alert} />
            )
          )
        )}
      </div>
    </CropFrame>
  )
}
