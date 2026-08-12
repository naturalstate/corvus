/**
 * ©AngelaMos | 2026
 * index.tsx
 */

import { useLiveStream } from '@/api/hooks'
import {
  AlertFeed,
  AnomalyHighlights,
  Distribution,
  LiveStream,
  StatCluster,
} from '@/components'
import styles from './scope.module.scss'

export function Component(): React.ReactElement {
  const live = useLiveStream()

  return (
    <div className={styles.page}>
      <section className={styles.masthead}>
        <img
          src="/assets/objects/xray-butterfly.png"
          alt=""
          className={styles.butterfly}
        />
        <div className={styles.headText}>
          <span className={styles.over}>passive tls surveillance / live</span>
          <h1 className={styles.title}>THE SCOPE</h1>
          <p className={styles.sub}>
            Fingerprints crossing the wire, scored against the corpus and read for
            the lie they tell.
          </p>
        </div>
        <StatCluster flowCount={live.flowCount} className={styles.stats} />
      </section>

      <section className={styles.grid}>
        <LiveStream
          feed={live.feed}
          connected={live.connected}
          flowCount={live.flowCount}
          className={styles.live}
        />
        <AnomalyHighlights className={styles.anomaly} />
        <Distribution className={styles.dist} />
        <AlertFeed className={styles.alerts} />
      </section>
    </div>
  )
}

Component.displayName = 'Scope'
