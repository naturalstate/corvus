/**
 * ©AngelaMos | 2026
 * index.tsx
 */

import { exportHref, useStats } from '@/api/hooks'
import { CropFrame, SearchPanel } from '@/components'
import styles from './intel.module.scss'

export function Component(): React.ReactElement {
  const { data } = useStats()
  const sources = data?.intel.sources ?? []

  return (
    <div className={styles.page}>
      <section className={styles.head}>
        <img src="/assets/objects/xray-lily.png" alt="" className={styles.lily} />
        <div className={styles.headText}>
          <span className={styles.over}>threat intelligence / catalogue</span>
          <h1 className={styles.title}>THE CORPUS</h1>
          <p className={styles.sub}>
            {(data?.intel.total ?? 0).toLocaleString()} fingerprints fused from{' '}
            {sources.length} feeds. Query it for a known hand, or carry the ledger
            out.
          </p>
        </div>
      </section>

      <section className={styles.grid}>
        <SearchPanel className={styles.search} />

        <div className={styles.side}>
          <CropFrame label="feeds // provenance" className={styles.feeds}>
            <ul className={styles.feedList}>
              {sources.map((source) => (
                <li key={source.name} className={styles.feed}>
                  <span className={styles.feedName}>{source.name}</span>
                  <span className={styles.feedMeta}>
                    <span className={styles.license}>
                      {source.license ?? 'unlicensed'}
                    </span>
                    <span className={styles.records}>
                      {source.records.toLocaleString()}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          </CropFrame>

          <CropFrame label="export // ledger" className={styles.export}>
            <div className={styles.exportBody}>
              <p className={styles.exportNote}>
                Carry the alert ledger out, structured for a report or raw for a
                notebook.
              </p>
              <div className={styles.exportBtns}>
                <a
                  className={styles.exportBtn}
                  href={exportHref('json', 5000)}
                  download
                >
                  json
                </a>
                <a
                  className={styles.exportBtn}
                  href={exportHref('csv', 5000)}
                  download
                >
                  csv
                </a>
              </div>
            </div>
          </CropFrame>
        </div>
      </section>
    </div>
  )
}

Component.displayName = 'Intel'
