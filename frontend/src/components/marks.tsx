/**
 * ©AngelaMos | 2026
 * marks.tsx
 */

import type { ReactNode } from 'react'
import { cx } from './cx'
import styles from './marks.module.scss'

// The small registration cross a scan sheet pins its corners with.
export function RegMark({
  className,
}: {
  className?: string
}): React.ReactElement {
  return (
    <svg
      className={cx(styles.reg, className)}
      viewBox="0 0 18 18"
      aria-hidden="true"
    >
      <path d="M9 0v6M9 12v6M0 9h6M12 9h6" />
      <circle cx="9" cy="9" r="2.4" />
    </svg>
  )
}

// The targeting reticle from the surveillance sheet: a ranged circle with a
// crosshair through it, used to mark the thing under inspection.
export function Reticle({
  className,
}: {
  className?: string
}): React.ReactElement {
  return (
    <svg
      className={cx(styles.reticle, className)}
      viewBox="0 0 80 80"
      aria-hidden="true"
    >
      <circle cx="40" cy="40" r="30" />
      <circle cx="40" cy="40" r="3" />
      <path d="M40 2v18M40 60v18M2 40h18M60 40h18" />
    </svg>
  )
}

// A panel a specimen is pinned inside: hairline rule, crop-mark corners, and a
// stencilled label riding the top edge. `tone='hot'` lights the frame when what
// it holds is an anomaly.
export function CropFrame({
  label,
  aside,
  tone = 'cold',
  span,
  children,
  className,
}: {
  label?: string
  aside?: ReactNode
  tone?: 'cold' | 'hot'
  span?: boolean
  children: ReactNode
  className?: string
}): React.ReactElement {
  return (
    <section
      className={cx(
        styles.frame,
        tone === 'hot' && styles.hot,
        span && styles.span,
        className
      )}
    >
      {(label || aside) && (
        <header className={styles.frameHead}>
          {label && <span className={styles.frameLabel}>{label}</span>}
          {aside && <span className={styles.frameAside}>{aside}</span>}
        </header>
      )}
      <div className={styles.frameBody}>{children}</div>
    </section>
  )
}

// The crawling status line that runs along an edge of the console, the way a
// poster runs its catalogue of credits along its bottom rule.
export function Ticker({
  items,
  className,
}: {
  items: string[]
  className?: string
}): React.ReactElement {
  // Two labelled passes of the same items so the lane can scroll seamlessly
  // without leaning on an array index for the key.
  return (
    <div className={cx(styles.ticker, className)} aria-hidden="true">
      <div className={styles.tickerLane}>
        {(['a', 'b'] as const).map((pass) =>
          items.map((item) => (
            <span key={`${pass}-${item}`} className={styles.tickerItem}>
              {item}
            </span>
          ))
        )}
      </div>
    </div>
  )
}
