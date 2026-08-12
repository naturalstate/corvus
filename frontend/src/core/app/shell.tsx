/**
 * ©AngelaMos | 2026
 * shell.tsx
 */

import { Suspense, useEffect, useState } from 'react'
import { ErrorBoundary, type FallbackProps } from 'react-error-boundary'
import { NavLink, Outlet } from 'react-router-dom'
import { cx, RegMark, Ticker } from '@/components'
import { ROUTES } from '@/config'
import styles from './shell.module.scss'

const NAV = [
  { to: ROUTES.SCOPE, label: 'scope' },
  { to: ROUTES.INTEL, label: 'intel' },
]

const TICKER = [
  'ja3',
  'ja3s',
  'ja4',
  'ja4s',
  'ja4h',
  'ja4x',
  'ja4t',
  'ja4ts',
  'quic-initial decryption',
  'passive capture only',
  'no tshark dependency',
  'the fingerprint outs the lie',
  'biometric of the handshake',
]

function pad(value: number): string {
  return String(value).padStart(2, '0')
}

function Clock(): React.ReactElement {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])
  const date = new Date(now)
  return (
    <span className={styles.clock}>
      {pad(date.getUTCHours())}:{pad(date.getUTCMinutes())}:
      {pad(date.getUTCSeconds())} utc
    </span>
  )
}

function ShellError({ error }: FallbackProps): React.ReactElement {
  const message = error instanceof Error ? error.message : String(error)
  return (
    <div className={styles.crash}>
      <span className={styles.crashTag}>signal lost</span>
      <pre className={styles.crashMsg}>{message}</pre>
    </div>
  )
}

function ShellLoading(): React.ReactElement {
  return <div className={styles.loading}>acquiring</div>
}

export function Shell(): React.ReactElement {
  return (
    <div className={styles.shell}>
      <header className={styles.top}>
        <div className={styles.brand}>
          <RegMark className={styles.reg} />
          <NavLink to={ROUTES.HOME} className={styles.mark}>
            TLSFP
          </NavLink>
          <span className={styles.tagline}>passive tls surveillance</span>
        </div>

        <nav className={styles.nav}>
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cx(styles.tab, isActive && styles.tabOn)
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className={styles.status}>
          <span className={styles.coord}>37.7749n / 122.4194w</span>
          <Clock />
        </div>
      </header>

      <main className={styles.main}>
        <ErrorBoundary FallbackComponent={ShellError}>
          <Suspense fallback={<ShellLoading />}>
            <Outlet />
          </Suspense>
        </ErrorBoundary>
      </main>

      <footer className={styles.foot}>
        <Ticker items={TICKER} />
      </footer>
    </div>
  )
}
