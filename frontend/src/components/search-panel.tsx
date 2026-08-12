/**
 * ©AngelaMos | 2026
 * search-panel.tsx
 */

import { useEffect, useState } from 'react'
import { useSearch } from '@/api/hooks'
import type { CatalogEntry, FpKind } from '@/api/types'
import { LIVE } from '@/config'
import { CategoryTag, KindTag } from './atoms'
import { cx } from './cx'
import { CropFrame } from './marks'
import styles from './search-panel.module.scss'

const KINDS: FpKind[] = [
  'ja3',
  'ja3s',
  'ja4',
  'ja4s',
  'ja4h',
  'ja4x',
  'ja4t',
  'ja4ts',
]

function useDebounced<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setSettled(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return settled
}

function ResultRow({ entry }: { entry: CatalogEntry }): React.ReactElement {
  return (
    <div className={styles.row}>
      <KindTag kind={entry.kind} />
      <span className={styles.value} title={entry.value}>
        {entry.value}
      </span>
      <span className={styles.label} title={entry.label}>
        {entry.label}
      </span>
      <CategoryTag category={entry.category} />
      <span className={styles.source}>{entry.source}</span>
    </div>
  )
}

export function SearchPanel({
  className,
}: {
  className?: string
}): React.ReactElement {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState<FpKind | ''>('')
  const debounced = useDebounced(query, 220)
  const { data, isFetching } = useSearch(debounced, kind)
  const results = data ?? []
  const capped = results.length >= LIVE.SEARCH_PAGE

  const aside = (
    <span className={styles.count}>
      {results.length}
      {capped ? '+' : ''} hits
    </span>
  )

  return (
    <CropFrame
      label="catalogue // query the corpus"
      aside={aside}
      className={cx(styles.frame, className)}
    >
      <div className={styles.body}>
        <div className={styles.controls}>
          <div className={cx(styles.inputWrap, isFetching && styles.busy)}>
            <span className={styles.prompt}>/</span>
            <input
              className={styles.input}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="label or fingerprint substring"
              spellCheck={false}
              autoComplete="off"
              aria-label="search the intelligence catalogue"
            />
          </div>
          <div className={styles.kinds}>
            <button
              type="button"
              className={cx(styles.kindBtn, kind === '' && styles.kindOn)}
              onClick={() => setKind('')}
            >
              all
            </button>
            {KINDS.map((option) => (
              <button
                key={option}
                type="button"
                className={cx(styles.kindBtn, kind === option && styles.kindOn)}
                onClick={() => setKind(option)}
              >
                {option}
              </button>
            ))}
          </div>
        </div>

        <div className={styles.results}>
          {results.length === 0 ? (
            <div className={styles.empty}>
              {debounced || kind
                ? 'no fingerprint in the corpus matches that query'
                : 'the corpus is open; type a label or a hash to filter it'}
            </div>
          ) : (
            results.map((entry, index) => (
              <ResultRow
                key={`${entry.kind}-${entry.value}-${index}`}
                entry={entry}
              />
            ))
          )}
        </div>
      </div>
    </CropFrame>
  )
}
