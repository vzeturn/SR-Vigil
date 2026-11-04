import { useVirtualizer } from '@tanstack/react-virtual';
import { useRef, type ReactNode } from 'react';

const ROW_HEIGHT = 36;

export interface Column<T> {
  header: string;
  width: string;
  cell: (row: T) => ReactNode;
}

interface VirtualTableProps<T> {
  rows: readonly T[];
  columns: readonly Column<T>[];
  rowKey: (row: T) => string;
  empty: string;
  label: string;
}

/** Fixed-height rows, only the visible window is mounted (5,000+ rows stay smooth). */
export function VirtualTable<T>({ rows, columns, rowKey, empty, label }: VirtualTableProps<T>) {
  const scroller = useRef<HTMLDivElement>(null);
  // TanStack's functions are not memoizable by React Compiler; we don't use the compiler, and the
  // virtualizer is read only in this component's render, so nothing stale can leak out.
  // eslint-disable-next-line react-hooks/incompatible-library
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
    initialRect: { width: 1000, height: 600 },
  });
  const template = columns.map((c) => c.width).join(' ');

  return (
    <div className="card" role="table" aria-label={label} aria-rowcount={rows.length}>
      <div className="grid-head" role="row" style={{ gridTemplateColumns: template }}>
        {columns.map((c) => (
          <span key={c.header} role="columnheader">
            {c.header}
          </span>
        ))}
      </div>
      {rows.length === 0 && <p className="muted">{empty}</p>}
      {/* Always mounted so the virtualizer has a scroll element before the first rows arrive. */}
      <div ref={scroller} className="scroller">
        <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
          {virtualizer.getVirtualItems().map((item) => {
            const row = rows[item.index];
            if (!row) return null;
            return (
              <div
                key={rowKey(row)}
                className="grid-row"
                role="row"
                style={{ gridTemplateColumns: template, transform: `translateY(${item.start}px)` }}
              >
                {columns.map((c) => (
                  <span key={c.header} role="cell">
                    {c.cell(row)}
                  </span>
                ))}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
