import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getBridge } from '../bridge';
import type { Rule, TrustedPublisher } from '../types';

interface Loaded {
  rules: Rule[];
  publishers: TrustedPublisher[];
}

export function RulesTrust() {
  const { t } = useTranslation();
  const [data, setData] = useState<Loaded | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    getBridge()
      .then((b) =>
        Promise.all([
          b.rpc<{ rules: Rule[] }>('rule.list'),
          b.rpc<{ publishers: TrustedPublisher[] }>('trust.list'),
        ]),
      )
      .then(([r, p]) => live && setData({ rules: r.rules, publishers: p.publishers }))
      .catch((e: unknown) => live && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      live = false;
    };
  }, []);

  if (error) return <p role="alert">{t('rules.error', { message: error })}</p>;
  if (!data) return <p className="muted">{t('table.loading')}</p>;

  return (
    <>
      <section className="card">
        <h2>{t('rules.rules')}</h2>
        <ul className="list">
          {data.rules.map((r) => (
            <li key={r.id}>
              <span>
                <span className="mono">{r.id}</span> {r.name}
              </span>
              <span className="chip">{t(`rules.${r.source === 'builtin' ? 'builtin' : 'user'}`)}</span>
            </li>
          ))}
        </ul>
      </section>
      <section className="card">
        <h2>{t('rules.publishers')}</h2>
        <ul className="list">
          {data.publishers.map((p) => (
            <li key={p.id}>
              <span>{p.subject_org}</span>
              <span className="chip">{t(`rules.${p.source === 'builtin' ? 'builtin' : 'user'}`)}</span>
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}
