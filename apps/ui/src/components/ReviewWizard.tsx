import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { PendingItem } from '../types';
import { AiAssessment } from './AiAssessment';
import { DecisionControls } from './DecisionControls';
import { Dialog } from './Dialog';
import { destinationText, itemName } from './pendingView';
import { VerdictChip } from './VerdictChip';

const STEPS = ['what', 'why', 'act'] as const;

interface Props {
  item: PendingItem;
  onClose: () => void;
}

/** Three steps: what is it, why this verdict, choose an action. */
export function ReviewWizard({ item, onClose }: Props) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const { identity, evaluation, ai_opinion: ai } = item;

  return (
    <Dialog title={t('wizard.title', { name: itemName(item) })} onClose={onClose}>
      <ol className="steps" aria-label={t('wizard.steps')}>
        {STEPS.map((s, i) => (
          <li key={s} aria-current={i === step ? 'step' : undefined} className={i === step ? 'on' : ''}>
            {t('wizard.step', { n: i + 1, name: t(`wizard.${s}`) })}
          </li>
        ))}
      </ol>

      {step === 0 && (
        <dl className="facts">
          <dt>{t('table.name')}</dt>
          <dd>{itemName(item)}</dd>
          <dt>{t('table.path')}</dt>
          <dd className="mono">{identity.path}</dd>
          <dt>{t('pending.publisher')}</dt>
          <dd>{identity.publisher ?? t('pending.noPublisher')}</dd>
          <dt>{t('wizard.signature')}</dt>
          <dd>{t(`signature.${identity.signature_status}`)}</dd>
          <dt>{t('wizard.sha256')}</dt>
          <dd className="mono">{identity.sha256}</dd>
          <dt>{t('pending.destination')}</dt>
          <dd className="mono">{destinationText(item)}</dd>
        </dl>
      )}

      {step === 1 && (
        <div>
          <p className="toolbar">
            <VerdictChip verdict={evaluation.verdict} />
            <span>{t('pending.score', { score: evaluation.score })}</span>
            {evaluation.hard_rule && <span className="chip malicious">{evaluation.hard_rule}</span>}
          </p>
          <h3>{t('wizard.signals')}</h3>
          {evaluation.signals.length === 0 ? (
            <p className="muted">{t('wizard.noSignals')}</p>
          ) : (
            <ul className="list">
              {evaluation.signals.map((s) => (
                <li key={s.id}>
                  <span>
                    {s.name} {s.detail && <span className="muted">{s.detail}</span>}
                  </span>
                  <span className="mono">{s.delta > 0 ? `+${s.delta}` : s.delta}</span>
                </li>
              ))}
            </ul>
          )}
          {ai && <AiAssessment opinion={ai} />}
        </div>
      )}

      {step === 2 && <DecisionControls item={item} onDone={onClose} />}

      <div className="dialog-foot">
        <button type="button" className="btn" onClick={onClose}>
          {t('wizard.cancel')}
        </button>
        <span className="spacer" />
        <button type="button" className="btn" disabled={step === 0} onClick={() => setStep(step - 1)}>
          {t('wizard.back')}
        </button>
        <button type="button" className="btn" disabled={step === STEPS.length - 1} onClick={() => setStep(step + 1)}>
          {t('wizard.next')}
        </button>
      </div>
    </Dialog>
  );
}
