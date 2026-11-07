import { BookOpenText, CircleAlert, LoaderCircle, RotateCw } from 'lucide-react';
import type { AiAnalysis } from '../data/types';
import { useTimeFormat } from '../lib/time';
import { Button } from './ui';

/**
 * AI explanation panel.
 * Visually separated from detection data (different surface, labelled
 * role) so users never confuse an explanation with the detection itself.
 */
export function AiPanel({
  ai,
  detectedBy,
  onRequest,
}: {
  ai: AiAnalysis;
  /** e.g. "Rule RM-SSH-001" or "Check SC-SSH-001" */
  detectedBy: string;
  onRequest: () => void;
}) {
  const { when } = useTimeFormat();

  return (
    <section className="ai" aria-label="AI explanation">
      <header className="ai__head">
        <BookOpenText className="ai__icon" aria-hidden />
        <div>
          <h2 className="ai__title">AI explanation</h2>
          <p className="ai__role">
            {ai.role} · Key {ai.keySlot ?? (ai.role === 'RM Analysis Agent' ? 'AEGIS1' : ai.role === 'SC Analysis Agent' ? 'AEGIS2' : 'AEGIS3')}
            {ai.state === 'ready' && ai.generatedAt && <> · {when(ai.generatedAt)}</>}
          </p>
        </div>
      </header>

      {ai.state === 'not_requested' && (
        <div className="ai__body">
          <p className="ai__muted">
            Not generated yet. The backend will send filtered context for this item only — no raw logs, secrets or evidence
            files.
          </p>
          <Button icon={BookOpenText} onClick={onRequest} size="sm">
            Request explanation
          </Button>
        </div>
      )}

      {ai.state === 'pending' && (
        <div className="ai__body ai__pending" aria-live="polite">
          <LoaderCircle className="spin" aria-hidden />
          <span>Generating explanation…</span>
        </div>
      )}

      {ai.state === 'failed' && (
        <div className="ai__body">
          <p className="ai__error">
            <CircleAlert aria-hidden />
            <span>{ai.error ?? 'The AI provider returned an error.'}</span>
          </p>
          <Button icon={RotateCw} onClick={onRequest} size="sm">
            Retry
          </Button>
        </div>
      )}

      {ai.state === 'ready' && (
        <div className="ai__body">
          <p className="ai__summary">{ai.summary}</p>

          {ai.uncertainty && (
            <div className="ai__block">
              <h3>Limits &amp; uncertainty</h3>
              <p>{ai.uncertainty}</p>
            </div>
          )}

          {ai.nextSteps && ai.nextSteps.length > 0 && (
            <div className="ai__block">
              <h3>Suggested investigation steps</h3>
              <ol>
                {ai.nextSteps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            </div>
          )}

          {ai.evidenceRefs && (
            <div className="ai__block">
              <h3>Based on</h3>
              <ul className="ai__refs">
                {ai.evidenceRefs.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <p className="ai__foot">
        Detected by {detectedBy}, not by AI. Explanations can be wrong — verify against the evidence above.
      </p>
    </section>
  );
}

