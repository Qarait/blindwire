type VerificationViewProps = {
  emojis: string[];
  numeric: number[];
  onConfirm: () => void;
};

export function VerificationView({ emojis, numeric, onConfirm }: VerificationViewProps) {
  return (
    <section className="panel verification-panel" aria-labelledby="verification-title">
      <p className="eyebrow">Trust check</p>
      <h2 id="verification-title">Compare your security words</h2>
      <p className="muted">Read these seven symbols and numbers aloud. Continue only when both screens match.</p>
      <div className="sas-emojis" aria-label="Security emojis">{emojis.map((emoji, index) => <span key={`${emoji}-${index}`}>{emoji}</span>)}</div>
      <div className="sas-numeric" aria-label="Security numbers">{numeric.map((value, index) => <span key={`${value}-${index}`}>{String(value).padStart(2, '0')}</span>)}</div>
      <button type="button" className="button primary full-width" onClick={onConfirm}>I verified the match</button>
    </section>
  );
}
