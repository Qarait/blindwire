import { useState } from 'react';

type RecoveryViewProps = {
  available: boolean;
  onEnable: (passphrase: string) => void;
  onResume: (passphrase: string) => void;
};

export function RecoveryView({ available, onEnable, onResume }: RecoveryViewProps) {
  const [passphrase, setPassphrase] = useState('');
  return (
    <section className="panel recovery-panel" aria-labelledby="recovery-title">
      <div className="section-heading"><div><p className="eyebrow">Continuity</p><h2 id="recovery-title">Recovery checkpoint</h2></div><span className="status-pill">Worker vault</span></div>
      <p className="muted">Protect an encrypted checkpoint with a passphrase. The browser stores ciphertext only.</p>
      <label className="field-label" htmlFor="recovery-passphrase">Passphrase</label>
      <input id="recovery-passphrase" className="text-input" type="password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} autoComplete="off" />
      <div className="button-row"><button type="button" className="button secondary" disabled={!passphrase} onClick={() => onEnable(passphrase)}>Save checkpoint</button>{available && <button type="button" className="button ghost" disabled={!passphrase} onClick={() => onResume(passphrase)}>Resume checkpoint</button>}</div>
    </section>
  );
}
