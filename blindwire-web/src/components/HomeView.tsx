import { useState } from 'react';

type HomeViewProps = {
  onCreate: () => void;
  onInspect: (uri: string) => void;
};

export function HomeView({ onCreate, onInspect }: HomeViewProps) {
  const [uri, setUri] = useState('');
  return (
    <section className="home-grid">
      <div className="hero-copy">
        <p className="eyebrow">BlindWire / browser</p>
        <h1>Private rooms,<br /><span>no account required.</span></h1>
        <p className="hero-lede">A short-lived encrypted room for conversations that should stay between the people in it.</p>
        <button type="button" className="button primary large" onClick={onCreate}>Create a private room <span aria-hidden="true">↗</span></button>
      </div>
      <div className="panel join-panel">
        <p className="eyebrow">Joining someone</p>
        <h2>Have an invite?</h2>
        <p className="muted">Paste the complete BlindWire link. It is checked inside the secure session worker.</p>
        <label className="field-label" htmlFor="invite-input">Invite link</label>
        <textarea id="invite-input" className="text-input invite-textarea" value={uri} onChange={(event) => setUri(event.target.value)} placeholder="blindwire://join?..." rows={4} />
        <button type="button" className="button secondary full-width" disabled={!uri.trim()} onClick={() => onInspect(uri.trim())}>Inspect invite</button>
      </div>
    </section>
  );
}
