import type { RoomSnapshot } from '../types';

export function StatusView({ snapshot, onReset }: { snapshot: RoomSnapshot; onReset: () => void }) {
  const terminal = snapshot.phase === 'fatal_error' || snapshot.phase === 'burned' || snapshot.phase === 'peer_disconnected';
  const title = snapshot.phase === 'burned' ? 'Room burned' : snapshot.phase === 'peer_disconnected' ? 'The other person left' : snapshot.phase === 'fatal_error' ? 'Room stopped safely' : snapshot.phase === 'invite_ready' ? 'Invite ready' : 'Connecting securely';
  return (
    <section className="panel status-panel" aria-live="polite">
      <div className="loader-mark" aria-hidden="true">{terminal ? '·' : '◌'}</div>
      <p className="eyebrow">{snapshot.relay_label ?? 'BlindWire'}</p>
      <h2>{title}</h2>
      <p className="muted">{snapshot.error?.message ?? (snapshot.phase === 'handshaking' ? 'Establishing the encrypted handshake.' : 'Only the dedicated worker can see the live session.')}</p>
      {snapshot.error && <p className="error-copy">{snapshot.error.code}</p>}
      {terminal && <button type="button" className="button secondary" onClick={onReset}>Return home</button>}
    </section>
  );
}
