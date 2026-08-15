import type { InvitePreview } from '../types';

type JoinViewProps = {
  preview: InvitePreview;
  onConfirm: () => void;
  onCancel: () => void;
};

export function JoinView({ preview, onConfirm, onCancel }: JoinViewProps) {
  return (
    <section className="panel join-confirm-panel" aria-labelledby="join-title">
      <p className="eyebrow">Invite inspected</p>
      <h2 id="join-title">Ready to connect?</h2>
      <dl className="detail-list">
        <div><dt>Room</dt><dd className="mono">{preview.room_label}</dd></div>
        <div><dt>Relay</dt><dd>{preview.relay_label}</dd></div>
        <div><dt>Trust</dt><dd>{preview.official_relay ? 'Official BlindWire relay' : 'Local development relay'}</dd></div>
        <div><dt>Expires</dt><dd>{new Date(preview.expires_at).toLocaleString()}</dd></div>
      </dl>
      <p className="muted">You will compare a security code with the person who shared this invite before any chat opens.</p>
      <div className="button-row"><button type="button" className="button primary" onClick={onConfirm}>Join room</button><button type="button" className="button ghost" onClick={onCancel}>Cancel</button></div>
    </section>
  );
}
