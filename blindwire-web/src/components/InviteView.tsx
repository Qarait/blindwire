import { QRCodeSVG } from 'qrcode.react';

type InviteViewProps = {
  uri: string;
  expiresAt: number;
  onCancel: () => void;
};

export function InviteView({ uri, expiresAt, onCancel }: InviteViewProps) {
  return (
    <section className="panel invite-panel" aria-labelledby="invite-title">
      <p className="eyebrow">Room created</p>
      <h2 id="invite-title">Share this one-time invite</h2>
      <p className="muted">The other person can scan the QR code or copy the exact link. It expires {new Date(expiresAt).toLocaleTimeString()}.</p>
      <div className="qr-frame" data-testid="invite-qr" data-qr-value={uri}>
        <QRCodeSVG value={uri} size={224} level="M" includeMargin />
      </div>
      <label className="field-label" htmlFor="invite-link">Invite link</label>
      <input id="invite-link" className="text-input mono" value={uri} readOnly />
      <div className="button-row">
        <button type="button" className="button secondary" onClick={() => void navigator.clipboard?.writeText(uri)}>Copy link</button>
        <button type="button" className="button ghost" onClick={onCancel}>Cancel room</button>
      </div>
    </section>
  );
}
