import { useState } from 'react';
import type { PublicMessage, RoomPhase } from '../types';

type ChatViewProps = {
  phase: RoomPhase;
  messages: PublicMessage[];
  onSend: (text: string) => void;
  onLeave: () => void;
  onBurn: () => void;
};

export function ChatView({ phase, messages, onSend, onLeave, onBurn }: ChatViewProps) {
  const [text, setText] = useState('');
  const canSend = phase === 'active';
  const submit = () => {
    if (!canSend || !text.trim()) return;
    onSend(text);
    setText('');
  };
  return (
    <section className="panel chat-panel" aria-labelledby="chat-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Private channel</p>
          <h2 id="chat-title">Messages</h2>
        </div>
        <span className={`status-pill ${canSend ? 'good' : ''}`}>{canSend ? 'Active' : 'Verification required'}</span>
      </div>
      <div className="message-list" aria-live="polite">
        {messages.length === 0 ? <p className="empty-state">No messages yet.</p> : messages.map((message) => (
          <article key={message.id} className={`message ${message.direction}`}>
            <p>{message.text}</p>
            <small>{message.status === 'acknowledged' ? 'Delivered' : message.direction === 'received' ? 'Received' : 'Sending'}</small>
          </article>
        ))}
      </div>
      <div className="compose-row">
        <label className="sr-only" htmlFor="message-text">Message</label>
        <input id="message-text" className="text-input" value={text} onChange={(event) => setText(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') submit(); }} disabled={!canSend} placeholder={canSend ? 'Write a message' : 'Verify the room first'} />
        <button type="button" className="button primary" onClick={submit} disabled={!canSend || !text.trim()}>Send</button>
      </div>
      <div className="button-row destructive-actions">
        <button type="button" className="button ghost" onClick={onLeave}>Leave room</button>
        <button type="button" className="button danger" onClick={onBurn}>Burn room</button>
      </div>
    </section>
  );
}
