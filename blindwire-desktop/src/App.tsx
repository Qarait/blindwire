import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import './App.css';

// --- Type Definitions based on Rust API ---
type AppError = { code: string; message: string; retryable: boolean };
type ParsedInviteSummary = { invite_handle: string; room: string; relay_label: string; is_custom_relay: boolean; expires_at: number };
type RoomInfo = { invite_uri: string; qr_string: string; room_id: string };

type VerificationState = { identicon_seed: string; emojis: string[]; verified: boolean };
type IdentityInfo = { relay: string; old_identicon: string; old_sas: string[]; new_identicon: string; new_sas: string[]; change_id: string };

type ViewState =
  | { type: 'HOME' }
  | { type: 'CONFIRM_JOIN'; summary: ParsedInviteSummary }
  | { type: 'CONNECTING' }
  | { type: 'VERIFYING'; peer: VerificationState }
  | { type: 'IDENTITY_CHANGE'; info: IdentityInfo }
  | { type: 'CHAT'; room: string }
  | { type: 'ERROR'; error: AppError };

function App() {
  const [view, setViewState] = useState<ViewState>({ type: 'HOME' });
  const [linkInput, setLinkInput] = useState('');

  useEffect(() => {
    // Listen for blindwire:// links
    const unlistenDeepLink = listen<string>('blindwire-deep-link', async (event) => {
      console.log("Received deep link:", event.payload);
      handleParseInvite(event.payload);
    });

    // Listen for peer verification
    const unlistenVerify = listen<VerificationState>('verification_state_changed', (event) => {
      setViewState({ type: 'VERIFYING', peer: event.payload });
    });

    // Listen for identity change requirement
    const unlistenIdentity = listen<IdentityInfo>('identity_change_required', (event) => {
      setViewState({ type: 'IDENTITY_CHANGE', info: event.payload });
    });

    // Listen for room entry
    const unlistenRoom = listen<{ room: string }>('room_state_changed', (event) => {
      setViewState({ type: 'CHAT', room: event.payload.room });
    });

    // Let Rust know the UI is ready to receive queued events
    invoke('frontend_ready').catch(console.error);

    return () => {
      unlistenDeepLink.then(f => f());
      unlistenVerify.then(f => f());
      unlistenIdentity.then(f => f());
      unlistenRoom.then(f => f());
    };
  }, []);

  const handleParseInvite = async (uri: string) => {
    try {
      const summary = await invoke<ParsedInviteSummary>('parse_invite', { uri });
      setViewState({ type: 'CONFIRM_JOIN', summary });
    } catch (e: any) {
      setViewState({ type: 'ERROR', error: e as AppError });
    }
  };

  const handleJoin = async (invite_handle: string) => {
    setViewState({ type: 'CONNECTING' });
    try {
      await invoke('join_room', { inviteHandle: invite_handle });
      // The actual transition to chat/verification will happen via Rust events later
    } catch (e: any) {
      setViewState({ type: 'ERROR', error: e as AppError });
    }
  };

  const handleCreateRoom = async () => {
    setViewState({ type: 'CONNECTING' });
    try {
      const info = await invoke<RoomInfo>('create_room');
      // Transition out
      setViewState({ type: 'CHAT', room: info.room_id });
    } catch (e: any) {
      setViewState({ type: 'ERROR', error: e as AppError });
    }
  };

  return (
    <>
      <div className="bg-mesh"></div>
      <div className="app-container">
        {view.type === 'HOME' && (
          <div className="glass-card">
            <h1>BlindWire</h1>
            <p>Secure, canonical rendezvous.</p>

            <button onClick={handleCreateRoom}>
              Create Secure Room
            </button>

            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
              <input
                type="text"
                placeholder="Paste blindwire:// link"
                value={linkInput}
                onChange={e => setLinkInput(e.target.value)}
              />
              <button onClick={() => handleParseInvite(linkInput)} style={{ width: 'auto' }}>Go</button>
            </div>
          </div>
        )}

        {view.type === 'CONFIRM_JOIN' && (
          <div className="glass-card">
            <h1>Join Room</h1>
            <div className="info-row">
              <span className="info-label">Room ID</span>
              <span className="info-value">{view.summary.room}</span>
            </div>
            <div className="info-row">
              <span className="info-label">Relay</span>
              <span className="info-value">{view.summary.relay_label}</span>
            </div>
            {view.summary.is_custom_relay && (
              <div style={{ color: 'var(--accent-color)', fontSize: '0.875rem', marginTop: '0.5rem' }}>
                This room uses a custom designated relay server.
              </div>
            )}

            <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
              <button className="secondary" onClick={() => setViewState({ type: 'HOME' })}>Cancel</button>
              <button onClick={() => handleJoin(view.summary.invite_handle)}>Connect</button>
            </div>
          </div>
        )}

        {view.type === 'CONNECTING' && (
          <div className="glass-card" style={{ alignItems: 'center' }}>
            <div className="spinner"></div>
            <p style={{ marginTop: '1rem' }}>Establishing secure connection...</p>
          </div>
        )}

        {view.type === 'VERIFYING' && (
          <div className="glass-card">
            <h1>Verify Peer</h1>
            <p>Ensure these emojis match the other device.</p>
            <div className="sas-grid">
              {view.peer.emojis.map((emoji, i) => (
                <div key={i} className="sas-emoji">{emoji}</div>
              ))}
            </div>
            <div style={{ marginTop: '2rem' }}>
              <button onClick={async () => {
                await invoke('confirm_peer_verified');
              }}>Matches (Verified)</button>
            </div>
          </div>
        )}

        {view.type === 'IDENTITY_CHANGE' && (
          <div className="glass-card" style={{ borderColor: 'var(--danger-color)' }}>
            <h1 style={{ color: 'var(--danger-color)', backgroundImage: 'none', WebkitTextFillColor: 'var(--danger-color)' }}>Security Alert</h1>
            <p style={{ color: 'white' }}>The server <strong>{view.info.relay}</strong> has changed its cryptographic identity.</p>
            <p style={{ marginTop: '1rem', fontSize: '0.85rem' }}>This usually means the server was reinstalled, but it could mean someone is impersonating it to intercept your connection.</p>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.5rem' }}>
              <button className="secondary" onClick={() => setViewState({ type: 'HOME' })}>Abort</button>
              <button className="danger" onClick={async () => {
                await invoke('trust_new_server_identity', { changeId: view.info.change_id });
                setViewState({ type: 'CONNECTING' });
              }}>Trust New Identity</button>
            </div>
          </div>
        )}

        {view.type === 'CHAT' && (
          <div className="chat-container">
            <div className="chat-messages">
              <p style={{ textAlign: 'center', opacity: 0.5 }}>Connected to room {view.room}</p>
            </div>
            <div className="chat-input-area">
              <input type="text" placeholder="Send an encrypted message..." />
              <button>Send</button>
              <button className="danger" onClick={() => setViewState({ type: 'HOME' })}>Leave</button>
            </div>
          </div>
        )}

        {view.type === 'ERROR' && (
          <div className="glass-card">
            <h1 style={{ color: 'var(--danger-color)', backgroundImage: 'none', WebkitTextFillColor: 'var(--danger-color)' }}>Connection Error</h1>
            <p>{view.error.message || "An unknown error occurred."}</p>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
              <button className="secondary" onClick={() => setViewState({ type: 'HOME' })}>Back</button>
              {view.error.retryable && (
                <button onClick={() => setViewState({ type: 'HOME' })}>Retry</button>
              )}
            </div>
          </div>
        )}

      </div>
    </>
  );
}

export default App;
