import { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { QRCodeSVG } from 'qrcode.react';
import './App.css';

// --- Type Definitions based on Rust API ---
type AppError = { code: string; message: string; retryable: boolean };
type ParsedInviteSummary = { invite_handle: string; room: string; relay_label: string; is_custom_relay: boolean; expires_at: number };
type RoomInfo = { invite_uri: string; qr_string: string; room_id: string };

type VerificationState = { identicon_seed: string; emojis: string[]; verified: boolean };
type RoomPhase = 'idle' | 'connecting' | 'verifying' | 'active' | 'peer_disconnected' | 'fatal_error';
type RoomSnapshot = {
  phase: RoomPhase;
  generation: number;
  revision: number;
  peer_verified: boolean;
  room: string | null;
  verification: VerificationState | null;
  error: AppError | null;
};

type ViewState =
  | { type: 'HOME' }
  | { type: 'CONFIRM_JOIN'; summary: ParsedInviteSummary }
  | { type: 'INVITE_QR'; info: RoomInfo }
  | { type: 'CONNECTING' }
  | { type: 'VERIFYING'; peer: VerificationState }
  | { type: 'CHAT'; room: string; peer_disconnected?: boolean }
  | { type: 'ERROR'; error: AppError };

function App() {
  const [view, setViewState] = useState<ViewState>({ type: 'HOME' });
  const [linkInput, setLinkInput] = useState('');
  const [messages, setMessages] = useState<{ text: string; timestamp: number; isMe: boolean }[]>([]);
  const [chatInput, setChatInput] = useState('');
  const latestSnapshot = useRef({ generation: -1, revision: -1 });
  const pendingInvite = useRef<ParsedInviteSummary | null>(null);

  useEffect(() => {
    // Listen for blindwire:// links
    const unlistenDeepLink = listen<string>('blindwire-deep-link', async (event) => {
      handleParseInvite(event.payload);
    });

    // Listen for inbound messages
    const unlistenMsg = listen<{ text: string; timestamp: number }>('message_received', (event) => {
      setMessages(m => [...m, { ...event.payload, isMe: false }]);
    });

    const applyRoomSnapshot = (snapshot: RoomSnapshot) => {
      const latest = latestSnapshot.current;
      if (
        snapshot.generation < latest.generation
        || (snapshot.generation === latest.generation && snapshot.revision <= latest.revision)
      ) {
        return;
      }
      latestSnapshot.current = { generation: snapshot.generation, revision: snapshot.revision };

      switch (snapshot.phase) {
        case 'idle':
          if (snapshot.error && pendingInvite.current) {
            setViewState({ type: 'CONFIRM_JOIN', summary: pendingInvite.current });
          } else if (snapshot.error) {
            setViewState({ type: 'ERROR', error: snapshot.error });
          } else {
            setViewState({ type: 'HOME' });
          }
          break;
        case 'connecting':
          setViewState({ type: 'CONNECTING' });
          break;
        case 'verifying':
          if (snapshot.verification) {
            setViewState({ type: 'VERIFYING', peer: snapshot.verification });
          }
          break;
        case 'active':
          pendingInvite.current = null;
          setViewState({ type: 'CHAT', room: snapshot.room ?? '', peer_disconnected: false });
          break;
        case 'peer_disconnected':
          setViewState({ type: 'CHAT', room: snapshot.room ?? '', peer_disconnected: true });
          break;
        case 'fatal_error':
          pendingInvite.current = null;
          setViewState({
            type: 'ERROR',
            error: snapshot.error ?? { code: 'SESSION_ENDED', message: 'The secure session ended.', retryable: false },
          });
          break;
      }
    };

    const unlistenRoom = listen<RoomSnapshot>('room_state_changed', (event) => {
      applyRoomSnapshot(event.payload);
    });

    invoke<RoomSnapshot>('get_room_snapshot').then(applyRoomSnapshot).catch(() => {});

    // Let Rust know the UI is ready to receive queued events
    invoke('frontend_ready').catch(() => {});

    return () => {
      unlistenDeepLink.then(f => f());
      unlistenRoom.then(f => f());
      unlistenMsg.then(f => f());
    };
  }, []);

  const handleParseInvite = async (uri: string) => {
    try {
      const summary = await invoke<ParsedInviteSummary>('parse_invite', { uri });
      pendingInvite.current = summary;
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
      setViewState({ type: 'INVITE_QR', info });
    } catch (e: any) {
      setViewState({ type: 'ERROR', error: e as AppError });
    }
  };

  const handleSendMessage = async () => {
    if (!chatInput.trim()) return;
    try {
      const text = chatInput;
      await invoke('send_message', { text });
      setMessages(m => [...m, { text, timestamp: Date.now(), isMe: true }]);
      setChatInput('');
    } catch (e: any) {
      setViewState({ type: 'ERROR', error: e as AppError });
    }
  };

  const clearMessages = () => {
    setMessages([]);
    setChatInput('');
  };

  return (
    <>
      <div className="bg-mesh"></div>
      <div className="app-container">
        {view.type === 'HOME' && (
          <div className="glass-card">
            <h1>BlindWire</h1>
            <p>Secure, canonical rendezvous.</p>

            <button onClick={() => { clearMessages(); handleCreateRoom(); }}>
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

        {view.type === 'INVITE_QR' && (
          <div className="glass-card">
            <h1>Invite Peer</h1>
            <p>Share this link or scan the QR code to start the secure session.</p>

            <div className="qr-container">
              <QRCodeSVG
                value={view.info.qr_string}
                data-qr-value={view.info.qr_string}
                size={220}
                level="M"
                marginSize={2}
                title="BlindWire invite QR code"
              />
            </div>

            <div className="info-row">
              <span className="info-label">Invite Link</span>
              <input
                type="text"
                readOnly
                value={view.info.invite_uri}
                className="invite-link-input"
                id="invite-link-input"
                style={{ width: '100%', marginTop: '0.5rem' }}
              />
            </div>

            <div style={{ display: 'flex', gap: '1rem', marginTop: '1.5rem' }}>
              <button className="secondary" onClick={async () => { try { await invoke('leave_room'); } catch(e){} setViewState({ type: 'HOME' }); }}>Cancel</button>
              <button onClick={() => {
                // In a real app we'd wait for PeerJoined event, 
                // but we can also manually "Proceed" if we want to watch the handshake
              }}>Waiting for peer...</button>
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

        {view.type === 'CHAT' && (
          <div className="chat-container">
            <div className="chat-messages">
              <p style={{ textAlign: 'center', opacity: 0.5, marginBottom: '1rem' }}>
                Connected to room {view.room}
              </p>
              {messages.map((m, i) => (
                <div key={i} className={`message-bubble ${m.isMe ? 'me' : 'peer'}`}>
                  <div className="message-content">{m.text}</div>
                  <div className="message-time">{new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
                </div>
              ))}
            </div>
            <div className="chat-input-area">
              <input
                type="text"
                placeholder={view.peer_disconnected ? "Peer disconnected" : "Send an encrypted message..."}
                value={chatInput}
                onChange={e => setChatInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && !view.peer_disconnected && handleSendMessage()}
                disabled={view.peer_disconnected}
                id="chat-input"
              />
              <button 
                onClick={handleSendMessage} 
                disabled={view.peer_disconnected}
                id="chat-send"
              >
                Send
              </button>
              <button className="danger" onClick={async () => { 
                await invoke('leave_room');
                clearMessages(); 
                setViewState({ type: 'HOME' }); 
              }}>Leave</button>
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
