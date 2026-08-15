import { useEffect, useState } from 'react';
import { createController, type Controller } from './controller';
import type { ControllerState } from './types';
import { ChatView } from './components/ChatView';
import { HomeView } from './components/HomeView';
import { InviteView } from './components/InviteView';
import { JoinView } from './components/JoinView';
import { RecoveryView } from './components/RecoveryView';
import { StatusView } from './components/StatusView';
import { VerificationView } from './components/VerificationView';
import './App.css';

type AppProps = { controller: Controller };

export function App({ controller }: AppProps) {
  const [state, setState] = useState<ControllerState>(() => controller.getState());
  useEffect(() => controller.subscribe(setState), [controller]);
  const { snapshot } = state;
  const dispatch = controller.dispatch;

  return (
    <div className="app-shell">
      <header className="topbar"><div className="brand"><span className="brand-mark">B</span><span>BlindWire</span></div><span className="topbar-note">private by default</span></header>
      <main className="main-content">
        {snapshot.phase === 'idle' && !state.invite_preview && <HomeView onCreate={() => dispatch({ type: 'create_room' })} onInspect={(uri) => dispatch({ type: 'inspect_invite', uri })} />}
        {snapshot.phase === 'idle' && snapshot.recovery_available && <RecoveryView available onEnable={() => undefined} onResume={(passphrase) => dispatch({ type: 'resume_recovery', passphrase })} />}
        {snapshot.phase === 'invite_ready' && state.invite_uri && state.invite_expires_at && <InviteView uri={state.invite_uri} expiresAt={state.invite_expires_at} onCancel={() => dispatch({ type: 'leave_room' })} />}
        {snapshot.phase === 'idle' && state.invite_preview && <JoinView preview={state.invite_preview} onConfirm={() => dispatch({ type: 'confirm_join' })} onCancel={() => dispatch({ type: 'leave_room' })} />}
        {(snapshot.phase === 'connecting' || snapshot.phase === 'handshaking' || snapshot.phase === 'recovering') && <StatusView snapshot={snapshot} onReset={() => dispatch({ type: 'leave_room' })} />}
        {snapshot.phase === 'verifying' && state.verification && <VerificationView emojis={state.verification.emojis} numeric={state.verification.numeric} onConfirm={() => dispatch({ type: 'confirm_verification' })} />}
        {(snapshot.phase === 'active' || snapshot.phase === 'verifying') && <ChatView phase={snapshot.phase} messages={state.messages} onSend={(text) => dispatch({ type: 'send_text', text })} onLeave={() => dispatch({ type: 'leave_room' })} onBurn={() => dispatch({ type: 'burn_room' })} />}
        {snapshot.phase === 'active' && <RecoveryView available={snapshot.recovery_available} onEnable={(passphrase) => dispatch({ type: 'enable_recovery', passphrase })} onResume={(passphrase) => dispatch({ type: 'resume_recovery', passphrase })} />}
        {(snapshot.phase === 'fatal_error' || snapshot.phase === 'peer_disconnected' || snapshot.phase === 'burned') && <StatusView snapshot={snapshot} onReset={() => dispatch({ type: 'leave_room' })} />}
      </main>
      <footer className="footer"><span>Protocol 2.1</span><span>Web Worker + WebAssembly</span><span>Session state is ephemeral</span></footer>
    </div>
  );
}

export function createBrowserController(): Controller {
  const worker = new Worker(new URL('./worker/entry.ts', import.meta.url), { type: 'module' });
  return createController(worker);
}
