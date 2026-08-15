import type {
  ControllerState,
  PublicMessage,
  RoomSnapshot,
  WorkerCommand,
  WorkerEvent,
} from './types';

export type WorkerLike = {
  postMessage(message: WorkerCommand): void;
  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerEvent>) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent<WorkerEvent>) => void): void;
  terminate(): void;
};

export type Controller = {
  dispatch(command: WorkerCommand): void;
  handleEvent(event: WorkerEvent): void;
  subscribe(listener: (state: ControllerState) => void): () => void;
  getState(): ControllerState;
  terminate(): void;
};

const emptySnapshot = (): RoomSnapshot => ({
  phase: 'idle',
  role: null,
  room_label: null,
  relay_label: null,
  local_verified: false,
  peer_verified: false,
  recovery_available: false,
  error: null,
});

export function initialControllerState(): ControllerState {
  return {
    snapshot: emptySnapshot(),
    invite_uri: null,
    invite_expires_at: null,
    invite_preview: null,
    verification: null,
    messages: [],
  };
}

export function reduceSnapshot(snapshot: RoomSnapshot, event: WorkerEvent): RoomSnapshot {
  if (event.type === 'state') {
    return event.snapshot;
  }
  if (event.type === 'recovery_available') {
    return { ...snapshot, recovery_available: true };
  }
  if (event.type === 'recovered') {
    return { ...snapshot, phase: 'active', recovery_available: true, error: null };
  }
  if (event.type === 'error') {
    return { ...snapshot, phase: 'fatal_error', error: event.error };
  }
  return snapshot;
}

export function reduceControllerState(state: ControllerState, event: WorkerEvent): ControllerState {
  const snapshot = reduceSnapshot(state.snapshot, event);
  switch (event.type) {
    case 'state':
      if (event.snapshot.phase === 'idle') {
        return {
          ...state,
          snapshot,
          invite_uri: null,
          invite_expires_at: null,
          invite_preview: null,
          verification: null,
          messages: [],
        };
      }
      return { ...state, snapshot };
    case 'invite_ready':
      return {
        ...state,
        snapshot: { ...snapshot, phase: 'invite_ready' },
        invite_uri: event.uri,
        invite_expires_at: event.expires_at,
      };
    case 'invite_preview':
      return { ...state, invite_preview: event.preview };
    case 'verification_ready':
      return {
        ...state,
        snapshot: { ...snapshot, phase: 'verifying' },
        verification: { emojis: [...event.emojis], numeric: [...event.numeric] },
      };
    case 'message_queued':
      return {
        ...state,
        messages: upsertMessage(state.messages, {
          id: event.id,
          text: event.text,
          timestamp: event.timestamp,
          direction: 'sent',
          status: 'queued',
        }),
      };
    case 'message_received':
      return {
        ...state,
        messages: upsertMessage(state.messages, {
          id: event.id,
          text: event.text,
          timestamp: event.timestamp,
          direction: 'received',
          status: 'received',
        }),
      };
    case 'message_acknowledged':
      return {
        ...state,
        messages: state.messages.map((message) =>
          message.id === event.id ? { ...message, status: 'acknowledged' } : message,
        ),
      };
    case 'recovery_available':
    case 'recovered':
    case 'error':
      return { ...state, snapshot };
  }
}

function upsertMessage(messages: PublicMessage[], message: PublicMessage): PublicMessage[] {
  const existing = messages.findIndex((item) => item.id === message.id);
  if (existing === -1) {
    return [...messages, message];
  }
  return messages.map((item, index) => (index === existing ? { ...item, ...message } : item));
}

export function createController(worker: WorkerLike): Controller {
  let state = initialControllerState();
  const subscribers = new Set<(state: ControllerState) => void>();
  const onMessage = (event: MessageEvent<WorkerEvent>) => {
    state = reduceControllerState(state, event.data);
    for (const subscriber of subscribers) {
      subscriber(state);
    }
  };

  worker.addEventListener('message', onMessage);

  return {
    dispatch(command) {
      worker.postMessage(command);
    },
    handleEvent(event) {
      onMessage(new MessageEvent('message', { data: event }));
    },
    subscribe(listener) {
      subscribers.add(listener);
      return () => subscribers.delete(listener);
    },
    getState() {
      return state;
    },
    terminate() {
      worker.removeEventListener('message', onMessage);
      subscribers.clear();
      worker.terminate();
    },
  };
}
