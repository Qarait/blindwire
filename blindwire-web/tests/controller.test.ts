import { describe, expect, it } from 'vitest';
import {
  createController,
  initialControllerState,
  type WorkerLike,
} from '../src/controller';
import type { WorkerEvent } from '../src/types';

class RecordingWorker implements WorkerLike {
  readonly sent: unknown[] = [];
  private readonly listeners = new Set<(event: MessageEvent<WorkerEvent>) => void>();

  postMessage(message: unknown): void {
    this.sent.push(message);
  }

  addEventListener(_type: 'message', listener: (event: MessageEvent<WorkerEvent>) => void): void {
    this.listeners.add(listener);
  }

  removeEventListener(_type: 'message', listener: (event: MessageEvent<WorkerEvent>) => void): void {
    this.listeners.delete(listener);
  }

  emit(data: WorkerEvent): void {
    for (const listener of this.listeners) {
      listener(new MessageEvent('message', { data }));
    }
  }

  terminate(): void {}
}

describe('browser Worker controller', () => {
  it('serializes commands without changing their public values', () => {
    const worker = new RecordingWorker();
    const controller = createController(worker);
    const command = { type: 'send_text' as const, text: 'hello from the UI' };

    controller.dispatch(command);

    expect(worker.sent).toEqual([command]);
  });

  it('projects public state and events without secret-bearing fields', () => {
    const worker = new RecordingWorker();
    const controller = createController(worker);
    worker.emit({
      type: 'state',
      snapshot: {
        phase: 'active',
        role: 'initiator',
        room_label: 'AAAA…',
        relay_label: 'relay.blindwire.net',
        local_verified: true,
        peer_verified: true,
        recovery_available: false,
        error: null,
      },
    });
    worker.emit({ type: 'message_received', id: 'message-1', text: 'hello', timestamp: 10 });

    const state = controller.getState();
    expect(state.snapshot.phase).toBe('active');
    expect(state.messages).toEqual([{ id: 'message-1', text: 'hello', timestamp: 10, direction: 'received', status: 'received' }]);
    expect(JSON.stringify(state)).not.toContain('capability');
    expect(JSON.stringify(state)).not.toContain('ciphertext');
  });

  it('notifies subscribers and removes them cleanly', () => {
    const worker = new RecordingWorker();
    const controller = createController(worker);
    const snapshots: string[] = [];
    const unsubscribe = controller.subscribe((state) => snapshots.push(state.snapshot.phase));

    worker.emit({ type: 'state', snapshot: { ...initialControllerState().snapshot, phase: 'connecting' } });
    unsubscribe();
    worker.emit({ type: 'state', snapshot: { ...initialControllerState().snapshot, phase: 'active' } });

    expect(snapshots).toEqual(['connecting']);
  });
});
