import { installWorker } from './worker';

installWorker(self as unknown as {
  postMessage(event: import('../types').WorkerEvent): void;
  onmessage: ((event: MessageEvent<import('../types').WorkerCommand>) => void) | null;
});
