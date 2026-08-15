import type { InvitePreview as InvitePreviewType } from './invite';

export type InvitePreview = InvitePreviewType;

export type RoomPhase =
  | 'idle'
  | 'invite_ready'
  | 'connecting'
  | 'handshaking'
  | 'verifying'
  | 'active'
  | 'recovering'
  | 'peer_disconnected'
  | 'burned'
  | 'fatal_error';

export type PublicError = {
  code: string;
  message: string;
  retryable: boolean;
};

export type RoomSnapshot = {
  phase: RoomPhase;
  role: 'initiator' | 'responder' | null;
  room_label: string | null;
  relay_label: string | null;
  local_verified: boolean;
  peer_verified: boolean;
  recovery_available: boolean;
  error: PublicError | null;
};

export type WorkerCommand =
  | { type: 'create_room' }
  | { type: 'inspect_invite'; uri: string }
  | { type: 'confirm_join' }
  | { type: 'confirm_verification' }
  | { type: 'send_text'; text: string }
  | { type: 'enable_recovery'; passphrase: string }
  | { type: 'resume_recovery'; passphrase: string }
  | { type: 'burn_room' }
  | { type: 'leave_room' };

export type VerificationState = {
  emojis: string[];
  numeric: number[];
};

export type PublicMessage = {
  id: string;
  text: string;
  timestamp: number;
  direction: 'sent' | 'received';
  status: 'queued' | 'received' | 'acknowledged';
};

export type WorkerEvent =
  | { type: 'state'; snapshot: RoomSnapshot }
  | { type: 'invite_ready'; uri: string; expires_at: number }
  | { type: 'invite_preview'; preview: InvitePreview }
  | { type: 'verification_ready'; emojis: string[]; numeric: number[] }
  | { type: 'message_queued'; id: string; text: string; timestamp: number }
  | { type: 'message_received'; id: string; text: string; timestamp: number }
  | { type: 'message_acknowledged'; id: string }
  | { type: 'recovery_available' }
  | { type: 'recovered' }
  | { type: 'error'; error: PublicError };

export type ControllerState = {
  snapshot: RoomSnapshot;
  invite_uri: string | null;
  invite_expires_at: number | null;
  invite_preview: InvitePreview | null;
  verification: VerificationState | null;
  messages: PublicMessage[];
};
