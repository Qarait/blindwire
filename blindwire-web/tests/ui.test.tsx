import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { InviteView } from '../src/components/InviteView';
import { ChatView } from '../src/components/ChatView';
import { VerificationView } from '../src/components/VerificationView';

describe('browser room UI', () => {
  it('renders the exact invite URI in the read-only input and QR value', () => {
    const uri = 'blindwire://join?v=1&r=room&t=token&e=1890000000000&u=wss%3A%2F%2Frelay.blindwire.net';
    render(<InviteView uri={uri} expiresAt={1890000000000} onCancel={vi.fn()} />);
    const input = screen.getByLabelText('Invite link');
    expect(input).toHaveValue(uri);
    expect(screen.getByTestId('invite-qr')).toHaveAttribute('data-qr-value', input.getAttribute('value'));
  });

  it('keeps chat send disabled before the active phase', () => {
    render(<ChatView phase="verifying" messages={[]} onSend={vi.fn()} onLeave={vi.fn()} onBurn={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled();
  });

  it('requires an explicit verification click', () => {
    const onConfirm = vi.fn();
    render(<VerificationView emojis={['🟦', '🟩']} numeric={[1, 2, 3]} onConfirm={onConfirm} />);
    expect(onConfirm).not.toHaveBeenCalled();
    screen.getByRole('button', { name: 'I verified the match' }).click();
    expect(onConfirm).toHaveBeenCalledOnce();
  });
});
