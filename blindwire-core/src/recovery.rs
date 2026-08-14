//! Recovery continuity secret derivation, proof authentication, and ratcheting.

use hkdf::Hkdf;
use hmac::digest::crypto_common::{Key, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::ProtocolError;
use crate::noise::Role;

const CONTINUITY_CONTEXT: &[u8] = b"blindwire/v2.1/continuity";
const RESUME_PROOF_CONTEXT: &[u8] = b"blindwire/v2.1/resume-proof";
const RATCHET_CONTEXT: &[u8] = b"blindwire/v2.1/ratchet";
const SECRET_LENGTH: usize = 32;
const HMAC_KEY_LENGTH: usize = 64;

type HmacSha256 = Hmac<Sha256>;

/// A session recovery continuity secret.
///
/// The secret is zeroized on drop and intentionally provides no cloning or
/// formatting interface. The optional worker snapshot feature adds only a
/// consuming, zeroizing codec for an encrypted worker vault.
pub struct ContinuitySecret(Zeroizing<[u8; SECRET_LENGTH]>);

#[cfg(feature = "worker-recovery-snapshot")]
impl ContinuitySecret {
    /// Consume this secret into the worker-only recovery snapshot codec.
    pub fn into_worker_snapshot_secret(self) -> Zeroizing<[u8; SECRET_LENGTH]> {
        self.0
    }

    /// Restore a secret from a decrypted worker-only recovery snapshot.
    pub fn from_worker_snapshot_secret(secret: Zeroizing<[u8; SECRET_LENGTH]>) -> Self {
        Self(secret)
    }
}

/// Derive the initial continuity secret from role-ordered contributions.
///
/// room is the HKDF-SHA256 salt. The input key material is exactly
/// initiator || responder, and the HKDF info is
/// blindwire/v2.1/continuity.
///
/// # Errors
///
/// Returns [ProtocolError::InternalError] if HKDF output expansion fails.
pub fn derive_continuity_secret(
    room: &[u8; 32],
    initiator: &[u8; 32],
    responder: &[u8; 32],
) -> Result<ContinuitySecret, ProtocolError> {
    let mut input_key_material = Zeroizing::new([0_u8; 64]);
    input_key_material[..32].copy_from_slice(initiator);
    input_key_material[32..].copy_from_slice(responder);

    expand_secret(room, &input_key_material[..], CONTINUITY_CONTEXT)
}

/// Compute a role- and session-bound recovery proof.
///
/// The authenticated transcript is exactly
/// blindwire/v2.1/resume-proof || room || role || epoch_be || fingerprint,
/// where initiator is encoded as 0x00 and responder as 0x01.
pub fn compute_resume_proof(
    secret: &ContinuitySecret,
    room: &[u8; 32],
    role: Role,
    epoch: u64,
    fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut padded_key = Zeroizing::new([0_u8; HMAC_KEY_LENGTH]);
    padded_key[..SECRET_LENGTH].copy_from_slice(&secret.0[..]);
    let key = Key::<HmacSha256>::from_slice(&padded_key[..]);
    let mut mac = <HmacSha256 as KeyInit>::new(key);

    mac.update(RESUME_PROOF_CONTEXT);
    mac.update(room);
    mac.update(&[role_byte(role)]);
    mac.update(&epoch.to_be_bytes());
    mac.update(fingerprint);
    mac.finalize().into_bytes().into()
}

/// Verify a recovery proof using a constant-time comparison.
///
/// # Errors
///
/// Returns [ProtocolError::InvalidResumeProof] when any authenticated
/// transcript field or proof byte differs.
pub fn verify_resume_proof(
    secret: &ContinuitySecret,
    room: &[u8; 32],
    role: Role,
    epoch: u64,
    fingerprint: &[u8; 32],
    proof: &[u8; 32],
) -> Result<(), ProtocolError> {
    let expected = compute_resume_proof(secret, room, role, epoch, fingerprint);
    if bool::from(expected.ct_eq(proof)) {
        Ok(())
    } else {
        Err(ProtocolError::InvalidResumeProof)
    }
}

/// Ratchet a continuity secret with fresh role-ordered contributions.
///
/// This function consumes previous so callers cannot accidentally reuse the
/// prior continuity secret after a successful ratchet. room is the
/// HKDF-SHA256 salt. The input key material is exactly
/// previous || initiator || responder, and the HKDF info is exactly
/// blindwire/v2.1/ratchet || epoch_be.
///
/// # Errors
///
/// Returns [ProtocolError::InternalError] if HKDF output expansion fails.
pub fn ratchet_continuity_secret(
    previous: ContinuitySecret,
    room: &[u8; 32],
    epoch: u64,
    initiator: &[u8; 32],
    responder: &[u8; 32],
) -> Result<ContinuitySecret, ProtocolError> {
    let mut input_key_material = Zeroizing::new([0_u8; 96]);
    input_key_material[..32].copy_from_slice(&previous.0[..]);
    input_key_material[32..64].copy_from_slice(initiator);
    input_key_material[64..].copy_from_slice(responder);
    drop(previous);

    let mut info = [0_u8; RATCHET_CONTEXT.len() + 8];
    info[..RATCHET_CONTEXT.len()].copy_from_slice(RATCHET_CONTEXT);
    info[RATCHET_CONTEXT.len()..].copy_from_slice(&epoch.to_be_bytes());

    expand_secret(room, &input_key_material[..], &info)
}

fn expand_secret(
    room: &[u8; 32],
    input_key_material: &[u8],
    info: &[u8],
) -> Result<ContinuitySecret, ProtocolError> {
    let hkdf = Hkdf::<Sha256>::new(Some(room), input_key_material);
    let mut secret = Zeroizing::new([0_u8; SECRET_LENGTH]);
    hkdf.expand(info, &mut secret[..])
        .map_err(|_| ProtocolError::InternalError)?;
    Ok(ContinuitySecret(secret))
}

const fn role_byte(role: Role) -> u8 {
    match role {
        Role::Initiator => 0,
        Role::Responder => 1,
    }
}
