use crate::protocol::{Role, SignalingVersion};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

pub const ROOM_TTL: Duration = Duration::from_secs(60 * 60);
pub const RECOVERY_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomError {
    RoleTaken,
    Unauthorized,
    Expired,
    VersionMismatch,
    Burned,
}

#[derive(Debug)]
pub struct Room {
    id: [u8; 32],
    version: SignalingVersion,
    created_at: Instant,
    token: Option<[u8; 32]>,
    token_reserved: bool,
    occupied: [bool; 2],
    complete: [bool; 2],
    confirmed: bool,
    capabilities: [Option<[u8; 32]>; 2],
    detached_at: [Option<Instant>; 2],
    epoch: u64,
    burned: bool,
}

impl Room {
    pub fn new(id: [u8; 32], version: SignalingVersion, created_at: Instant) -> Self {
        Self {
            id,
            version,
            created_at,
            token: None,
            token_reserved: false,
            occupied: [false; 2],
            complete: [false; 2],
            confirmed: false,
            capabilities: [None; 2],
            detached_at: [None; 2],
            epoch: 0,
            burned: false,
        }
    }

    pub const fn id(&self) -> [u8; 32] {
        self.id
    }

    pub const fn version(&self) -> SignalingVersion {
        self.version
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn is_burned(&self) -> bool {
        self.burned
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.created_at) >= ROOM_TTL
    }

    pub const fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    pub const fn occupied(&self, role: Role) -> bool {
        self.occupied[index(role)]
    }

    pub fn join_initial(
        &mut self,
        role: Role,
        token: Option<[u8; 32]>,
        now: Instant,
    ) -> Result<Option<[u8; 32]>, RoomError> {
        self.reject_expired_or_burned(now)?;
        let slot = index(role);
        if self.occupied[slot] {
            return Err(RoomError::RoleTaken);
        }

        match role {
            Role::Initiator => {
                if self.token.is_some() {
                    return Err(RoomError::RoleTaken);
                }
                let mut fresh = [0_u8; 32];
                rand::thread_rng().fill_bytes(&mut fresh);
                self.token = Some(fresh);
                self.occupied[slot] = true;
                Ok(Some(fresh))
            }
            Role::Responder => {
                let Some(expected) = self.token else {
                    return Err(RoomError::Unauthorized);
                };
                let Some(provided) = token else {
                    return Err(RoomError::Unauthorized);
                };
                if self.token_reserved || expected.ct_eq(&provided).unwrap_u8() != 1 {
                    return Err(RoomError::Unauthorized);
                }
                self.token_reserved = true;
                self.occupied[slot] = true;
                Ok(None)
            }
        }
    }

    pub fn complete_handshake(&mut self, role: Role, now: Instant) -> Result<bool, RoomError> {
        self.reject_expired_or_burned(now)?;
        if !self.occupied(role) || (!self.token_reserved && !self.confirmed) {
            return Err(RoomError::Unauthorized);
        }

        self.complete[index(role)] = true;
        if self.complete == [true, true] {
            self.confirmed = true;
            self.token_reserved = true;
            self.complete = [false; 2];
            return Ok(true);
        }
        Ok(false)
    }

    pub fn register_recovery(
        &mut self,
        role: Role,
        capability: [u8; 32],
        now: Instant,
    ) -> Result<(), RoomError> {
        self.reject_expired_or_burned(now)?;
        if !self.confirmed || !self.occupied(role) {
            return Err(RoomError::Unauthorized);
        }
        self.capabilities[index(role)] = Some(Sha256::digest(capability).into());
        self.detached_at[index(role)] = None;
        Ok(())
    }

    pub const fn stored_capability_hash(&self, role: Role) -> Option<[u8; 32]> {
        self.capabilities[index(role)]
    }

    pub fn begin_resume(
        &mut self,
        role: Role,
        capability: [u8; 32],
        expected_epoch: u64,
        now: Instant,
    ) -> Result<u64, RoomError> {
        self.reject_expired_or_burned(now)?;
        if !self.confirmed || self.occupied(role) || expected_epoch != self.epoch {
            return Err(RoomError::Unauthorized);
        }

        let Some(detached_at) = self.detached_at[index(role)] else {
            return Err(RoomError::Unauthorized);
        };
        if now.duration_since(detached_at) >= RECOVERY_TTL {
            return Err(RoomError::Expired);
        }

        let Some(expected) = self.capabilities[index(role)] else {
            return Err(RoomError::Unauthorized);
        };
        let actual: [u8; 32] = Sha256::digest(capability).into();
        if expected.ct_eq(&actual).unwrap_u8() != 1 {
            return Err(RoomError::Unauthorized);
        }

        self.epoch = self.epoch.checked_add(1).ok_or(RoomError::Unauthorized)?;
        self.occupied[index(role)] = true;
        self.detached_at[index(role)] = None;
        self.complete = [false; 2];
        Ok(self.epoch)
    }

    pub fn detach(&mut self, role: Role, now: Instant) {
        self.occupied[index(role)] = false;
        if self.confirmed {
            if self.detached_at[index(role)].is_none() {
                self.detached_at[index(role)] = Some(now);
            }
        } else if role == Role::Responder {
            self.token_reserved = false;
            self.complete = [false; 2];
        }
    }

    pub fn burn(&mut self, role: Role) -> Result<(), RoomError> {
        if !self.occupied(role) {
            return Err(RoomError::Unauthorized);
        }
        self.burned = true;
        self.token = None;
        self.token_reserved = false;
        self.complete = [false; 2];
        self.capabilities = [None; 2];
        self.detached_at = [None; 2];
        self.occupied = [false; 2];
        Ok(())
    }

    fn reject_expired_or_burned(&self, now: Instant) -> Result<(), RoomError> {
        if self.burned {
            Err(RoomError::Burned)
        } else if self.is_expired(now) {
            Err(RoomError::Expired)
        } else {
            Ok(())
        }
    }
}

const fn index(role: Role) -> usize {
    match role {
        Role::Initiator => 0,
        Role::Responder => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{Room, RoomError, RECOVERY_TTL, ROOM_TTL};
    use crate::protocol::{Role, SignalingVersion};
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant};

    fn confirmed_room(now: Instant) -> Room {
        let mut room = Room::new([0x41; 32], SignalingVersion::V4, now);
        let token = room
            .join_initial(Role::Initiator, None, now)
            .unwrap()
            .unwrap();
        room.join_initial(Role::Responder, Some(token), now)
            .unwrap();
        room.complete_handshake(Role::Initiator, now).unwrap();
        room.complete_handshake(Role::Responder, now).unwrap();
        room
    }

    #[test]
    fn only_the_tokened_responder_can_join_and_both_completions_confirm() {
        let now = Instant::now();
        let mut room = Room::new([0x41; 32], SignalingVersion::V4, now);
        let token = room
            .join_initial(Role::Initiator, None, now)
            .unwrap()
            .unwrap();

        assert_eq!(
            room.join_initial(Role::Responder, Some([0; 32]), now),
            Err(RoomError::Unauthorized)
        );
        assert_eq!(
            room.join_initial(Role::Responder, Some(token), now)
                .unwrap(),
            None
        );
        assert!(!room.complete_handshake(Role::Initiator, now).unwrap());
        assert!(room.complete_handshake(Role::Responder, now).unwrap());
        assert!(room.is_confirmed());
    }

    #[test]
    fn role_ownership_and_token_reservation_are_single_use() {
        let now = Instant::now();
        let mut room = Room::new([0x42; 32], SignalingVersion::V4, now);
        let token = room
            .join_initial(Role::Initiator, None, now)
            .unwrap()
            .unwrap();
        assert_eq!(
            room.join_initial(Role::Initiator, None, now),
            Err(RoomError::RoleTaken)
        );
        room.join_initial(Role::Responder, Some(token), now)
            .unwrap();
        assert_eq!(
            room.join_initial(Role::Responder, Some(token), now),
            Err(RoomError::RoleTaken)
        );
    }

    #[test]
    fn recovery_registration_stores_only_a_capability_hash() {
        let now = Instant::now();
        let mut room = confirmed_room(now);
        let capability = [0x52; 32];
        room.register_recovery(Role::Initiator, capability, now)
            .unwrap();

        let expected: [u8; 32] = Sha256::digest(capability).into();
        assert_eq!(room.stored_capability_hash(Role::Initiator), Some(expected));
        assert_ne!(
            room.stored_capability_hash(Role::Initiator),
            Some(capability)
        );
    }

    #[test]
    fn resume_requires_hash_match_detachment_and_current_epoch_then_rotates_once() {
        let now = Instant::now();
        let mut room = confirmed_room(now);
        let capability = [0x52; 32];
        room.register_recovery(Role::Initiator, capability, now)
            .unwrap();
        room.detach(Role::Initiator, now);

        assert_eq!(
            room.begin_resume(Role::Initiator, [0; 32], 0, now),
            Err(RoomError::Unauthorized)
        );
        assert_eq!(
            room.begin_resume(Role::Initiator, capability, 0, now)
                .unwrap(),
            1
        );
        assert_eq!(
            room.begin_resume(Role::Initiator, capability, 0, now),
            Err(RoomError::Unauthorized)
        );
    }

    #[test]
    fn recovery_and_room_expiry_are_distinct_terminal_windows() {
        let now = Instant::now();
        let mut room = confirmed_room(now);
        let capability = [0x61; 32];
        room.register_recovery(Role::Initiator, capability, now)
            .unwrap();
        room.detach(Role::Initiator, now);

        assert_eq!(
            room.begin_resume(Role::Initiator, capability, 0, now + RECOVERY_TTL),
            Err(RoomError::Expired)
        );
        assert!(room.is_expired(now + ROOM_TTL));
        assert_eq!(
            room.register_recovery(Role::Responder, [0x62; 32], now + ROOM_TTL),
            Err(RoomError::Expired)
        );
    }

    #[test]
    fn burn_is_terminal_and_clears_recovery_state() {
        let now = Instant::now();
        let mut room = confirmed_room(now);
        room.register_recovery(Role::Initiator, [0x71; 32], now)
            .unwrap();

        assert_eq!(room.burn(Role::Initiator), Ok(()));
        assert!(room.is_burned());
        assert_eq!(room.stored_capability_hash(Role::Initiator), None);
        assert_eq!(room.burn(Role::Initiator), Err(RoomError::Unauthorized));
        assert_eq!(
            room.register_recovery(Role::Responder, [0x72; 32], now),
            Err(RoomError::Burned)
        );
        assert_eq!(
            room.join_initial(Role::Initiator, None, now),
            Err(RoomError::Burned)
        );
    }

    #[test]
    fn unconfirmed_rooms_do_not_accept_recovery_registration() {
        let now = Instant::now();
        let mut room = Room::new([0x81; 32], SignalingVersion::V4, now);
        room.join_initial(Role::Initiator, None, now).unwrap();
        assert_eq!(
            room.register_recovery(Role::Initiator, [0x82; 32], now),
            Err(RoomError::Unauthorized)
        );
    }

    #[test]
    fn detaching_before_confirmation_releases_responder_reservation() {
        let now = Instant::now();
        let mut room = Room::new([0x91; 32], SignalingVersion::V4, now);
        let token = room
            .join_initial(Role::Initiator, None, now)
            .unwrap()
            .unwrap();
        room.join_initial(Role::Responder, Some(token), now)
            .unwrap();
        room.detach(Role::Responder, now);
        assert_eq!(
            room.join_initial(Role::Responder, Some(token), now),
            Ok(None)
        );
    }

    #[test]
    fn recovery_window_is_not_extended_by_repeated_detach() {
        let now = Instant::now();
        let mut room = confirmed_room(now);
        let capability = [0xa1; 32];
        room.register_recovery(Role::Initiator, capability, now)
            .unwrap();
        room.detach(Role::Initiator, now);
        room.detach(Role::Initiator, now + Duration::from_secs(1));
        assert_eq!(
            room.begin_resume(Role::Initiator, capability, 0, now + RECOVERY_TTL),
            Err(RoomError::Expired)
        );
    }

    #[test]
    fn a_resumed_room_requires_and_confirms_a_fresh_handshake_round() {
        let now = Instant::now();
        let mut room = confirmed_room(now);
        let capability = [0xb1; 32];
        room.register_recovery(Role::Initiator, capability, now)
            .unwrap();
        room.detach(Role::Initiator, now);
        assert_eq!(
            room.begin_resume(Role::Initiator, capability, 0, now),
            Ok(1)
        );

        assert!(!room.complete_handshake(Role::Initiator, now).unwrap());
        assert!(room.complete_handshake(Role::Responder, now).unwrap());
    }
}
