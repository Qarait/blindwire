//! Wire framing and bounds checking.
//!
//! Wire format:
//! ```text
//! +----------------+------------------+
//! | LENGTH (2B BE) | BODY (N bytes)   |
//! +----------------+------------------+
//! ```
//!
//! Body format:
//! ```text
//! +----------+-------------------+
//! | TYPE (1B)| PAYLOAD (N-1 B)   |
//! +----------+-------------------+
//! ```

use zeroize::Zeroizing;

use crate::error::ProtocolError;

/// Maximum wire message length (header + body).
pub const MAX_WIRE_LENGTH: usize = 4096;

/// Maximum plaintext length after decryption.
pub const MAX_PLAINTEXT_LENGTH: usize = 4000;

/// Minimum body length (at least type byte).
pub const MIN_BODY_LENGTH: usize = 1;

/// Length prefix size.
pub const LENGTH_PREFIX_SIZE: usize = 2;

/// Message type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Noise protocol handshake message.
    Handshake = 0x01,

    /// Encrypted application data.
    Data = 0x02,

    /// Session termination signal.
    Terminate = 0x03,
}

impl MessageType {
    /// Parse message type from byte.
    /// Returns error for unknown types. No fallback. No default.
    pub fn from_byte(byte: u8) -> Result<Self, ProtocolError> {
        match byte {
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Terminate),
            _ => Err(ProtocolError::UnknownMessageType),
        }
    }

    /// Convert to byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// A validated wire frame.
///
/// Frames are immutable after construction. Validation happens at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    msg_type: MessageType,
    pub(crate) payload: Zeroizing<Vec<u8>>,
}

impl Frame {
    /// Parse a frame from raw bytes (body only, after length prefix removed).
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Body is empty
    /// - Body exceeds MAX_WIRE_LENGTH
    /// - Message type is unknown
    /// - TERMINATE has non-empty payload
    pub fn parse(body: &[u8]) -> Result<Self, ProtocolError> {
        // Bounds check: not empty
        if body.is_empty() {
            return Err(ProtocolError::MessageEmpty);
        }

        // Bounds check: not too large
        if body.len() > MAX_WIRE_LENGTH {
            return Err(ProtocolError::MessageTooLarge);
        }

        // Parse type byte
        let msg_type = MessageType::from_byte(body[0])?;

        // Extract payload (everything after type byte)
        let payload = Zeroizing::new(body[1..].to_vec());

        // TERMINATE must have empty payload
        if msg_type == MessageType::Terminate && !payload.is_empty() {
            return Err(ProtocolError::TerminatePayloadNotEmpty);
        }

        Ok(Self { msg_type, payload })
    }

    /// Read length prefix from stream.
    ///
    /// Returns the body length (not including the 2-byte prefix itself).
    ///
    /// # Errors
    ///
    /// Returns error if length is 0 or exceeds MAX_WIRE_LENGTH.
    pub fn read_length(bytes: &[u8; LENGTH_PREFIX_SIZE]) -> Result<usize, ProtocolError> {
        let length = u16::from_be_bytes(*bytes) as usize;

        // Bounds check: not zero
        if length < MIN_BODY_LENGTH {
            return Err(ProtocolError::MessageEmpty);
        }

        // Bounds check: not too large
        if length > MAX_WIRE_LENGTH {
            return Err(ProtocolError::MessageTooLarge);
        }

        Ok(length)
    }

    /// Create a new HANDSHAKE frame.
    pub fn handshake(payload: Vec<u8>) -> Result<Self, ProtocolError> {
        if payload.len() + 1 > MAX_WIRE_LENGTH {
            return Err(ProtocolError::MessageTooLarge);
        }
        Ok(Self {
            msg_type: MessageType::Handshake,
            payload: Zeroizing::new(payload),
        })
    }

    /// Create a new DATA frame.
    ///
    /// Payload is already-encrypted ciphertext.
    pub fn data(ciphertext: Vec<u8>) -> Result<Self, ProtocolError> {
        if ciphertext.len() + 1 > MAX_WIRE_LENGTH {
            return Err(ProtocolError::MessageTooLarge);
        }
        Ok(Self {
            msg_type: MessageType::Data,
            payload: Zeroizing::new(ciphertext),
        })
    }

    /// Create a new TERMINATE frame.
    pub fn terminate() -> Self {
        Self {
            msg_type: MessageType::Terminate,
            payload: Zeroizing::new(Vec::new()),
        }
    }

    /// Get the message type.
    pub fn msg_type(&self) -> MessageType {
        self.msg_type
    }

    /// Get the payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consume the frame and take ownership of the payload.
    pub fn into_payload(self) -> Zeroizing<Vec<u8>> {
        self.payload
    }

    /// Serialize frame to wire format (length prefix + type + payload).
    pub fn to_wire(&self) -> Vec<u8> {
        let body_len = 1 + self.payload.len();
        let mut wire = Vec::with_capacity(LENGTH_PREFIX_SIZE + body_len);

        // Length prefix (big-endian u16)
        // Cast is safe: we validated body_len <= MAX_WIRE_LENGTH (4096) which fits in u16
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (body_len as u16).to_be_bytes();
        wire.extend_from_slice(&len_bytes);

        // Type byte
        wire.push(self.msg_type.to_byte());

        // Payload
        wire.extend_from_slice(&self.payload);

        wire
    }
}

/// Validate decrypted plaintext.
///
/// # Errors
///
/// Returns error if:
/// - Plaintext is empty
/// - Plaintext exceeds MAX_PLAINTEXT_LENGTH
/// - Plaintext is not valid UTF-8
/// - Plaintext contains NUL byte
pub fn validate_plaintext(plaintext: &[u8]) -> Result<&str, ProtocolError> {
    // Bounds check: not empty
    if plaintext.is_empty() {
        return Err(ProtocolError::EmptyPlaintext);
    }

    // Bounds check: not too large
    if plaintext.len() > MAX_PLAINTEXT_LENGTH {
        return Err(ProtocolError::PlaintextTooLarge);
    }

    // Check for NUL bytes (forbidden)
    if plaintext.contains(&0x00) {
        return Err(ProtocolError::NulByteInPlaintext);
    }

    // Validate UTF-8
    std::str::from_utf8(plaintext).map_err(|_| ProtocolError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_roundtrip() {
        for byte in [0x01, 0x02, 0x03] {
            let mt = MessageType::from_byte(byte).unwrap();
            assert_eq!(mt.to_byte(), byte);
        }
    }

    #[test]
    fn test_unknown_message_type() {
        assert_eq!(
            MessageType::from_byte(0x00),
            Err(ProtocolError::UnknownMessageType)
        );
        assert_eq!(
            MessageType::from_byte(0x04),
            Err(ProtocolError::UnknownMessageType)
        );
        assert_eq!(
            MessageType::from_byte(0xFF),
            Err(ProtocolError::UnknownMessageType)
        );
    }

    #[test]
    fn test_frame_parse_empty() {
        assert_eq!(Frame::parse(&[]), Err(ProtocolError::MessageEmpty));
    }

    #[test]
    fn test_frame_parse_terminate() {
        let frame = Frame::parse(&[0x03]).unwrap();
        assert_eq!(frame.msg_type(), MessageType::Terminate);
        assert!(frame.payload().is_empty());
    }

    #[test]
    fn test_frame_terminate_with_payload_fails() {
        assert_eq!(
            Frame::parse(&[0x03, 0x01]),
            Err(ProtocolError::TerminatePayloadNotEmpty)
        );
    }

    #[test]
    fn test_frame_roundtrip() {
        let original = Frame::handshake(vec![1, 2, 3, 4]).unwrap();
        let wire = original.to_wire();

        // Parse length
        let len = Frame::read_length(&[wire[0], wire[1]]).unwrap();
        assert_eq!(len, 5); // type byte + 4 payload bytes

        // Parse body
        let parsed = Frame::parse(&wire[2..]).unwrap();
        assert_eq!(parsed.msg_type(), MessageType::Handshake);
        assert_eq!(parsed.payload(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_validate_plaintext_valid() {
        let text = "Hello, world!";
        assert_eq!(validate_plaintext(text.as_bytes()), Ok(text));
    }

    #[test]
    fn test_validate_plaintext_empty() {
        assert_eq!(validate_plaintext(&[]), Err(ProtocolError::EmptyPlaintext));
    }

    #[test]
    fn test_validate_plaintext_nul_byte() {
        assert_eq!(
            validate_plaintext(&[0x48, 0x00, 0x49]),
            Err(ProtocolError::NulByteInPlaintext)
        );
    }

    #[test]
    fn test_validate_plaintext_invalid_utf8() {
        assert_eq!(
            validate_plaintext(&[0xFF, 0xFE]),
            Err(ProtocolError::InvalidUtf8)
        );
    }
}
