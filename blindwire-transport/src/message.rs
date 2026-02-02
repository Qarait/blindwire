//! Zeroizing message wrapper.
//!
//! Plaintext is short-lived by construction. Callers must opt-in to copying.

use zeroize::Zeroizing;

/// A received message that zeroizes on Drop.
///
/// This type does not implement `Clone` to prevent accidental plaintext duplication.
/// If you need to keep the data, use `into_string()` or copy explicitly.
#[derive(Debug)]
pub struct Message(Zeroizing<Vec<u8>>);

impl Message {
    /// Create a new message from raw bytes.
    pub(crate) fn new(data: Vec<u8>) -> Self {
        Self(Zeroizing::new(data))
    }

    /// Get message as a string slice.
    ///
    /// Returns an error if the message is not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.0)
    }

    /// Get message as raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get message length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if message is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the message and convert to a String.
    ///
    /// This transfers ownership and zeroizes the original buffer.
    /// Returns an error if the message is not valid UTF-8.
    pub fn into_string(self) -> Result<String, std::str::Utf8Error> {
        // Validate UTF-8 first
        let _ = std::str::from_utf8(&self.0)?;
        // This is safe because we validated above
        // We copy to a new String to allow the Zeroizing buffer to be dropped
        Ok(String::from_utf8_lossy(&self.0).into_owned())
    }
}

// Explicitly NOT implementing Clone to prevent plaintext duplication
// impl Clone for Message { ... } // FORBIDDEN

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_zeroizes() {
        let data = b"secret message".to_vec();
        let msg = Message::new(data);
        assert_eq!(msg.as_str().ok(), Some("secret message"));
        // Message will be zeroized when dropped
        drop(msg);
    }

    #[test]
    fn test_into_string() {
        let msg = Message::new(b"hello world".to_vec());
        let s = msg.into_string().ok();
        assert_eq!(s, Some("hello world".to_string()));
    }

    #[test]
    fn test_invalid_utf8() {
        let msg = Message::new(vec![0xFF, 0xFE]);
        assert!(msg.as_str().is_err());
        assert!(msg.into_string().is_err());
    }
}
