//! Small, explicit wrappers around the platform cryptographic random source.

use crate::ProtocolError;

/// The platform entropy provider used by protocol code.
pub struct SystemEntropy;

impl SystemEntropy {
    /// Fill a caller-provided buffer with cryptographically secure bytes.
    pub fn fill(buffer: &mut [u8]) -> Result<(), ProtocolError> {
        getrandom::getrandom(buffer).map_err(|_| ProtocolError::EntropyUnavailable)
    }
}

/// Return an array filled by the platform cryptographic random source.
pub fn random_array<const N: usize>() -> Result<[u8; N], ProtocolError> {
    let mut bytes = [0_u8; N];
    SystemEntropy::fill(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::random_array;

    #[test]
    fn system_entropy_returns_distinct_nonzero_values() {
        let first = random_array::<32>().unwrap();
        let second = random_array::<32>().unwrap();
        assert!(first.iter().any(|byte| *byte != 0));
        assert!(second.iter().any(|byte| *byte != 0));
        assert_ne!(first, second);
    }
}
