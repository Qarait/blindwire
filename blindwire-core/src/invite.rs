use std::collections::HashSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

/// Represents an explicitly validated, parsed BlindWire invite deep link or QR payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitePayload {
    /// Room/session ID.
    pub room: String,
    /// Single-use authorization token.
    pub token: String,
    /// Expiry Unix timestamp (milliseconds).
    pub exp: u64,
    /// Fully qualified websocket URL of the relay.
    pub relay_url: Url,
    /// SPKI pinning hash of the custom relay (hex formatted or raw base64url).
    pub relay_pin: Option<String>,
}

/// Errors that can occur during deep link parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteError {
    /// The URI could not be parsed as a URL or lacks the blindwire scheme.
    InvalidUriFormat,
    /// A required query parameter is missing (e.g., v, r, t, e).
    MissingRequiredField(&'static str),
    /// The query payload contains unknown keys or duplicated keys.
    UnknownOrDuplicateField(String),
    /// The version is unsupported (only v=1 is supported).
    InvalidVersion,
    /// A field value exceeds the strict allowed maximum length.
    OversizedField(&'static str),
    /// The relay URL is invalid, too long, or not a secure websocket (wss://).
    InvalidRelayUrl,
    /// The invite token's expiry timestamp has passed.
    ExpiredToken,
    /// An explicit custom relay was specified but no SPKI pin ('p=') was provided.
    CustomRelayRequiresPin,
    /// The official relay was specified (or defaulted) and an inline pin was improperly provided.
    OfficialRelayMustNotHavePin,
    /// A field does not match the expected formatting (e.g., base64url without padding).
    InvalidEncoding(&'static str),
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUriFormat => write!(f, "Invalid URI format"),
            Self::MissingRequiredField(k) => write!(f, "Missing required field: {}", k),
            Self::UnknownOrDuplicateField(k) => write!(f, "Unknown or duplicate query field: {}", k),
            Self::InvalidVersion => write!(f, "Invalid or unsupported version (must be v=1)"),
            Self::OversizedField(k) => write!(f, "Field exceeds max length bounds: {}", k),
            Self::InvalidRelayUrl => write!(f, "Relay URL is invalid or not wss://"),
            Self::ExpiredToken => write!(f, "Invite token has expired"),
            Self::CustomRelayRequiresPin => write!(f, "Custom relays require a pinning hash (p=)"),
            Self::OfficialRelayMustNotHavePin => write!(f, "Official relay must not include an inline pin (prevents injection)"),
            Self::InvalidEncoding(k) => write!(f, "Field contains invalid characters (must be base64url no-padding): {}", k),
        }
    }
}

impl std::error::Error for InviteError {}

// Official relay canonical address
const OFFICIAL_RELAY_URL: &str = "wss://relay.blindwire.io";

impl InvitePayload {
    /// Parses a raw blindwire:// deep link or QR string into a validated payload.
    pub fn parse(uri: &str) -> Result<Self, InviteError> {
        let parsed_url = Url::parse(uri).map_err(|_| InviteError::InvalidUriFormat)?;

        if parsed_url.scheme() != "blindwire" {
            return Err(InviteError::InvalidUriFormat);
        }
        if parsed_url.domain() != Some("join") && parsed_url.host_str() != Some("join") {
            // Some platforms send blindwire://join?x=y, some send blindwire:join?x=y
            if parsed_url.path() != "join" && parsed_url.host_str() != Some("join") {
                return Err(InviteError::InvalidUriFormat);
            }
        }

        let mut v: Option<String> = None;
        let mut r: Option<String> = None;
        let mut t: Option<String> = None;
        let mut e: Option<String> = None;
        let mut u: Option<String> = None;
        let mut p: Option<String> = None;

        let mut seen_keys = HashSet::new();

        for (key, value) in parsed_url.query_pairs() {
            let k = key.into_owned();
            if !seen_keys.insert(k.clone()) {
                return Err(InviteError::UnknownOrDuplicateField(k));
            }

            match k.as_str() {
                "v" => v = Some(value.into_owned()),
                "r" => r = Some(value.into_owned()),
                "t" => t = Some(value.into_owned()),
                "e" => e = Some(value.into_owned()),
                "u" => u = Some(value.into_owned()),
                "p" => p = Some(value.into_owned()),
                _ => return Err(InviteError::UnknownOrDuplicateField(k)),
            }
        }

        // 1. Version validation
        let v = v.ok_or(InviteError::MissingRequiredField("v"))?;
        if v != "1" {
            return Err(InviteError::InvalidVersion);
        }

        // 2. Extract and bound-check core fields
        let room = r.ok_or(InviteError::MissingRequiredField("r"))?;
        if room.is_empty() || room.len() > 64 {
            return Err(InviteError::OversizedField("r"));
        }
        if !is_base64url_unpadded(&room) {
            return Err(InviteError::InvalidEncoding("r"));
        }

        let token = t.ok_or(InviteError::MissingRequiredField("t"))?;
        if token.len() < 16 || token.len() > 128 {
            return Err(InviteError::OversizedField("t"));
        }
        if !is_base64url_unpadded(&token) {
            return Err(InviteError::InvalidEncoding("t"));
        }

        let exp_str = e.ok_or(InviteError::MissingRequiredField("e"))?;
        if exp_str.len() < 10 || exp_str.len() > 13 {
            return Err(InviteError::OversizedField("e"));
        }
        let exp = exp_str.parse::<u64>().map_err(|_| InviteError::InvalidEncoding("e"))?;

        // 3. Expiry validation (with 5 minute tolerance for local clock skew)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        let skew_ms = 5 * 60 * 1000;
        if now > exp + skew_ms {
            return Err(InviteError::ExpiredToken);
        }

        // 4. Relay and Pin validation
        let relay_url_str = u.unwrap_or_else(|| OFFICIAL_RELAY_URL.to_string());
        if relay_url_str.len() > 256 {
            return Err(InviteError::OversizedField("u"));
        }
        
        let mut relay_url = Url::parse(&relay_url_str).map_err(|_| InviteError::InvalidRelayUrl)?;
        if relay_url.scheme() != "wss" {
            // Note: we might want to allow 'ws' for local dev, but strictly enforcing wss in prod.
            // If the user needs 'ws' for 127.0.0.1, we could add an unencrypted backdoor, but for now wss only.
            return Err(InviteError::InvalidRelayUrl);
        }
        
        // Strip trailing slash for exact matches
        let is_official = matches_official_relay(&relay_url);

        let pin = p;
        if let Some(ref pin_val) = pin {
            if pin_val.len() != 43 {
                return Err(InviteError::OversizedField("p"));
            }
            if !is_base64url_unpadded(pin_val) {
                return Err(InviteError::InvalidEncoding("p"));
            }
        }

        if is_official && pin.is_some() {
            return Err(InviteError::OfficialRelayMustNotHavePin);
        }

        if !is_official && pin.is_none() {
            return Err(InviteError::CustomRelayRequiresPin);
        }

        Ok(Self {
            room,
            token,
            exp,
            relay_url,
            relay_pin: pin,
        })
    }
}

/// Maintains the client-local lifecycle state of a single-use invite token.
/// Prevents duplicate in-flight connection attempts without aggressively burning
/// the token upon transient network failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// Token has not been used yet.
    Fresh,
    /// Token is currently in-flight during a connection attempt.
    Pending,
    /// Token was successfully authenticated or explicitly rejected as already used.
    Consumed,
}

impl TokenState {
    /// Attempts to transition the state to `Pending` for a connection attempt.
    /// Returns an error if the token is already pending or consumed.
    pub fn try_use(&mut self) -> Result<(), &'static str> {
        match self {
            Self::Fresh => {
                *self = Self::Pending;
                Ok(())
            }
            Self::Pending => Err("Token is currently in-flight"),
            Self::Consumed => Err("Token has been consumed"),
        }
    }

    /// Transitions the token state to `Consumed` (e.g., after success or explicit reuse error).
    pub fn mark_consumed(&mut self) {
        *self = Self::Consumed;
    }

    /// Resets a `Pending` state back to `Fresh` if a connection fails transiently.
    pub fn reset_on_transient_failure(&mut self) {
        if *self == Self::Pending {
            *self = Self::Fresh;
        }
    }
}

fn is_base64url_unpadded(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') && !s.ends_with('=')
}

fn matches_official_relay(url: &Url) -> bool {
    // Official is wss://relay.blindwire.io (with or without internal ports/paths)
    // To be strict, domain must be relay.blindwire.io exactly.
    url.domain() == Some("relay.blindwire.io")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock "now" for test expiry bounds (far future)
    fn get_valid_exp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 + 10_000_000
    }

    fn base_valid_uri() -> String {
        format!("blindwire://join?v=1&r=room123&t=token1234567890123&e={}", get_valid_exp())
    }

    #[test]
    fn test_valid_official_payload() {
        let uri = base_valid_uri();
        let payload = InvitePayload::parse(&uri).unwrap();
        
        assert_eq!(payload.room, "room123");
        assert_eq!(payload.relay_pin, None);
        assert_eq!(payload.relay_url.as_str(), "wss://relay.blindwire.io/");
    }

    #[test]
    fn test_deeplink_rejects_invalid_version() {
        let uri = format!("blindwire://join?v=2&r=room123&t=token1234567890123&e={}", get_valid_exp());
        assert_eq!(InvitePayload::parse(&uri), Err(InviteError::InvalidVersion));
    }

    #[test]
    fn test_deeplink_rejects_oversized_payload() {
        // Exceed room 64 chars
        let big_room = "A".repeat(65);
        let uri = format!("blindwire://join?v=1&r={}&t=token1234567890123&e={}", big_room, get_valid_exp());
        assert_eq!(InvitePayload::parse(&uri), Err(InviteError::OversizedField("r")));

        // Exceed token 128 chars
        let big_token = "B".repeat(129);
        let uri = format!("blindwire://join?v=1&r=room1&t={}&e={}", big_token, get_valid_exp());
        assert_eq!(InvitePayload::parse(&uri), Err(InviteError::OversizedField("t")));
    }

    #[test]
    fn test_duplicate_query_key_rejected() {
        let uri = format!("{}&t=evil", base_valid_uri());
        assert_eq!(InvitePayload::parse(&uri), Err(InviteError::UnknownOrDuplicateField("t".to_string())));
    }

    #[test]
    fn test_invite_token_expiry() {
        // Create an explicitly expired token timestamp (10 mins ago)
        let past_exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 - (10 * 60 * 1000);
        let uri = format!("blindwire://join?v=1&r=room1&t=token1234567890123&e={}", past_exp);
        assert_eq!(InvitePayload::parse(&uri), Err(InviteError::ExpiredToken));
    }

    #[test]
    fn test_custom_relay_requires_pin_or_tofu_path() {
        // Missing pin
        let uri = format!("{}&u=wss://custom.net", base_valid_uri());
        assert_eq!(InvitePayload::parse(&uri), Err(InviteError::CustomRelayRequiresPin));

        // Valid pin format (43 chars base64url)
        let valid_pin = "A".repeat(43);
        let valid_uri = format!("{}&u=wss://custom.net&p={}", base_valid_uri(), valid_pin);
        let payload = InvitePayload::parse(&valid_uri).expect("Should parse with pin");
        assert_eq!(payload.relay_pin.unwrap(), valid_pin);
    }

    #[test]
    fn test_official_relay_rejects_inline_pin_field() {
        // Injecting a pin for the implicit official relay
        let uri = format!("{}&p={}", base_valid_uri(), "A".repeat(43));
        assert_eq!(InvitePayload::parse(&uri), Err(InviteError::OfficialRelayMustNotHavePin));

        // Injecting a pin for the explicit official relay
        let uri_explicit = format!("{}&u=wss://relay.blindwire.io&p={}", base_valid_uri(), "A".repeat(43));
        assert_eq!(InvitePayload::parse(&uri_explicit), Err(InviteError::OfficialRelayMustNotHavePin));
    }

    #[test]
    fn test_invite_token_single_use() {
        let mut state = TokenState::Fresh;
        // First click
        assert!(state.try_use().is_ok());
        assert_eq!(state, TokenState::Pending);
        // Second click while pending fails
        assert!(state.try_use().is_err());
        
        // Success -> Consumed
        state.mark_consumed();
        assert_eq!(state, TokenState::Consumed);
        assert!(state.try_use().is_err());
    }

    #[test]
    fn test_transient_failure_does_not_consume_token() {
        let mut state = TokenState::Fresh;
        // First click
        state.try_use().unwrap();
        
        // Transient network failure occurs...
        state.reset_on_transient_failure();
        
        assert_eq!(state, TokenState::Fresh);
        // Can try again safely
        assert!(state.try_use().is_ok());
    }
}
