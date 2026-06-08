use std::env;
use std::fs;
use std::path::PathBuf;

const PIN_ENV: &str = "BLINDWIRE_OFFICIAL_SPKI_PINS";

fn main() {
    println!("cargo:rerun-if-env-changed={PIN_ENV}");

    let profile = env::var("PROFILE").expect("Cargo must set PROFILE");
    let raw_pins = env::var(PIN_ENV).unwrap_or_default();
    let pins = parse_pins(&raw_pins);

    if profile == "release" && pins.is_empty() {
        panic!(
            "{PIN_ENV} must contain one or two comma-separated SPKI-SHA256 hex pins for release builds"
        );
    }

    let output = render_pins(&pins);
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR"));
    fs::write(out_dir.join("official_pins.rs"), output)
        .expect("failed to generate official relay pins");
}

fn parse_pins(raw: &str) -> Vec<[u8; 32]> {
    if raw.trim().is_empty() {
        return Vec::new();
    }

    let encoded: Vec<_> = raw.split(',').map(str::trim).collect();
    assert!(
        (1..=2).contains(&encoded.len()),
        "{PIN_ENV} must contain one or two pins"
    );

    let mut pins = Vec::with_capacity(encoded.len());
    for value in encoded {
        assert!(
            value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "each {PIN_ENV} entry must be exactly 64 hexadecimal characters"
        );

        let mut pin = [0u8; 32];
        for (index, byte) in pin.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .expect("validated hexadecimal pin");
        }
        assert!(!pins.contains(&pin), "{PIN_ENV} contains a duplicate pin");
        pins.push(pin);
    }
    pins
}

fn render_pins(pins: &[[u8; 32]]) -> String {
    let mut output = String::from("pub const OFFICIAL_PINS: &[[u8; 32]] = &[\n");
    for pin in pins {
        output.push_str("    [");
        for (index, byte) in pin.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            output.push_str(&format!("0x{byte:02x}"));
        }
        output.push_str("],\n");
    }
    output.push_str("];\n");
    output
}
