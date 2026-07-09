//! add-automatic-updates task 6.1: offline release-manifest signing tool.
//!
//! Maintainer-only — never shipped as part of an end-user install (see
//! `installer/macos/build-pkg.sh`/`installer/windows/yadorilink.iss`,
//! neither of which package this binary). Reuses
//! `yadorilink_daemon::update::manifest`'s exact types and wire format
//! rather than a second, independent implementation, so a manifest this
//! tool signs is guaranteed to be exactly what the daemon's own
//! `manifest::verify_and_parse` accepts.
//!
//! Usage:
//!   # Generate a new Ed25519 keypair for a release-signing trust root.
//!   yadorilink-sign-manifest keygen
//!
//!   # Sign a manifest body (a JSON file matching `UpdateManifest`'s
//!   # shape) with a private key, producing a `SignedManifestEnvelope`.
//!   yadorilink-sign-manifest sign \
//!     --key-hex <64-hex-char private key seed> \
//!     --key-id <key id, must match a `manifest::TRUSTED_KEYS` entry> \
//!     --manifest path/to/manifest-body.json \
//!     --out path/to/signed-manifest.json
//!
//! Keep the signing key outside the repository and inject it only when
//! generating a release manifest.

use std::path::PathBuf;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use yadorilink_daemon::update::manifest::{SignedManifestEnvelope, UpdateManifest};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(),
        Some("sign") => sign(&args[2..]),
        _ => {
            eprintln!("usage: yadorilink-sign-manifest <keygen|sign> [args...]");
            std::process::exit(2);
        }
    }
}

fn keygen() {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    println!("private_key_hex: {}", hex::encode(seed));
    println!("public_key_hex: {}", hex::encode(verifying_key.to_bytes()));
    println!(
        "\nAdd the public key to `manifest::TRUSTED_KEYS` with a stable key_id before signing \
         any manifest with the matching private key. Never commit the private key \
         to this repository."
    );
}

struct SignArgs {
    key_hex: String,
    key_id: String,
    manifest_path: PathBuf,
    out_path: PathBuf,
}

fn parse_sign_args(args: &[String]) -> SignArgs {
    let mut key_hex = None;
    let mut key_id = None;
    let mut manifest_path = None;
    let mut out_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key-hex" => {
                key_hex = args.get(i + 1).cloned();
                i += 2;
            }
            "--key-id" => {
                key_id = args.get(i + 1).cloned();
                i += 2;
            }
            "--manifest" => {
                manifest_path = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            "--out" => {
                out_path = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            other => {
                eprintln!("unrecognized argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let missing = |name: &str| -> ! {
        eprintln!("missing required argument: --{name}");
        std::process::exit(2);
    };
    SignArgs {
        key_hex: key_hex.unwrap_or_else(|| missing("key-hex")),
        key_id: key_id.unwrap_or_else(|| missing("key-id")),
        manifest_path: manifest_path.unwrap_or_else(|| missing("manifest")),
        out_path: out_path.unwrap_or_else(|| missing("out")),
    }
}

fn sign(args: &[String]) {
    let args = parse_sign_args(args);

    let key_bytes = hex::decode(&args.key_hex).unwrap_or_else(|e| {
        eprintln!("error: --key-hex is not valid hex: {e}");
        std::process::exit(1);
    });
    let key_bytes: [u8; 32] = key_bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        eprintln!("error: --key-hex must decode to exactly 32 bytes, got {}", v.len());
        std::process::exit(1);
    });
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let manifest_json = std::fs::read_to_string(&args.manifest_path).unwrap_or_else(|e| {
        eprintln!("error: failed to read {}: {e}", args.manifest_path.display());
        std::process::exit(1);
    });
    // Validate it actually parses as an `UpdateManifest` before signing —
    // signing a document nothing can ever verify_and_parse successfully
    // is a maintainer mistake worth catching here, not on a beta user's
    // machine.
    if let Err(e) = serde_json::from_str::<UpdateManifest>(&manifest_json) {
        eprintln!("error: manifest does not parse as UpdateManifest: {e}");
        std::process::exit(1);
    }

    let signature = signing_key.sign(manifest_json.as_bytes());
    let envelope = SignedManifestEnvelope {
        key_id: args.key_id,
        manifest_json,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    };

    let out_json = serde_json::to_string_pretty(&envelope).expect("envelope always serializes");
    std::fs::write(&args.out_path, out_json).unwrap_or_else(|e| {
        eprintln!("error: failed to write {}: {e}", args.out_path.display());
        std::process::exit(1);
    });
    println!("wrote signed manifest envelope to {}", args.out_path.display());
}
