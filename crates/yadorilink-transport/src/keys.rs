use std::io::Write;
use std::path::Path;

use boringtun::x25519::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::TransportError;

/// A device's WireGuard identity (the relevant behavior: "generate/persist per-device keypairs").
pub struct DeviceKeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl DeviceKeyPair {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::fill(&mut bytes[..]);
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Loads a keypair from `path` if it exists, otherwise generates a new
    /// one and persists it (hex-encoded, one 32-byte private key per file).
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, TransportError> {
        let path = path.as_ref();
        if let Some(keypair) = load_existing_keypair(path)? {
            return Ok(keypair);
        }

        let keypair = Self::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match persist_new_keypair(path, &keypair) {
            Ok(()) => Ok(keypair),
            Err(TransportError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                load_existing_keypair(path)?.ok_or_else(|| {
                    TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "private key appeared during creation but could not be loaded",
                    ))
                })
            }
            Err(err) => Err(err),
        }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, TransportError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TransportError::InvalidKey("public key must be 32 bytes".into()))?;
    Ok(PublicKey::from(array))
}

fn load_existing_keypair(path: &Path) -> Result<Option<DeviceKeyPair>, TransportError> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let contents = Zeroizing::new(contents);
    let bytes = Zeroizing::new(
        hex::decode(contents.trim()).map_err(|e| TransportError::InvalidKey(e.to_string()))?,
    );
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::InvalidKey("private key must be 32 bytes".into()))?;
    let array = Zeroizing::new(array);
    let secret = StaticSecret::from(*array);
    let public = PublicKey::from(&secret);
    Ok(Some(DeviceKeyPair { secret, public }))
}

fn persist_new_keypair(path: &Path, keypair: &DeviceKeyPair) -> Result<(), TransportError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let mut file = options.open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let secret_bytes = Zeroizing::new(keypair.secret.to_bytes());
        let encoded = Zeroizing::new(hex::encode(secret_bytes.as_ref()));
        file.write_all(encoded.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        let mut file = options.open(path)?;
        let secret_bytes = Zeroizing::new(keypair.secret.to_bytes());
        let encoded = Zeroizing::new(hex::encode(secret_bytes.as_ref()));
        file.write_all(encoded.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn load_or_generate_creates_private_key_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg_key");

        DeviceKeyPair::load_or_generate(&path).unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn load_or_generate_reuses_existing_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg_key");
        let first = DeviceKeyPair::load_or_generate(&path).unwrap();

        let second = DeviceKeyPair::load_or_generate(&path).unwrap();

        assert_eq!(second.secret.to_bytes(), first.secret.to_bytes());
        assert_eq!(second.public_bytes(), first.public_bytes());
    }
}
