//! Content-addressed identities and opaque string newtypes shared across
//! the replica domain model.

/// SHA-256 of a change's canonical encoding — its content-addressed
/// identity. Two byte-identical encodings hash equal on every device.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChangeHash(pub [u8; 32]);

/// SHA-256 of a `FileVersion`'s canonical encoding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionHash(pub [u8; 32]);

/// Content hash of a single stored block. Length-prefixed in the canonical
/// encoding rather than fixed at 32 bytes, so the hash width is not baked
/// into the wire format.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BlockHash(pub Vec<u8>);

/// A device's stable identity string (the same value used as the
/// `device_id` key throughout the index and wire protocol).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DeviceId(pub String);

/// A synced folder group's identity string.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FolderGroupId(pub String);

/// A file path relative to a folder group's root, as an opaque UTF-8 string.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SyncPath(pub String);

macro_rules! string_newtype {
    ($t:ty) => {
        impl $t {
            pub fn as_str(&self) -> &str {
                &self.0
            }
            pub fn into_string(self) -> String {
                self.0
            }
        }
        impl From<String> for $t {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
        impl From<&str> for $t {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
string_newtype!(DeviceId);
string_newtype!(FolderGroupId);
string_newtype!(SyncPath);

impl std::fmt::Debug for ChangeHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChangeHash({})", hex::encode(self.0))
    }
}
impl std::fmt::Debug for VersionHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VersionHash({})", hex::encode(self.0))
    }
}
impl ChangeHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl VersionHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
