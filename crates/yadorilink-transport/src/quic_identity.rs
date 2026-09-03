//! Peer identity for QUIC: mutual TLS 1.3 with RFC 7250 raw public keys over
//! this device's Ed25519 signing key.
//!
//! ## Why the signing key, and not the transport key
//!
//! A TLS handshake is authenticated by *signing* the transcript. X25519 is a
//! Diffie-Hellman key, not a signature scheme, so the device's WireGuard
//! static key cannot authenticate a QUIC connection at all -- there is no
//! operation it can perform that proves possession over a transcript. Of the
//! keys a device already holds, exactly one is signature-capable, already
//! mandatory on every device, and already distributed to peers through the
//! netmap: the Ed25519 device signing key. Reusing it is therefore not a
//! shortcut; it is the only option that does not invent a third identity.
//!
//! Reusing one key for two jobs -- offline authorship of history entries and
//! live transport authentication -- is safe here because TLS 1.3 domain-
//! separates its own signatures by construction: a `CertificateVerify` covers
//! `0x20` repeated 64 times, then a context string, then `0x00`, then the
//! transcript hash. A signature minted for a connection cannot be replayed as
//! authorship, and vice versa, as long as the history's signing payload keeps
//! its own leading domain tag.
//!
//! ## Why there is no certificate
//!
//! There is no CA, no issuance step and no name to bind. The netmap already
//! says which public keys are authorized, and it is the only authority that
//! could revoke one. An X.509 wrapper around that fact would add parsing,
//! expiry and chain-building without adding a single decision that anything
//! in this system actually consults. RFC 7250 lets both endpoints present the
//! bare `SubjectPublicKeyInfo` instead, which is precisely the shape the
//! netmap distributes.
//!
//! ## Why mutual authentication is not a configuration knob
//!
//! What is being replaced -- the WireGuard Noise-IK handshake -- authenticates
//! *both* endpoints before any payload moves, and nothing above this layer
//! re-encrypts sync data. TLS, by contrast, defaults to authenticating only
//! the server, and the client-authentication half is the one routinely left
//! out. Leaving it out here would not merely produce a weaker connection: it
//! would let an unauthenticated caller receive plaintext file content from a
//! device that believes it is talking to a netmap peer. So the server side of
//! this module always requires and verifies a client raw public key, and this
//! module offers no way to ask for anything less.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, RwLock};

use ed25519_dalek::Signer as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{AlwaysResolvesServerRawPublicKeys, NoServerSessionStorage};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, PeerIncompatible,
    SignatureAlgorithm, SignatureScheme,
};

use crate::error::TransportError;
use crate::keys::DeviceSigningKeyPair;

/// The application protocol this build speaks, exactly.
///
/// The generation number rides the ALPN rather than a post-handshake
/// capability exchange because ALPN is negotiated *inside* the TLS handshake:
/// a peer of a different generation is refused before any application frame
/// exists, and before either side has spent anything but the handshake it was
/// going to spend anyway. There is no compatibility range and no negotiation
/// -- a mismatch is a refusal, which is the whole point of pinning an exact
/// generation while the protocol has no released baseline to be compatible
/// with.
///
/// This is now the *only* place the peer protocol generation is defined. It
/// used to be one of two: a `protocol_version` field on the first
/// application message claimed the same authority, and two definitions of one
/// number eventually disagree. Being the only one carries an obligation --
/// **this number moves whenever the peer wire changes**, because nothing else
/// is left that can refuse a peer speaking the previous shape. Generation `7`
/// removes every dead/future-only wire field this build never sent or never
/// read: `ChangeBatch.compression`/`compressed_changes` (no sender ever
/// compressed), `HeadsAnnounce.frontier_hint` (no receiver ever read it),
/// `VersionPresentAck`'s `folder_group_id`/`file_path`/`signature`,
/// `HandoffLeaseRelease`/`HandoffTicketRelease`'s `request_id` (fire-and-
/// forget, never correlated), `ClusterConfig`'s `folder_group_ids`/
/// `known_peer_device_ids`/`available_worker_slots`/
/// `estimated_queue_delay_ms` (advertised but never consumed), and
/// `BlockResponseHeader`'s `redirect` case (no production sender ever built
/// one) -- plus the never-wired `FileInfo`/`BlockInfo`/proto `RecordKind`
/// messages. `6` adds `have_heads`/`want_heads` to `ChangeRequest` and
/// `more` to `ChangeBatch`, so anti-entropy transfers a have-aware delta
/// across explicit oldest-first pages instead of a bounded prefix of the
/// requester's full ancestor closure; `5` was the block protocol in which
/// one request is one bidirectional stream; `4` was the same transport
/// still carrying block content inline on the control stream.
pub const YADORILINK_P2P_ALPN: &[u8] = b"yadorilink-p2p/7";

/// The name a dialer passes to `quinn::Endpoint::connect`.
///
/// It is a placeholder and is deliberately never checked. Under RFC 7250 the
/// peer presents a bare public key, which carries no name to compare against;
/// identity is decided entirely by which key was presented. quinn still
/// requires *some* syntactically valid name for the API, so this constant
/// exists to keep every call site passing the same meaningless one rather
/// than inventing names that look like they matter.
pub const PEER_SERVER_NAME: &str = "yadorilink-peer";

/// The RFC 5280 `SubjectPublicKeyInfo` prefix for an Ed25519 public key.
///
/// ```text
/// 30 2A          SEQUENCE (42 bytes)
///    30 05       SEQUENCE (5 bytes) -- AlgorithmIdentifier
///       06 03 2B 65 70   OBJECT IDENTIFIER 1.3.101.112 (id-Ed25519)
///    03 21 00    BIT STRING (33 bytes, 0 unused bits)
/// ```
///
/// Every field is fixed for this one algorithm, so the encoding is a constant
/// rather than a DER construction: there is nothing to vary. Keeping the same
/// constant on both the encode and the decode path is deliberate -- the bytes
/// this device emits and the bytes it will accept from a peer are then
/// literally the same definition, and cannot drift apart.
const ED25519_SPKI_PREFIX: [u8; 12] =
    [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];

/// Length of a complete Ed25519 SPKI: the fixed prefix plus the key.
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

/// Wraps a raw Ed25519 public key in its `SubjectPublicKeyInfo` encoding.
fn ed25519_spki(public_key: &[u8; 32]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(ED25519_SPKI_LEN);
    spki.extend_from_slice(&ED25519_SPKI_PREFIX);
    spki.extend_from_slice(public_key);
    spki
}

/// Recovers the raw Ed25519 public key from a `SubjectPublicKeyInfo`.
///
/// Everything reaching this function came off the wire from a peer that has
/// not been authenticated yet, so it checks the length before the prefix and
/// the prefix before the key, and never indexes on a value a peer controls.
/// A hostile SPKI must produce `None` here, never a panic in the middle of a
/// handshake.
pub(crate) fn ed25519_key_from_spki(spki: &[u8]) -> Option<[u8; 32]> {
    let (prefix, key) = spki.split_at_checked(ED25519_SPKI_PREFIX.len())?;
    if prefix != ED25519_SPKI_PREFIX {
        return None;
    }
    key.try_into().ok()
}

/// This device's Ed25519 signing key, presented to rustls as a private key it
/// can use for TLS authentication.
///
/// rustls asks for an `Arc<dyn SigningKey>` precisely so that a key it does
/// not know how to parse can still be used. That matters here: the device
/// seed lives in this crate's own key store, never as PKCS#8 DER, and the
/// only way to hand it over without inventing a serialization step (and a
/// window in which the secret exists in a second encoding) is to implement
/// the trait directly over the key object we already hold.
struct DeviceSigningIdentity {
    signing: ed25519_dalek::SigningKey,
    spki: Vec<u8>,
}

// Hand-written, and empty on purpose. `SigningKey` requires `Debug`, and the
// natural derive would put a private key into any log line that formats a
// rustls config -- the same reason this crate's `DeviceKeyPair` has no
// `Debug` at all.
impl fmt::Debug for DeviceSigningIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceSigningIdentity")
    }
}

impl SigningKey for DeviceSigningIdentity {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Ed25519 or nothing. Returning a signer for a scheme this key cannot
        // actually produce would surface as an unverifiable signature at the
        // peer, which is a far more confusing failure than declining here and
        // letting rustls report that no mutually supported scheme exists.
        offered.contains(&SignatureScheme::ED25519).then(|| {
            Box::new(DeviceSignatureWriter { signing: self.signing.clone() }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki.as_slice()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

struct DeviceSignatureWriter {
    signing: ed25519_dalek::SigningKey,
}

impl fmt::Debug for DeviceSignatureWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceSignatureWriter")
    }
}

impl Signer for DeviceSignatureWriter {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        // Ed25519 hashes internally, so `message` is signed as given -- there
        // is no separate hash step for the caller to get wrong.
        Ok(self.signing.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// This device's identity in the form rustls presents to a peer: the raw
/// public key as the sole "certificate", and the matching signing key.
///
/// Public because it is half of the composition seam a differently
/// configured endpoint is built from; the two config constructors below are
/// the ordinary way to reach it.
pub fn device_certified_key(device: &DeviceSigningKeyPair) -> Arc<CertifiedKey> {
    let spki = ed25519_spki(&device.public_bytes());
    let key =
        Arc::new(DeviceSigningIdentity { signing: device.signing.clone(), spki: spki.clone() });
    // For a raw public key the "certificate chain" is a single entry holding
    // the SPKI itself. That is rustls' representation, not a fiction we are
    // maintaining: with `only_raw_public_keys` negotiated, this is what goes
    // on the wire and what the peer's verifier receives.
    Arc::new(CertifiedKey::new(vec![CertificateDer::from(spki)], key))
}

/// The set of peer public keys this device currently authorizes, shared live
/// with every verifier built from it.
///
/// The lifetimes involved do not line up unless this is shared and mutable.
/// A `quinn::ServerConfig` -- and the TLS configuration inside it -- is
/// assembled once, when the device's endpoint is built; netmap authorization
/// changes whenever the coordination plane pushes an update, which is any
/// number of times afterwards. Revocation in this system is netmap-driven and
/// nothing else: raw public keys have no CRL and no OCSP responder, so
/// "this device is no longer authorized" can only mean "the set the verifier
/// reads no longer contains its key". If that set were a construction-time
/// snapshot, honouring a revocation would mean rebuilding the endpoint --
/// tearing down every *other* peer's live connection to withdraw one key.
///
/// So the set is behind an `RwLock` and every verifier holds a handle to the
/// same one. Reads happen on the handshake path, once per connection
/// attempt, and are contended only against the comparatively rare netmap
/// update, which is the direction an `RwLock` is good at.
///
/// What this deliberately does *not* do is disturb connections that are
/// already established: [`revoke`](Self::revoke) decides who may connect
/// next, not who stays connected. Tearing down a live session is the
/// orchestrator's job, because it owns the session and knows what to do with
/// the work in flight on it. The guarantee here is the narrower one that a
/// removed key is refused from that moment on.
#[derive(Clone, Default)]
pub struct AuthorizedPeerKeys {
    keys: Arc<RwLock<BTreeSet<[u8; 32]>>>,
}

// Hand-written and count-only, matching `PinnedPeerKeys` below: which peers a
// device is authorized to talk to is netmap-derived membership information,
// not something to spill into a log line that happens to format a config.
impl fmt::Debug for AuthorizedPeerKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedPeerKeys").field("len", &self.len()).finish()
    }
}

impl AuthorizedPeerKeys {
    /// An empty set: this device authorizes nobody until told otherwise.
    ///
    /// That is the correct state to start in, not a placeholder. An endpoint
    /// built on an empty set refuses every peer, so the window between
    /// "endpoint exists" and "netmap applied" is closed rather than open --
    /// see [`PinnedPeerKeys::accept`].
    pub fn new() -> Self {
        Self::default()
    }

    /// A set holding exactly `keys`. Equivalent to [`new`](Self::new)
    /// followed by [`replace`](Self::replace) -- and it removes nothing,
    /// because a fresh set held nothing to begin with.
    pub fn with(keys: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let set = Self::new();
        let removed = set.replace(keys);
        debug_assert!(removed.is_empty(), "a fresh set cannot drop a key");
        set
    }

    /// A poisoned lock means some thread panicked while holding it. The set
    /// itself is a `BTreeSet` of fixed-size keys with no partially-applied
    /// state to observe -- an insert either happened or did not -- so the
    /// contents are still exactly what the last completed update left, and
    /// recovering them is right where refusing to read (and thereby failing
    /// every handshake) would not be. This matches how the rest of this
    /// workspace handles its own `std::sync` guards.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeSet<[u8; 32]>> {
        self.keys.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeSet<[u8; 32]>> {
        self.keys.write().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Adds `key`. Returns whether it was newly added.
    pub fn authorize(&self, key: [u8; 32]) -> bool {
        self.write().insert(key)
    }

    /// Removes `key`, so no *subsequent* connection presenting it is
    /// accepted. Returns whether it had been authorized.
    pub fn revoke(&self, key: &[u8; 32]) -> bool {
        self.write().remove(key)
    }

    /// Replaces the whole set, which is the shape a netmap push arrives in:
    /// an authoritative list of who is authorized now, not a delta. Applied
    /// under one write lock so no handshake can observe a half-applied
    /// update -- a peer that is in both the old and the new set must never
    /// be refused just because the update happened to be running.
    ///
    /// Returns the keys the replacement removed. The caller needs them: a
    /// withdrawn key is only half of revoking a peer, and the other half --
    /// releasing anything that peer already has in flight -- has to happen
    /// for every key this drops, not only for keys revoked one at a time.
    #[must_use = "the removed keys still have to be revoked, not just dropped from the set"]
    pub fn replace(&self, keys: impl IntoIterator<Item = [u8; 32]>) -> Vec<[u8; 32]> {
        let next: BTreeSet<[u8; 32]> = keys.into_iter().collect();
        let mut current = self.write();
        let removed = current.difference(&next).copied().collect();
        *current = next;
        removed
    }

    /// Whether `key` is currently authorized.
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.read().contains(key)
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }
}

/// The set of Ed25519 public keys a connection will accept from the peer.
///
/// One type implements both verifier traits, so the client's view of the
/// server and the server's view of the client are decided by the same code
/// reading the same pinned set. That is deliberate. When the two directions
/// are separate implementations, the client half gets exercised by every
/// connection and the server half only by connections that reach it, so a
/// mistake in the server half can sit unnoticed while every handshake still
/// succeeds -- a silent downgrade from mutual authentication to one-sided.
/// Here there is no second implementation to forget.
///
/// The set itself is an [`AuthorizedPeerKeys`], read afresh on every
/// handshake; see that type for why it has to be live rather than a
/// construction-time snapshot.
pub struct PinnedPeerKeys {
    expected: AuthorizedPeerKeys,
    /// The signature algorithms of the provider this configuration is built
    /// on. Held rather than looked up per handshake so the verifier cannot
    /// end up validating against a different provider than the one doing the
    /// key exchange.
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

// `WebPkiSupportedAlgorithms` is not `Debug`, and both verifier traits
// require it.
impl fmt::Debug for PinnedPeerKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedPeerKeys").field("expected", &self.expected.len()).finish()
    }
}

impl PinnedPeerKeys {
    /// Pins a fixed set of keys, verified against `provider`'s algorithms.
    ///
    /// For the one-key client direction and for tests: the resulting set has
    /// no handle anywhere else, so nothing can change it. A device's
    /// accepting direction wants [`with_live_set`](Self::with_live_set)
    /// instead.
    ///
    /// An empty set is a legal argument and produces an endpoint that refuses
    /// every peer. That is the correct reading of "this device currently
    /// authorizes nobody", and it is the direction this has to fail in: an
    /// endpoint that accepted anyone when its expected set had not been
    /// populated yet would be indistinguishable, on the wire, from one that
    /// was configured correctly.
    pub fn new(
        expected: impl IntoIterator<Item = [u8; 32]>,
        provider: &rustls::crypto::CryptoProvider,
    ) -> Self {
        Self::with_live_set(AuthorizedPeerKeys::with(expected), provider)
    }

    /// Verifies against `expected` as it stands at each handshake, rather
    /// than as it stood when this verifier was built. The same fail-closed
    /// reading of an empty set applies -- including the case where the set
    /// became empty after construction.
    pub fn with_live_set(
        expected: AuthorizedPeerKeys,
        provider: &rustls::crypto::CryptoProvider,
    ) -> Self {
        Self { expected, supported: provider.signature_verification_algorithms }
    }

    /// Decides whether a presented raw public key is one this endpoint
    /// accepts, returning a TLS error if it is not.
    ///
    /// Both a malformed SPKI and a well-formed but unpinned key end here, and
    /// both must end as an `Err`. There is no path through this function that
    /// reaches an accepted state without a set membership test succeeding.
    fn accept(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), rustls::Error> {
        // A raw public key stands alone. Anything additional means the peer
        // is not speaking the profile that was negotiated, so refuse rather
        // than quietly ignoring the extra entries.
        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(CertificateError::BadEncoding));
        }
        let Some(presented) = ed25519_key_from_spki(end_entity.as_ref()) else {
            return Err(rustls::Error::InvalidCertificate(CertificateError::BadEncoding));
        };
        if !self.expected.contains(&presented) {
            // `UnknownIssuer` would be the closer analogue in an X.509 world,
            // but there is no issuer here. The key simply is not one this
            // device was told to talk to, which is an application-level
            // decision about identity.
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(())
    }

    /// The handshake signature check, shared by both directions.
    ///
    /// The peer's key has already been matched against the pinned set by the
    /// time this runs; this is what turns "presented a key we accept" into
    /// "possesses that key", and without it the first half proves nothing.
    fn verify_handshake_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.supported,
        )
    }
}

impl ServerCertVerifier for PinnedPeerKeys {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        // Unused, and that is the RFC 7250 profile rather than an omission:
        // a raw public key asserts no name, so there is nothing for a name to
        // be checked against. `PEER_SERVER_NAME` documents why the value a
        // dialer passes is meaningless.
        _server_name: &ServerName<'_>,
        // No certificate means no issuer, so no OCSP responder to consult.
        _ocsp_response: &[u8],
        // No validity period either: a key is authorized for exactly as long
        // as the netmap lists it, which no clock on this device can tell us.
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.accept(end_entity, intermediates).map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Unreachable: these configurations offer TLS 1.3 only. Refusing
        // rather than delegating keeps it that way even if some future
        // caller assembles a configuration from these pieces and forgets the
        // version restriction.
        Err(rustls::Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for PinnedPeerKeys {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Hints name the certificate authorities a client should pick from.
        // There are none, and an empty list tells the client to present
        // whatever identity it has -- which is exactly one raw public key.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.accept(end_entity, intermediates).map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The crypto provider these configurations are built on.
///
/// Named explicitly rather than taken from the process-wide default: whether
/// some other crate installed a default first is not something a peer
/// connection's security should depend on, and `ring` is this workspace's
/// deliberate choice over `aws-lc-rs` and its C toolchain requirement.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Dials one specific peer: this device authenticates with its own Ed25519
/// key, and accepts an answer only from `expected_peer`.
///
/// The expected key is a single key, not a set, and that asymmetry with
/// [`quic_server_config`] is the point. A dial is aimed at one device; if a
/// caller could hand over the whole netmap here, any authorized peer that
/// managed to answer this dial would be accepted in place of the intended
/// one, and every check would still have passed.
pub fn quic_client_config(
    device: &DeviceSigningKeyPair,
    expected_peer: [u8; 32],
) -> Result<quinn::ClientConfig, TransportError> {
    let provider = provider();
    let verifier = Arc::new(PinnedPeerKeys::new([expected_peer], &provider));
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(quic_config_error)?
        .dangerous()
        // "Dangerous" names the fact that certificate validation is being
        // replaced rather than skipped. What replaces it is stricter than the
        // web PKI it displaces: exactly one pinned key is acceptable, with no
        // issuer that could vouch for a second.
        .with_custom_certificate_verifier(verifier)
        // The client-authentication half. A resolver that always presents
        // this device's raw public key is what makes the connection mutual;
        // there is no branch here that presents nothing.
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
            device_certified_key(device),
        )));
    crypto.alpn_protocols = vec![YADORILINK_P2P_ALPN.to_vec()];
    // Resumption would let a peer re-enter an established session by
    // presenting a ticket instead of its raw public key, which is the one
    // thing revocation has to be able to stop. These are long-lived
    // connections between a handful of devices, so there is nothing to trade
    // away by refusing it.
    crypto.resumption = rustls::client::Resumption::disabled();
    Ok(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(quic_config_error)?,
    )))
}

/// Accepts connections from any device in `authorized_peers`, and requires
/// every one of them to prove possession of its pinned Ed25519 key.
///
/// The set is the netmap's answer to "who may talk to this device". It is
/// unconditionally enforced: there is no unauthenticated acceptance path
/// through this configuration, because nothing above this transport
/// re-encrypts, and an unauthenticated peer that got this far would be
/// reading plaintext file content.
///
/// `authorized_peers` is taken by handle rather than by value so this
/// configuration -- built once, when the device's single endpoint is
/// constructed -- keeps reflecting netmap updates that arrive afterwards.
/// See [`AuthorizedPeerKeys`] for why revocation cannot work any other way
/// without rebuilding the endpoint under every other peer's live connection.
pub fn quic_server_config(
    device: &DeviceSigningKeyPair,
    authorized_peers: &AuthorizedPeerKeys,
) -> Result<quinn::ServerConfig, TransportError> {
    let provider = provider();
    let verifier = Arc::new(PinnedPeerKeys::with_live_set(authorized_peers.clone(), &provider));
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(quic_config_error)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            device_certified_key(device),
        )));
    crypto.alpn_protocols = vec![YADORILINK_P2P_ALPN.to_vec()];
    // The server half of refusing resumption: issue no tickets and remember
    // no sessions, so a revoked device has nothing to present but its key.
    crypto.send_tls13_tickets = 0;
    crypto.session_storage = Arc::new(NoServerSessionStorage {});
    // 0-RTT data would arrive before this handshake's client authentication
    // has happened at all.
    crypto.max_early_data_size = 0;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(quic_config_error)?,
    )))
}

/// Both failures these constructors can report are "the crypto provider does
/// not offer what TLS 1.3 over QUIC needs", which is a build-time property of
/// the pinned `ring` provider rather than anything a caller or a peer
/// influences. They are surfaced as errors anyway: a handshake path must not
/// contain a panic that a future provider change could reach.
fn quic_config_error(err: impl fmt::Display) -> TransportError {
    TransportError::QuicConfig(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encode and decode halves have to be exact inverses, because one
    /// runs on what this device presents and the other on what it accepts.
    #[test]
    fn an_spki_this_device_emits_decodes_back_to_the_same_key() {
        let device = DeviceSigningKeyPair::generate();
        let spki = ed25519_spki(&device.public_bytes());
        assert_eq!(spki.len(), ED25519_SPKI_LEN);
        assert_eq!(ed25519_key_from_spki(&spki), Some(device.public_bytes()));
    }

    /// Every one of these arrives from an unauthenticated peer, so the
    /// requirement is `None` rather than a panic -- a truncated prefix in
    /// particular is what a naive fixed-offset slice would fault on.
    #[test]
    fn malformed_subject_public_key_info_is_rejected_without_panicking() {
        let good = ed25519_spki(&[7u8; 32]);

        assert_eq!(ed25519_key_from_spki(&[]), None, "empty");
        assert_eq!(ed25519_key_from_spki(&good[..5]), None, "truncated inside the prefix");
        assert_eq!(ed25519_key_from_spki(&good[..ED25519_SPKI_LEN - 1]), None, "short key");

        let mut long = good.clone();
        long.push(0);
        assert_eq!(ed25519_key_from_spki(&long), None, "trailing bytes");

        let mut wrong_oid = good.clone();
        wrong_oid[8] = 0x71;
        assert_eq!(ed25519_key_from_spki(&wrong_oid), None, "a different algorithm identifier");
    }

    /// The identity a peer receives and the key that signs the transcript
    /// have to be the same key. Disagreement between them would fail only at
    /// the peer, during a handshake, for a reason nothing local reports.
    ///
    /// `CertifiedKey::keys_match` is deliberately not used: it parses the
    /// first entry as an X.509 certificate, which under RFC 7250 it is not.
    #[test]
    fn the_presented_public_key_matches_the_key_that_signs() {
        let device = DeviceSigningKeyPair::generate();
        let certified = device_certified_key(&device);

        let presented = certified.end_entity_cert().expect("an identity is present");
        assert_eq!(
            ed25519_key_from_spki(presented.as_ref()),
            Some(device.public_bytes()),
            "the key a peer is shown"
        );
        let advertised = certified.key.public_key().expect("the signing key exposes its SPKI");
        assert_eq!(advertised.as_ref(), presented.as_ref(), "the key that signs");
    }

    /// Only Ed25519, and specifically not "the first thing offered".
    #[test]
    fn no_scheme_other_than_ed25519_is_accepted() {
        let device = DeviceSigningKeyPair::generate();
        let key = DeviceSigningIdentity {
            signing: device.signing.clone(),
            spki: ed25519_spki(&device.public_bytes()),
        };

        assert!(key.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256]).is_none());
        assert!(key.choose_scheme(&[]).is_none());
        let chosen = key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256, SignatureScheme::ED25519])
            .expect("Ed25519 was on offer");
        assert_eq!(chosen.scheme(), SignatureScheme::ED25519);
    }

    /// The signature the TLS layer will hand to a peer must verify under the
    /// public key this device advertises.
    #[test]
    fn a_produced_signature_verifies_under_the_advertised_key() {
        use ed25519_dalek::Verifier as _;

        let device = DeviceSigningKeyPair::generate();
        let key = DeviceSigningIdentity {
            signing: device.signing.clone(),
            spki: ed25519_spki(&device.public_bytes()),
        };
        let signer = key.choose_scheme(&[SignatureScheme::ED25519]).expect("Ed25519 signer");

        let signature = signer.sign(b"a transcript stand-in").expect("sign");
        let signature =
            ed25519_dalek::Signature::from_slice(&signature).expect("64-byte signature");
        assert!(device.verifying.verify(b"a transcript stand-in", &signature).is_ok());
    }

    /// The membership test itself, in both directions and with the empty set
    /// included, without needing a handshake to reach it.
    #[test]
    fn only_pinned_keys_are_accepted_by_either_verifier() {
        let provider = provider();
        let pinned = DeviceSigningKeyPair::generate();
        let stranger = DeviceSigningKeyPair::generate();

        let verifier = PinnedPeerKeys::new([pinned.public_bytes()], &provider);
        let good = CertificateDer::from(ed25519_spki(&pinned.public_bytes()));
        let bad = CertificateDer::from(ed25519_spki(&stranger.public_bytes()));

        assert!(verifier.accept(&good, &[]).is_ok());
        assert!(verifier.accept(&bad, &[]).is_err());
        // A pinned key with anything appended to it is still a refusal: the
        // profile is one key, alone.
        assert!(verifier.accept(&good, std::slice::from_ref(&bad)).is_err());

        let refuses_everyone = PinnedPeerKeys::new([], &provider);
        assert!(refuses_everyone.accept(&good, &[]).is_err(), "an empty set must fail closed");
    }

    /// The membership test reads the live set, not a copy taken when the
    /// verifier was built. Without this the whole point of the shared set is
    /// lost: `quic_server_config` would still be answering with whatever the
    /// netmap said at endpoint-construction time.
    ///
    /// The handshake-level counterpart -- a key removed from a *running*
    /// endpoint's set being refused on the next connection -- is in
    /// `tests/quic_peer_identity.rs`; this one pins the decision itself.
    #[test]
    fn the_verifier_reads_the_live_set_rather_than_a_snapshot() {
        let provider = provider();
        let peer = DeviceSigningKeyPair::generate();
        let presented = CertificateDer::from(ed25519_spki(&peer.public_bytes()));

        let authorized = AuthorizedPeerKeys::new();
        let verifier = PinnedPeerKeys::with_live_set(authorized.clone(), &provider);
        assert!(verifier.accept(&presented, &[]).is_err(), "nobody authorized yet");

        assert!(authorized.authorize(peer.public_bytes()), "newly added");
        assert!(verifier.accept(&presented, &[]).is_ok(), "authorized after construction");

        assert!(authorized.revoke(&peer.public_bytes()), "was authorized");
        assert!(verifier.accept(&presented, &[]).is_err(), "refused once revoked");

        // A whole-set replacement is how a netmap push lands, and it has to
        // move membership in both directions at once.
        let other = DeviceSigningKeyPair::generate();
        let _ = authorized.replace([peer.public_bytes(), other.public_bytes()]);
        assert!(verifier.accept(&presented, &[]).is_ok(), "restored by a replacement");
        // The replacement must also REPORT what it dropped: a caller that
        // only learned the new membership could not finish revoking the
        // peers this removed.
        let removed = authorized.replace([other.public_bytes()]);
        assert_eq!(removed, vec![peer.public_bytes()], "a replacement must report what it drops");
        assert!(verifier.accept(&presented, &[]).is_err(), "dropped by a replacement");

        // And an emptying replacement still fails closed, which is the state
        // a device with no peers left should be in.
        assert_eq!(authorized.replace([]), vec![other.public_bytes()]);
        assert!(authorized.is_empty());
        assert!(verifier.accept(&presented, &[]).is_err(), "an emptied set must fail closed");
    }
}
