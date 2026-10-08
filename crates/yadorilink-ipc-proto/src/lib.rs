pub mod framing;
pub mod pipe_peer;

pub mod sync {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.sync.v1.rs"));
}

pub mod shellipc {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.shellipc.v1.rs"));
}

pub mod local_discovery {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.local_discovery.v1.rs"));
}

// Track Send's own peer-to-peer wire protocol -- see `proto/send.proto`'s
// own doc comment for why this is a wholly separate message family from
// `sync` above, never exchanged over the sync protocol's ALPN/stream.
pub mod send {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.send.v1.rs"));
}

pub mod daemonctl {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.daemonctl.v1.rs"));

    /// The one human-readable word for a path's local state, derived from its
    /// two independent facts: `remote` (nothing here), `local-stale` (an
    /// object stands but is not the current version), `local-current`,
    /// `hydrating`, `evicting`; `unknown` when the daemon reported nothing.
    #[must_use]
    pub fn local_state_word(state: Option<&LocalState>) -> &'static str {
        let Some(state) = state else { return "unknown" };
        match state.transition() {
            LocalTransition::Hydrating => "hydrating",
            LocalTransition::Evicting => "evicting",
            LocalTransition::None if state.current_content_present => "local-current",
            LocalTransition::None if state.local_object_present => "local-stale",
            LocalTransition::None => "remote",
        }
    }

    /// Exact daemon-control protocol generation for the current pre-release
    /// source tree. The CLI, desktop app, and daemon are shipped as one unit;
    /// development builds are not required to interoperate across protocol
    /// generations. A version mismatch should fail clearly rather than select a
    /// backward-compatibility path.
    ///
    /// `8`: adds Track Send's `send_file`/`list_inbox`/`receive_transfer`
    /// request and response variants.
    /// `9`: adds Folder Rewind's read-only `rewind_preview` request and
    /// response variants.
    /// `10`: added LAN discovery's read-only
    /// `list_lan_discovered_candidates` request and response variants.
    /// `11`: removes them again, together with the legacy LAN broadcast
    /// discovery that produced the candidate list -- peer connectivity is
    /// the reconciliation substrate's own endpoint, whose candidate set
    /// this daemon does not enumerate. A removal is as breaking as an
    /// addition: a stale CLI or desktop build would send a request
    /// variant this daemon no longer has a field for, and must be refused
    /// at the version check rather than have its request silently decode
    /// as "no payload set".
    ///
    /// `12`: adds the preserved-data requests (`list_preserved`, `restore_preserved`,
    /// `discard_preserved`) and the `preserved` summary of `StatusResponse`.
    ///
    /// `13`: adds `retry_preserved`.
    ///
    /// `14`: adds `LinkStatus.durability_check_pending`.
    ///
    /// `15`: removes the `pin`/`unpin` requests,
    /// `LinkRequest.max_local_size_bytes` and
    /// `MaterializationStatusResponse.pinned`.
    pub const CONTROL_PROTOCOL_VERSION: u32 = 15;
}

#[cfg(test)]
mod tests;
