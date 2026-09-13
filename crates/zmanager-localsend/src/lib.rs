//! LAN peer discovery and `LocalSend`-protocol file transfer for `ZManager`.
//!
//! This crate is a thin wrapper around the vendored `localsend-rs` fork
//! (MIT, originally `CrossCopy/localsend-rs` — see NOTICE /
//! `THIRD_PARTY_NOTICES.md`). No protocol behavior is added or changed here;
//! `LocalSend` v2 is push-only by design and stays that way. Application-level
//! workflows that need a "response" (e.g. contact-list sync) are built as
//! two ordinary pushes, not as new wire primitives.

mod registry;

pub use localsend_rs as protocol;
pub use registry::{
    BridgeResult, CancelSendRequest, DeviceInfoDto, DiscoverRequest, DiscoveredDevice, LocalSendBridgeError, LocalSendRegistry, PollEventsResult, QueuedEvent,
    RespondToTransferRequest, SendFileRequest, SendFileResult, StartReceiverRequest, TransferDecisionKind, TransferFile, registry,
};
