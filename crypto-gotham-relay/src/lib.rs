// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod client;
pub mod cover_loop;
pub mod delay;
pub mod enroll_client;
pub mod gossip;
pub mod mailbox_client;
pub mod nat;
pub mod pool;
pub mod process;
pub mod rate_limit;
pub mod rendezvous;
pub mod replay;
pub mod surb;
pub mod transport;

pub use client::{ClientError, GothamClient, MAX_PAYLOAD_SIZE};
pub use cover_loop::{spawn_cover_loop, CoverLoopHandle, QueuedMessage, QueuedPacket};
pub use delay::PoissonScheduler;
pub use gossip::{spawn_gossip_loop, GossipConfig, GossipError, GossipNode};
pub use mailbox_client::{fetch_auth_for, MailboxClient, MailboxClientError};
pub use pool::ConnectionPool;
pub use process::{DropReason, ProcessOutcome, Relay};
pub use rate_limit::{RateDecision, RateLimiter, ThrottleReason};
pub use replay::{ReplayCache, ReplayCheck};
pub use surb::{build_surb, build_surb_with_delay, ship_surb_reply, Surb, SurbError, SurbKeys};
pub use transport::{
    allow_unauthenticated_mailbox_fetch, make_mailbox_deposit_handler,
    make_mailbox_service_handler, make_unsealing_delivery_handler, run_relay_listener,
    run_relay_listener_with_mailbox, run_relay_listener_with_services,
    run_relay_listener_with_services_shared, serve_endpoint, serve_endpoint_with_mailbox,
    serve_endpoint_with_services, serve_endpoint_with_services_shared,
    set_allow_unauthenticated_mailbox_fetch, DeliveryHandler, GossipService, TransportError,
};

pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
