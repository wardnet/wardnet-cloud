//! End-to-end mesh-mTLS harness crate.
//!
//! This crate carries no library code — it exists only to host the
//! docker-compose-backed integration test in `tests/tombstone_flow.rs`, which is
//! `#[ignore]`d and driven by the `source/Makefile` `e2e-*` targets. The compose
//! topology and service Dockerfiles live alongside it under `end2end-tests/mesh/`.
