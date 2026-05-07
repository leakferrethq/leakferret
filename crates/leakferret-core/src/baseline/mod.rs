//! Per-repo baseline of known findings + append-only history log.
//!
//! `.leakferret-baseline.json` (committed) is the current-state
//! ledger: one entry per fingerprinted secret with first-seen,
//! last-verified, status (`Active` / `Rotated` / `Fixture` / `Ignored`),
//! and policy hints (`block_in_ci`).
//!
//! `.leakferret-history.jsonl` (committed; can grow large) is the
//! append-only audit log of every state transition. Useful for the
//! hosted dashboard and for forensic timelines.
//!
//! Fingerprints are [`crate::Fingerprint`] — HMAC-SHA256 with a
//! per-repo salt loaded from `.leakferret-salt`. The salt makes
//! fingerprints unique-per-repo so a leaked baseline cannot be used
//! to identify secrets in *another* repo.

mod history;
mod store;

pub use history::{append_event, HistoryEvent, HistoryEventKind};
pub use store::{load_or_init, save, Baseline, BaselineEntry, BaselineExposure, BaselineStatus};
