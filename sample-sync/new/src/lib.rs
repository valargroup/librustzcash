//! Proposed Orchard sync caller API model.
//!
//! This crate is a design target for the replacement API. It intentionally
//! contains traits and data shapes rather than implementation. The key design
//! difference from `sample-sync-legacy` is that callers pass viewing keys
//! directly, and the API separates discovery, full transaction ingestion, and
//! note-centric witness maintenance.

pub mod api;

pub use api::*;
