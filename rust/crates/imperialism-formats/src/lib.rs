#![forbid(unsafe_code)]

//! Compatibility boundary for retail saves, scenarios, maps, resources, and asset imports.
//!
//! Format implementations will decode into versioned legacy DTOs before converting into
//! `imperialism-core` state. This crate intentionally contains no live game rules or Bevy types.
