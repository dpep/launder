//! launder — make logs pastesafe.
//!
//! Pipe in a stack trace or log spew and get the same text back with
//! identifying paths, usernames, secrets, and contacts replaced by readable
//! semantic placeholders — while preserving everything a reader needs to
//! actually help (relative paths, extensions, line numbers, system paths,
//! diagnostic IDs).
//!
//! Pipeline: **read line → detect spans → resolve overlaps → assign
//! placeholders → emit.** Streaming and line-oriented; one line in flight
//! (except `-j`, which also accumulates for the final object). See `README.md`
//! for the product vision and `CLAUDE.md` for conventions.

pub mod cli;
pub mod config;
pub mod detect;
pub mod emit;
pub mod engine;
pub mod input;
pub mod registry;
pub mod report;
pub mod system;
