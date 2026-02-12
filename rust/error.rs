//! Error types and Result alias for kallsyms parsing.

use thiserror::Error;

/// All errors that can occur while parsing kallsyms.
#[derive(Error, Debug)]
pub enum KallsymsError {
    /// No compatible kallsyms structure was found.
    #[error("No kallsyms found (token table/index not discoverable)")]
    NotFound,
    /// The layout or decoded data violated format expectations.
    #[error("Invalid kallsyms format: {0}")]
    InvalidFormat(String),
    /// Input was compressed but decompression failed.
    #[error("Decompression failed: {0}")]
    Decompression(String),
    /// I/O error surfaced while reading a compressed stream.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenient result alias.
pub type Result<T> = std::result::Result<T, KallsymsError>;
