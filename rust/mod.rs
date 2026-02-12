//! Kallsyms parser (modular, documented, parallel by default).
//!
//! - Discovers kallsyms components inside a kernel image (optionally gzip/LZ4).
//! - Aligns token_index and token_table precisely with robust checks.
//! - Finds names, markers, and addresses with strict plausibility filters.
//! - Auto-selects a vendor variant for name decoding (V1..V4).
//! - Uses rayon to parallelize expensive loops.
//!
//! Entry point: Kallsyms::parse(bytes)

mod addresses;
mod candidates;
mod decoder;
mod decompress;
mod error;
mod helpers;
mod layout;
mod markers;
mod names;
mod parser;
mod tokens;
mod types;
mod samsung;

pub use error::{KallsymsError, Result};
pub use parser::Kallsyms;
pub use types::{KallsymsStats, Symbol, SymbolType};
pub use samsung::extract_samsung_kallsyms;
