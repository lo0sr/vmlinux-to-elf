//! Transparent input decompression when the buffer is gzip or LZ4.

use std::io::{Cursor, Read};
use log::info;

use super::error::{KallsymsError, Result};

/// If the input looks like gzip or LZ4, decompress it; otherwise return it as-is.
pub fn decompress_kernel_if_needed(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 4 {
        return Ok(data.to_vec());
    }

    // Gzip
    if data.starts_with(&[0x1f, 0x8b]) {
        info!("Kallsyms: gzip detected, decompressing");
        let mut dec = flate2::read::GzDecoder::new(data);
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .map_err(|e| KallsymsError::Decompression(e.to_string()))?;
        return Ok(out);
    }

    // LZ4 frame
    if data.get(0..4) == Some(&[0x04, 0x22, 0x4d, 0x18]) {
        info!("Kallsyms: lz4 frame detected, decompressing");
        let mut dec = lz4_flex::frame::FrameDecoder::new(Cursor::new(data));
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .map_err(|e| KallsymsError::Decompression(e.to_string()))?;
        return Ok(out);
    }

    Ok(data.to_vec())
}
