//! Discovery of the kallsyms "markers" array (descending u32 offsets).

use super::error::{KallsymsError, Result};

/// Locate the end-aligned markers array before the token table.
/// Returns (markers_start_offset, markers_count).
pub fn find_markers_for_candidate(
    data: &[u8],
    token_table_offset: usize,
) -> Result<(usize, usize)> {
    if token_table_offset < 64 {
        return Err(KallsymsError::InvalidFormat(
            "token_table too early in file".into(),
        ));
    }

    let start_search = token_table_offset.saturating_sub(256 * 1024);
    for pos in (start_search..token_table_offset).step_by(4).rev() {
        if let Some(result) = try_read_markers_ending_at(data, pos) {
            return Ok(result);
        }
    }

    Err(KallsymsError::InvalidFormat("markers not found".into()))
}

/// Try to interpret a descending sequence of u32 offsets ending at end_pos.
pub fn try_read_markers_ending_at(data: &[u8], end_pos: usize) -> Option<(usize, usize)> {
    let end_pos = end_pos & !3;
    if end_pos < 40 {
        return None;
    }

    let mut pos = end_pos - 4;
    let mut prev = u32::from_le_bytes([
        data[end_pos - 4],
        data[end_pos - 3],
        data[end_pos - 2],
        data[end_pos - 1],
    ]);
    let mut count = 1;

    while pos >= 4 && count < 4096 {
        pos -= 4;
        let val = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        if val >= prev {
            pos += 4;
            break;
        }
        prev = val;
        count += 1;
    }

    if count < 8 {
        return None;
    }

    let markers_start = pos;
    let markers_count = count;

    let estimated_syms = markers_count * 256;
    if !(1000..=2_000_000).contains(&estimated_syms) {
        return None;
    }

    Some((markers_start, markers_count))
}
