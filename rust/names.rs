//! Names area discovery and sampling utilities.

use super::error::{KallsymsError, Result};

/// Locate the names block and the num_syms value preceding it by scanning
/// back from markers. Supports num_syms stored as u32 or u64.
pub fn find_names_and_num_syms(
    data: &[u8],
    markers_offset: usize,
    _names_size_hint: usize,
    markers_count: usize,
) -> Result<(usize, usize, usize)> {
    let max_back = 4 * 1024 * 1024;
    let search_start = markers_offset.saturating_sub(max_back);
    let search_end = markers_offset;
    let expected_markers = markers_count;

    for ns_off in (search_start..search_end).step_by(4) {
        if ns_off + 4 <= data.len() {
            let n = u32::from_le_bytes([
                data[ns_off],
                data[ns_off + 1],
                data[ns_off + 2],
                data[ns_off + 3],
            ]) as usize;
            if n > 0 && n.div_ceil(256) == expected_markers {
                let names_start = ns_off + 4;
                if walk_names_until_limit(data, names_start, n, search_end).is_some() {
                    return Ok((names_start, ns_off, n));
                }
            }
        }
        if ns_off + 8 <= data.len() {
            let n = u64::from_le_bytes([
                data[ns_off],
                data[ns_off + 1],
                data[ns_off + 2],
                data[ns_off + 3],
                data[ns_off + 4],
                data[ns_off + 5],
                data[ns_off + 6],
                data[ns_off + 7],
            ]) as usize;
            if n > 0 && n.div_ceil(256) == expected_markers {
                let names_start = ns_off + 8;
                if walk_names_until_limit(data, names_start, n, search_end).is_some() {
                    return Ok((names_start, ns_off, n));
                }
            }
        }
    }

    Err(KallsymsError::InvalidFormat(
        "names/num_syms not found".into(),
    ))
}

/// Walk a length-prefixed names block without decoding, enforcing a hard end.
pub fn walk_names_until_limit(
    data: &[u8],
    mut pos: usize,
    expected: usize,
    hard_end: usize,
) -> Option<usize> {
    for _ in 0..expected {
        if pos >= hard_end || pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 || len > 255 {
            return None;
        }
        pos += 1 + len;
    }
    Some(pos)
}

/// Collect up to max_samples encoded name entries for quick scoring.
pub fn collect_name_samples(
    data: &[u8],
    names_off: usize,
    names_size: usize,
    num_syms: usize,
    max_samples: usize,
) -> Vec<&[u8]> {
    let mut samples = Vec::with_capacity(max_samples.min(num_syms));
    let mut pos = names_off;
    let end = names_off + names_size;

    for _ in 0..max_samples.min(num_syms) {
        if pos >= end {
            break;
        }
        let len = data[pos] as usize;
        pos += 1;
        if len == 0 || pos + len > end {
            break;
        }
        let enc = &data[pos..pos + len];
        pos += len;
        samples.push(enc);
    }
    samples
}
