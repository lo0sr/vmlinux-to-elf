//! Search for token_index candidates and validate a complete kallsyms layout.

use log::info;
use rayon::iter::ParallelBridge;
use rayon::prelude::*;

use super::error::{KallsymsError, Result};
use super::helpers::is_valid_token_table;
use super::layout::KallsymsLayout;
use super::markers::find_markers_for_candidate;
use super::names::find_names_and_num_syms;

/// A plausible token table/index pairing location (index bytes are not stored).
#[derive(Debug, Clone)]
pub struct TokenCandidate {
    pub token_table_offset: usize,
    pub token_table_size: usize,
    pub token_index_offset: usize,
}

/// Find a complete, internally consistent kallsyms layout by testing candidates.
pub fn find_complete_kallsyms_structure(data: &[u8]) -> Result<KallsymsLayout> {
    info!("Kallsyms: Searching for complete structure...");

    let candidates = find_all_token_candidates(data);
    info!(
        "Kallsyms: Found {} token structure candidates",
        candidates.len()
    );

    // Try candidates in parallel; return the first that validates.
    if let Some(layout) = candidates
        .par_iter()
        .filter_map(|cand| try_build_complete_structure(data, cand).ok())
        .find_any(|_| true)
    {
        info!("Kallsyms: Candidate validated successfully!");
        return Ok(layout);
    }

    Err(KallsymsError::NotFound)
}

/// Scan the latter half of the file for 256x u16 non-decreasing arrays that
/// could be token_index, and a plausible token_table just before them.
pub fn find_all_token_candidates(data: &[u8]) -> Vec<TokenCandidate> {
    let start = data.len() / 2;
    let end = data.len().saturating_sub(512);
    let step = 2;

    // Iterate offsets lazily and process in parallel via ParallelBridge.
    let offsets = (start..end)
        .step_by(step)
        .filter(|pos| pos.is_multiple_of(2));

    offsets
        .par_bridge()
        .filter_map(|pos| {
            for use_be in [false, true] {
                // Validate monotonic 256x u16 and capture last value.
                let mut index_last = 0u16;
                for i in 0..256 {
                    let p = pos + i * 2;
                    let (&b0, &b1) = data.get(p).zip(data.get(p + 1))?;
                    let val = if use_be {
                        u16::from_be_bytes([b0, b1])
                    } else {
                        u16::from_le_bytes([b0, b1])
                    };
                    if i > 0 && val < index_last {
                        index_last = 0;
                        break;
                    }
                    index_last = val;
                }
                if !(64..=8192).contains(&index_last) {
                    continue;
                }
                let last_token_start = index_last as usize;

                // Try small set of paddings and table_end_offset.
                for padding in [0usize, 4, 8, 16, 32, 64, 128] {
                    let table_end_with_padding = pos.saturating_sub(padding);
                    if table_end_with_padding <= last_token_start + 2 {
                        continue;
                    }
                    for table_end_offset in 0..128usize {
                        let table_end = table_end_with_padding.saturating_sub(table_end_offset);
                        let table_size = last_token_start + table_end_offset + 1;
                        if !(64..=8192).contains(&table_size) {
                            continue;
                        }
                        let table_start = table_end.saturating_sub(table_size);
                        if table_end > data.len() || table_start >= table_end {
                            continue;
                        }
                        let table_slice = &data[table_start..table_end];
                        if table_slice.len() != table_size {
                            continue;
                        }
                        if last_token_start >= table_size {
                            continue;
                        }
                        if !is_valid_token_table(table_slice) {
                            continue;
                        }

                        return Some(TokenCandidate {
                            token_table_offset: table_start,
                            token_table_size: table_size,
                            token_index_offset: pos,
                        });
                    }
                }
            }
            None
        })
        .collect()
}

fn try_build_complete_structure(data: &[u8], candidate: &TokenCandidate) -> Result<KallsymsLayout> {
    let (markers_offset, markers_count) =
        find_markers_for_candidate(data, candidate.token_table_offset)?;

    let (names_offset, num_syms_offset, num_syms) =
        find_names_and_num_syms(data, markers_offset, 0, markers_count)?;

    // Prefer exact walk up to markers if possible
    let mut names_size = markers_offset - names_offset;
    let mut test_pos = names_offset;
    let mut count = 0;
    while test_pos < markers_offset && count < num_syms {
        if test_pos >= data.len() {
            break;
        }
        let len = data[test_pos] as usize;
        if len == 0 || len > 255 {
            break;
        }
        test_pos += 1 + len;
        count += 1;
    }
    if count == num_syms && test_pos <= markers_offset {
        names_size = test_pos - names_offset;
    }

    Ok(KallsymsLayout::new(
        num_syms,
        num_syms_offset,
        names_offset,
        names_size,
        markers_offset,
        markers_count,
        candidate.token_table_offset,
        candidate.token_table_size,
        candidate.token_index_offset,
    ))
}
