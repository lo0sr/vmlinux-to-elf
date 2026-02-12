//! Address extraction (absolute u64 or base+relative i32).

use super::error::{KallsymsError, Result};
use super::helpers::relax_validate_kernel_addresses;
use log::info;

/// Find addresses array near num_syms (within a window) and decode it.
/// Supports absolute u64 or base(u64)+relative i32 formats.
pub fn find_and_read_addresses(
    data: &[u8],
    num_syms_offset: usize,
    num_syms: usize,
) -> Result<Vec<u64>> {
    let window = 1024 * 1024;
    let start = num_syms_offset.saturating_sub(window);
    let end = num_syms_offset;

    if let Some(addrs) = try_find_relative_in_window(data, start, end, num_syms) {
        info!("Kallsyms: using relative offsets format (window)");
        return Ok(addrs);
    }
    if let Some(addrs) = try_find_absolute_in_window(data, start, end, num_syms) {
        info!("Kallsyms: using absolute addresses format (window)");
        return Ok(addrs);
    }

    Err(KallsymsError::InvalidFormat("addresses not found".into()))
}

/// Try base(u64)+relative(i32) layout inside [start, end).
pub fn try_find_relative_in_window(
    data: &[u8],
    start: usize,
    end: usize,
    num_syms: usize,
) -> Option<Vec<u64>> {
    if num_syms == 0 {
        return None;
    }
    let offsets_size = num_syms.checked_mul(4)?;
    for base_pos in (start..end).step_by(4) {
        if base_pos + 8 > end {
            break;
        }
        let base = u64::from_le_bytes([
            data[base_pos],
            data[base_pos + 1],
            data[base_pos + 2],
            data[base_pos + 3],
            data[base_pos + 4],
            data[base_pos + 5],
            data[base_pos + 6],
            data[base_pos + 7],
        ]);
        let min_offsets_start = start;
        let max_offsets_start = base_pos.saturating_sub(offsets_size);
        if max_offsets_start < min_offsets_start {
            continue;
        }
        let try_offsets = [max_offsets_start, base_pos.saturating_sub(offsets_size)];
        for &offsets_start in &try_offsets {
            if offsets_start + offsets_size > base_pos {
                continue;
            }
            let mut addrs = Vec::with_capacity(num_syms);
            for i in 0..num_syms {
                let p = offsets_start + i * 4;
                if p + 3 >= data.len() {
                    addrs.clear();
                    break;
                }
                let off = i32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
                addrs.push(base.wrapping_add(off as i64 as u64));
            }
            if !addrs.is_empty() && relax_validate_kernel_addresses(&addrs) {
                return Some(addrs);
            }
        }
    }
    None
}

/// Try absolute u64 array layout inside [start, end).
pub fn try_find_absolute_in_window(
    data: &[u8],
    start: usize,
    end: usize,
    num_syms: usize,
) -> Option<Vec<u64>> {
    let total = num_syms.checked_mul(8)?;
    for s in (start..end).step_by(8) {
        if s + total > end {
            break;
        }
        let mut addrs = Vec::with_capacity(num_syms);
        for i in 0..num_syms {
            let p = s + i * 8;
            if p + 7 >= data.len() {
                addrs.clear();
                break;
            }
            addrs.push(u64::from_le_bytes([
                data[p],
                data[p + 1],
                data[p + 2],
                data[p + 3],
                data[p + 4],
                data[p + 5],
                data[p + 6],
                data[p + 7],
            ]));
        }
        if !addrs.is_empty() && relax_validate_kernel_addresses(&addrs) {
            return Some(addrs);
        }
    }
    None
}
