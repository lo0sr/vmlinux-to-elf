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
        let base_le = u64::from_le_bytes([
            data[base_pos],
            data[base_pos + 1],
            data[base_pos + 2],
            data[base_pos + 3],
            data[base_pos + 4],
            data[base_pos + 5],
            data[base_pos + 6],
            data[base_pos + 7],
        ]);
        let base_be = u64::from_be_bytes([
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
            for (base, is_be) in [(base_le, false), (base_be, true)] {
                let mut addrs = Vec::with_capacity(num_syms);
                for i in 0..num_syms {
                    let p = offsets_start + i * 4;
                    if p + 3 >= data.len() {
                        addrs.clear();
                        break;
                    }
                    let off = if is_be {
                        i32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]])
                    } else {
                        i32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]])
                    };
                    addrs.push(base.wrapping_add(off as i64 as u64));
                }
                if !addrs.is_empty() && relax_validate_kernel_addresses(&addrs) {
                    return Some(addrs);
                }
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
    for ptr_size in [8usize, 4usize] {
        let total = num_syms.checked_mul(ptr_size)?;
        for s in (start..end).step_by(ptr_size) {
            if s + total > end {
                break;
            }
            for is_be in [false, true] {
                let mut addrs = Vec::with_capacity(num_syms);
                for i in 0..num_syms {
                    let p = s + i * ptr_size;
                    if p + ptr_size - 1 >= data.len() {
                        addrs.clear();
                        break;
                    }
                    let addr = if ptr_size == 8 {
                        let arr = [
                            data[p],
                            data[p + 1],
                            data[p + 2],
                            data[p + 3],
                            data[p + 4],
                            data[p + 5],
                            data[p + 6],
                            data[p + 7],
                        ];
                        if is_be {
                            u64::from_be_bytes(arr)
                        } else {
                            u64::from_le_bytes(arr)
                        }
                    } else {
                        let arr = [data[p], data[p + 1], data[p + 2], data[p + 3]];
                        let v = if is_be {
                            u32::from_be_bytes(arr)
                        } else {
                            u32::from_le_bytes(arr)
                        };
                        v as u64
                    };
                    addrs.push(addr);
                }
                if !addrs.is_empty() && relax_validate_kernel_addresses(&addrs) {
                    return Some(addrs);
                }
            }
        }
    }
    None
}
