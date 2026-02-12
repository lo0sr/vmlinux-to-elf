//! Token index/table alignment and name-plausibility scoring.

use log::info;
use rayon::prelude::*;

use super::error::{KallsymsError, Result};
use super::helpers::{is_valid_symbol_name_bytes, starts_with_any};

/// Common kernel prefixes to score plausible decoded names.
fn common_prefixes() -> &'static [&'static [u8]] {
    &[
        b"__",
        b"_s",
        b"_t",
        b"init",
        b"ext",
        b"drm_",
        b"clk_",
        b"devm_",
        b"trace",
        b"cpu_",
        b"arm_",
        b"arch_",
        b"mm_",
        b"vm_",
        b"kmem",
        b"mem",
        b"usb_",
        b"pcie_",
        b"nvme_",
        b"scsi_",
        b"ufs_",
        b"f2fs_",
        b"ext4_",
        b"proc_",
        b"rcu_",
        b"sched_",
        b"ioremap",
        b"module_",
        b"security_",
        b"debug_",
    ]
}

/// Align and read the 256x u16 token_index array within ±32 bytes of the hint.
/// Uses name plausibility to break ties and prefers 8-byte alignment.
pub fn align_and_read_token_index(
    data: &[u8],
    index_off_hint: usize,
    table_off_hint: usize,
    names_off: usize,
    names_size: usize,
    num_syms: usize,
) -> Result<[u16; 256]> {
    // Probe ±32 bytes around hint, even offsets
    let offsets: Vec<usize> = (-32i32..=32)
        .map(|d| {
            if d < 0 {
                index_off_hint.saturating_sub(d.unsigned_abs() as usize)
            } else {
                index_off_hint.saturating_add(d as usize)
            }
        })
        .filter(|&off| off.is_multiple_of(2) && off + 512 <= data.len())
        .collect();

    let result = offsets
        .par_iter()
        .filter_map(|&off| {
            let mut best: Option<([u16; 256], usize, f64)> = None;
            for is_be in [false, true] {
                let arr = match read_token_index_exact(data, off, is_be) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if !arr.windows(2).all(|w| w[0] <= w[1]) || arr[255] < 64 || arr[255] > 8192 {
                    continue;
                }
                let name_score = extract_tokens_strict_at_base(data, table_off_hint, &arr)
                    .map(|(toks, _)| {
                        score_names_with_tokens_raw(data, names_off, names_size, num_syms, &toks)
                    })
                    .unwrap_or(0.0);

                let align_bonus = if off.is_multiple_of(8) {
                    2.0
                } else if off.is_multiple_of(4) {
                    1.0
                } else {
                    0.0
                };
                let prox = 1.0 / (1.0 + ((off as isize - index_off_hint as isize).abs() as f64));
                let endian_bonus = if is_be { 0.0 } else { 0.02 };
                let score = name_score * 0.7 + align_bonus * 0.2 + prox * 0.1 + endian_bonus;

                match best {
                    Some((_, _, best_score)) if best_score >= score => {}
                    _ => best = Some((arr, off, score)),
                }
            }
            best
        })
        .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap());

    if let Some((arr, off, _)) = result {
        if off != index_off_hint {
            info!(
                "Kallsyms: corrected token_index alignment to 0x{:08x} (was 0x{:08x})",
                off, index_off_hint
            );
        }
        Ok(arr)
    } else {
        Err(KallsymsError::InvalidFormat(
            "token index alignment failed".into(),
        ))
    }
}

/// Read exactly 256 u16 entries from the given offset in selected endianness.
pub fn read_token_index_exact(data: &[u8], offset: usize, is_be: bool) -> Result<[u16; 256]> {
    let mut index = [0u16; 256];
    for (i, slot) in index.iter_mut().enumerate() {
        let pos = offset + i * 2;
        if pos + 1 >= data.len() {
            return Err(KallsymsError::InvalidFormat("token index truncated".into()));
        }
        *slot = if is_be {
            u16::from_be_bytes([data[pos], data[pos + 1]])
        } else {
            u16::from_le_bytes([data[pos], data[pos + 1]])
        };
    }
    Ok(index)
}

/// Locate the correct token_table base near the hint and extract all 256 tokens.
/// Validates token boundary ordering and scores name plausibility.
pub fn extract_tokens_with_name_validation(
    data: &[u8],
    table_off_hint: usize,
    index: &[u16; 256],
    names_off: usize,
    names_size: usize,
    num_syms: usize,
) -> Result<(Vec<Vec<u8>>, usize, usize)> {
    let window: Vec<usize> = (-512i32..=512)
        .map(|d| {
            if d < 0 {
                table_off_hint.saturating_sub(d.unsigned_abs() as usize)
            } else {
                table_off_hint.saturating_add(d as usize)
            }
        })
        .filter(|&off| off < data.len())
        .collect();

    let best = window
        .par_iter()
        .filter_map(|&off| {
            let (tokens, size) = extract_tokens_strict_at_base(data, off, index).ok()?;
            let name_score =
                score_names_with_tokens_raw_strict(data, names_off, names_size, num_syms, &tokens);
            let token_score = tokens.len() as f64 / 256.0;
            let off4 = (off + 3) & !3;
            let delta4 = (off4 as isize - table_off_hint as isize).unsigned_abs();
            let bias = 1.5 / (1.0 + delta4 as f64);
            let score = token_score * 0.2 + name_score * 0.7 + 0.1 * bias;
            Some((tokens, off, size, score))
        })
        .max_by(|a, b| a.3.partial_cmp(&b.3).unwrap());

    if let Some((toks, off, size, _score)) = best {
        // Accept any score - don't apply plausibility filters
        Ok((toks, off, size))
    } else {
        Err(KallsymsError::InvalidFormat(
            "token table alignment not found".into(),
        ))
    }
}

/// Extract tokens at a fixed base using the index; ensures NUL termination and non-overlap.
pub fn extract_tokens_strict_at_base(
    data: &[u8],
    base: usize,
    index: &[u16; 256],
) -> Result<(Vec<Vec<u8>>, usize)> {
    let mut tokens: Vec<Vec<u8>> = Vec::with_capacity(256);
    let mut last_end = base;

    for i in 0..256 {
        let start = base + index[i] as usize;
        if start >= data.len() || start < base {
            return Err(KallsymsError::InvalidFormat(
                "token start OOB or before base".into(),
            ));
        }
        // Find the first NUL
        let mut z = start;
        while z < data.len() && data[z] != 0 {
            z += 1;
        }
        if z >= data.len() {
            return Err(KallsymsError::InvalidFormat("token end not found".into()));
        }
        if i < 255 {
            let next_start = base + index[i + 1] as usize;
            if z > next_start {
                return Err(KallsymsError::InvalidFormat(
                    "token overflows into next".into(),
                ));
            }
        }
        tokens.push(data[start..z].to_vec());
        last_end = z + 1;
    }

    let size = last_end.saturating_sub(base);
    Ok((tokens, size))
}

/// Strict plausibility scoring with larger sample size and stronger penalties.
pub fn score_names_with_tokens_raw_strict(
    data: &[u8],
    names_off: usize,
    names_size: usize,
    num_syms: usize,
    tokens: &[Vec<u8>],
) -> f64 {
    let prefixes = common_prefixes();
    let sample = num_syms.min(256);
    let mut pos = names_off;
    let end = names_off + names_size;

    let mut ok = 0usize;
    let mut short_bad = 0usize;
    let mut very_short = 0usize;
    let mut prefix_hits = 0usize;
    let mut total = 0usize;

    for _ in 0..sample {
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

        total += 1;
        if enc.is_empty() {
            continue;
        }
        let type_byte = enc[0];
        let bytes = &enc[1..];

        let mut out = Vec::with_capacity(1 + bytes.len() * 4);
        out.push(type_byte);

        for &b in bytes {
            let empty: &[u8] = &[];
            let tok = tokens.get(b as usize).map(|v| &v[..]).unwrap_or(empty);
            out.extend_from_slice(tok);
        }

        if out.len() < 3 {
            very_short += 1;
            continue;
        }
        let name_bytes = &out[1..];

        if name_bytes.len() <= 2 {
            very_short += 1;
        }

        if is_valid_symbol_name_bytes(name_bytes) {
            ok += 1;
            if starts_with_any(name_bytes, prefixes) {
                prefix_hits += 1;
            }
        } else if out.len() <= 6 {
            short_bad += 1;
        }
    }

    if total == 0 {
        return 0.0;
    }
    let ok_ratio = ok as f64 / total as f64;
    let short_penalty = (short_bad as f64 / total as f64) * 0.7;
    let very_short_penalty = (very_short as f64 / total as f64) * 0.9;
    let prefix_bonus = (prefix_hits as f64 / total as f64) * 0.35;

    (ok_ratio - short_penalty - very_short_penalty + prefix_bonus).clamp(0.0, 1.0)
}

/// Lightweight plausibility scoring with smaller sample and softer penalties.
pub fn score_names_with_tokens_raw(
    data: &[u8],
    names_off: usize,
    names_size: usize,
    num_syms: usize,
    tokens: &[Vec<u8>],
) -> f64 {
    let prefixes = common_prefixes();
    let sample = num_syms.min(96);
    let mut pos = names_off;
    let end = names_off + names_size;

    let mut ok = 0usize;
    let mut short_bad = 0usize;
    let mut prefix_hits = 0usize;
    let mut total = 0usize;

    for _ in 0..sample {
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

        total += 1;
        if enc.is_empty() {
            continue;
        }
        let type_byte = enc[0];
        let bytes = &enc[1..];

        let mut out = Vec::with_capacity(1 + bytes.len() * 4);
        out.push(type_byte);

        for &b in bytes {
            let empty: &[u8] = &[];
            let tok = tokens.get(b as usize).map(|v| &v[..]).unwrap_or(empty);
            out.extend_from_slice(tok);
        }

        if out.len() < 3 {
            short_bad += 1;
            continue;
        }
        let name_bytes = &out[1..];
        if is_valid_symbol_name_bytes(name_bytes) {
            ok += 1;
            if starts_with_any(name_bytes, prefixes) {
                prefix_hits += 1;
            }
        } else if out.len() <= 6 {
            short_bad += 1;
        }
    }

    if total == 0 {
        return 0.0;
    }
    let ok_ratio = ok as f64 / total as f64;
    let short_penalty = (short_bad as f64 / total as f64) * 0.4;
    let prefix_bonus = (prefix_hits as f64 / total as f64) * 0.25;

    (ok_ratio - short_penalty + prefix_bonus).clamp(0.0, 1.0)
}
