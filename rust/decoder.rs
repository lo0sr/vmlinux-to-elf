//! Name decoder selection (V1..V4) and full name decoding.

use log::warn;
use rayon::prelude::*;

use super::error::{KallsymsError, Result};
use super::helpers::{is_valid_symbol_name_bytes, starts_with_any};
use super::names::collect_name_samples;

/// Supported decode variants:
/// - V1: tokens[b]
/// - V2: tokens[token_index[b]]
/// - V3: tokens[remap[b]]
/// - V4: tokens[token_index[remap[b]]]
#[derive(Clone, Copy, Debug)]
pub enum DecodeVariant {
    V1TokensRaw,
    V2TokensViaIndex,
    V3TokensViaRemap,
    V4TokensViaIndexRemap,
}

/// Selected decoding strategy and score.
#[derive(Clone, Copy, Debug)]
pub struct DecodeStrategy {
    pub variant: DecodeVariant,
    pub name: &'static str,
    pub remap: Option<[u8; 256]>,
    pub remap_offset: Option<usize>,
    pub score: f64,
}

/// Search for 256-byte permutations near token_table or names that may act as remap tables.
pub fn detect_remap_candidates(
    data: &[u8],
    token_table_off: usize,
    names_off: usize,
    window: usize,
) -> Vec<(usize, [u8; 256])> {
    let mut out = Vec::new();
    for &center in &[token_table_off, names_off] {
        let start = center.saturating_sub(window);
        let end = (center + window).min(data.len());
        let mut off = start;
        while off + 256 <= end {
            if let Some(rem) = try_read_permutation(&data[off..off + 256]) {
                out.push((off, rem));
                if out.len() >= 4 {
                    break;
                }
            }
            off += 1;
        }
        if !out.is_empty() {
            break;
        }
    }
    out
}

/// Validate that a 256-byte slice is a proper permutation (each value unique).
pub fn try_read_permutation(slice: &[u8]) -> Option<[u8; 256]> {
    if slice.len() != 256 {
        return None;
    }
    let mut seen = [false; 256];
    for &b in slice {
        if seen[b as usize] {
            return None;
        }
        seen[b as usize] = true;
    }
    let mut rem = [0u8; 256];
    rem.copy_from_slice(slice);
    Some(rem)
}

/// Score all decode variants and pick the highest-scoring one.
pub fn select_decode_strategy(
    data: &[u8],
    names_off: usize,
    names_size: usize,
    num_syms: usize,
    tokens: &[Vec<u8>],
    token_index: &[u16; 256],
    remap_candidates: &[(usize, [u8; 256])],
) -> DecodeStrategy {
    let samples = collect_name_samples(data, names_off, names_size, num_syms, 192);

    // Build candidate strategies. Parallel-score them.
    let base = [
        DecodeStrategy {
            variant: DecodeVariant::V1TokensRaw,
            name: "V1(tokens[b])",
            remap: None,
            remap_offset: None,
            score: 0.0,
        },
        DecodeStrategy {
            variant: DecodeVariant::V2TokensViaIndex,
            name: "V2(tokens[token_index[b]])",
            remap: None,
            remap_offset: None,
            score: 0.0,
        },
    ];

    let mut variants: Vec<DecodeStrategy> = base.into();

    for (i, (off, rem)) in remap_candidates.iter().take(2).enumerate() {
        let label = if i == 0 {
            "V3(tokens[remap[b]])"
        } else {
            "V3(tokens[remap[b]])#2"
        };
        variants.push(DecodeStrategy {
            variant: DecodeVariant::V3TokensViaRemap,
            name: label,
            remap: Some(*rem),
            remap_offset: Some(*off),
            score: 0.0,
        });
    }
    for (i, (off, rem)) in remap_candidates.iter().take(2).enumerate() {
        let label = if i == 0 {
            "V4(tokens[token_index[remap[b]]])"
        } else {
            "V4(tokens[token_index[remap[b]]])#2"
        };
        variants.push(DecodeStrategy {
            variant: DecodeVariant::V4TokensViaIndexRemap,
            name: label,
            remap: Some(*rem),
            remap_offset: Some(*off),
            score: 0.0,
        });
    }

    let best = variants
        .into_par_iter()
        .map(|mut s| {
            s.score = score_strategy_names(
                s.variant,
                s.remap.as_ref().map(|a| &a[..]),
                tokens,
                token_index,
                &samples,
            );
            s
        })
        .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
        .unwrap();

    if best.score < 0.35 {
        warn!(
            "Kallsyms: low decode score across strategies (best {:.2}), using V1",
            best.score
        );
        return DecodeStrategy {
            variant: DecodeVariant::V1TokensRaw,
            name: "V1(tokens[b])",
            remap: None,
            remap_offset: None,
            score: best.score,
        };
    }

    best
}

/// Score a strategy using sample names decoded with the provided tokens/index/remap.
pub fn score_strategy_names(
    variant: DecodeVariant,
    remap: Option<&[u8]>,
    tokens: &[Vec<u8>],
    token_index: &[u16; 256],
    samples: &[&[u8]],
) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }

    let prefixes: &[&[u8]] = &[
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
    ];

    let mut ok = 0usize;
    let mut short_bad = 0usize;
    let mut very_short = 0usize;
    let mut prefix_hits = 0usize;
    let mut total = 0usize;

    // Use a small out buffer reused per sample; keeps allocations down.
    for enc in samples.iter().take(192) {
        total += 1;
        if enc.is_empty() {
            continue;
        }
        let type_byte = enc[0];
        let bytes = &enc[1..];

        let mut out = Vec::with_capacity(1 + bytes.len() * 4);
        out.push(type_byte);

        match variant {
            DecodeVariant::V1TokensRaw => {
                for &b in bytes {
                    let empty: &[u8] = &[];
                    let tok = tokens.get(b as usize).map(|v| &v[..]).unwrap_or(empty);
                    out.extend_from_slice(tok);
                }
            }
            DecodeVariant::V2TokensViaIndex => {
                for &b in bytes {
                    let idx = token_index[b as usize] as usize;
                    let empty: &[u8] = &[];
                    let tok = tokens.get(idx).map(|v| &v[..]).unwrap_or(empty);
                    out.extend_from_slice(tok);
                }
            }
            DecodeVariant::V3TokensViaRemap => {
                let rem = match remap {
                    Some(r) => r,
                    None => return 0.0,
                };
                for &b in bytes {
                    let rb = rem[b as usize] as usize;
                    let empty: &[u8] = &[];
                    let tok = tokens.get(rb).map(|v| &v[..]).unwrap_or(empty);
                    out.extend_from_slice(tok);
                }
            }
            DecodeVariant::V4TokensViaIndexRemap => {
                let rem = match remap {
                    Some(r) => r,
                    None => return 0.0,
                };
                for &b in bytes {
                    let rb = rem[b as usize] as usize;
                    let idx = token_index[rb] as usize;
                    let empty: &[u8] = &[];
                    let tok = tokens.get(idx).map(|v| &v[..]).unwrap_or(empty);
                    out.extend_from_slice(tok);
                }
            }
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
    let short_penalty = (short_bad as f64 / total as f64) * 0.5;
    let very_short_penalty = (very_short as f64 / total as f64) * 0.7;
    let prefix_bonus = (prefix_hits as f64 / total as f64) * 0.3;

    (ok_ratio - short_penalty - very_short_penalty + prefix_bonus).clamp(0.0, 1.0)
}

/// Decode all names using the chosen decoding variant. Returns each entry as
/// [type_byte | utf8_symbol_bytes].
#[allow(clippy::too_many_arguments)]
pub fn decode_all_names_with_strategy(
    data: &[u8],
    names_off: usize,
    names_size: usize,
    num_syms: usize,
    tokens: &[Vec<u8>],
    token_index: &[u16; 256],
    remap: Option<&[u8]>,
    variant: DecodeVariant,
) -> Result<Vec<Vec<u8>>> {
    let mut result: Vec<Vec<u8>> = Vec::with_capacity(num_syms);
    let mut pos = names_off;
    let end = names_off + names_size;

    for _ in 0..num_syms {
        if pos >= end {
            return Err(KallsymsError::InvalidFormat("names overflow".into()));
        }

        let len = data[pos] as usize;
        pos += 1;

        if pos + len > end {
            return Err(KallsymsError::InvalidFormat("name length overflow".into()));
        }

        let enc = &data[pos..pos + len];
        pos += len;

        if enc.is_empty() {
            return Err(KallsymsError::InvalidFormat("empty encoded name".into()));
        }

        let type_byte = enc[0];
        let bytes = &enc[1..];

        let mut out = Vec::with_capacity(1 + bytes.len() * 4);
        out.push(type_byte);

        match variant {
            DecodeVariant::V1TokensRaw => {
                for &b in bytes {
                    let empty: &[u8] = &[];
                    let tok = tokens.get(b as usize).map(|v| &v[..]).unwrap_or(empty);
                    out.extend_from_slice(tok);
                }
            }
            DecodeVariant::V2TokensViaIndex => {
                for &b in bytes {
                    let idx = token_index[b as usize] as usize;
                    let empty: &[u8] = &[];
                    let tok = tokens.get(idx).map(|v| &v[..]).unwrap_or(empty);
                    out.extend_from_slice(tok);
                }
            }
            DecodeVariant::V3TokensViaRemap => {
                let rem = remap.ok_or_else(|| {
                    KallsymsError::InvalidFormat("remap missing for selected strategy".into())
                })?;
                for &b in bytes {
                    let rb = rem[b as usize] as usize;
                    let empty: &[u8] = &[];
                    let tok = tokens.get(rb).map(|v| &v[..]).unwrap_or(empty);
                    out.extend_from_slice(tok);
                }
            }
            DecodeVariant::V4TokensViaIndexRemap => {
                let rem = remap.ok_or_else(|| {
                    KallsymsError::InvalidFormat("remap missing for selected strategy".into())
                })?;
                for &b in bytes {
                    let rb = rem[b as usize] as usize;
                    let idx = token_index[rb] as usize;
                    let empty: &[u8] = &[];
                    let tok = tokens.get(idx).map(|v| &v[..]).unwrap_or(empty);
                    out.extend_from_slice(tok);
                }
            }
        }

        result.push(out);
    }

    if pos != end {
        return Err(KallsymsError::InvalidFormat(
            "names block size mismatch".into(),
        ));
    }

    Ok(result)
}
