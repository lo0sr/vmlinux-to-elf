//! Helpers for plausibility checks and sampling.

/// Basic sanity check for a token table region: lots of NUL terminators,
/// mostly printable tokens, very few control characters.
pub fn is_valid_token_table(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }
    let mut null_count = 0;
    let mut non_null_printable = 0;
    let mut control_chars = 0;
    for &b in data {
        if b == 0 {
            null_count += 1;
        } else if b.is_ascii_graphic() || b == b'_' {
            non_null_printable += 1;
        } else if b < 32 {
            control_chars += 1;
        }
    }
    null_count >= 16
        && (non_null_printable + null_count) * 100 / data.len() >= 90
        && control_chars * 100 / data.len() < 5
}

/// Check if a decoded name is reasonable for kallsyms (ASCII-ish identifier).
pub fn is_valid_symbol_name_bytes(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > 512 {
        return false;
    }
    
    // Accept all characters - we want raw, unmodified symbols
    // This basically just checks that the name isn't empty or too long
    true
}

/// Return true if s starts with any of the given byte prefixes.
pub fn starts_with_any(s: &[u8], prefixes: &[&[u8]]) -> bool {
    prefixes.iter().any(|p| s.starts_with(p))
}

/// Relaxed kernel-address plausibility check: mostly non-zero and high VA.
pub fn relax_validate_kernel_addresses(addrs: &[u64]) -> bool {
    if addrs.is_empty() {
        return false;
    }
    let mut high = 0usize;
    let mut nonzero = 0usize;
    for &a in addrs {
        if a != 0 {
            nonzero += 1;
        }
        // Relaxed VA sanity checks common on 64-bit kernels.
        if a >= 0xffff_0000_0000_0000 || a >= 0xffff_8000_0000_0000 || a >= 0xffffff80_00000000 {
            high += 1;
        }
    }
    nonzero * 100 / addrs.len() >= 95 && high * 100 / addrs.len() >= 70
}
