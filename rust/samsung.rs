//! Samsung-specific kallsyms extractor
//!
//! Samsung kernels often have stripped kallsyms tables or use custom formats.
//! This module provides specialized extraction for Samsung kernels.

use std::collections::HashMap;
use log::info;

use super::decompress::decompress_kernel_if_needed;
use super::error::{KallsymsError, Result};
use super::types::{Symbol, SymbolType};
use super::parser::Kallsyms;

/// Common function patterns in Samsung kernels
const SAMSUNG_FUNCTION_SIGNATURES: &[(&str, &[u8])] = &[
    // Common starting bytes of functions
    ("__do_sys", &[0x48, 0x89, 0x5c, 0x24]),     // x86_64
    ("__arm64_", &[0xd5, 0x3b, 0xbf, 0xa9]),     // ARM64
    ("sys_", &[0xa9, 0xbf, 0x7b, 0xfd]),         // ARM64 sys calls
    ("do_syscall_", &[0xd5, 0x3b, 0xbf, 0xa9]),  // ARM64 syscall handlers
    ("_text", &[0xa9, 0xbf, 0x7b, 0xfd]),        // Common ARM64 pattern
    ("stext", &[0xd5, 0x3b, 0xbf, 0xa9]),        // ARM64 entry
    ("start_kernel", &[0xa9, 0xbf, 0x7b, 0xfd]), // Kernel start
];

/// Extract kallsyms directly from Samsung kernel using signature scanning
pub fn extract_samsung_kallsyms(kernel_data: &[u8]) -> Result<Kallsyms> {
    // First try the normal parser
    match super::parser::Kallsyms::parse(kernel_data) {
        Ok(k) => {
            info!("Successfully parsed kallsyms using standard parser");
            return Ok(k);
        }
        Err(e) => {
            info!("Standard kallsyms parser failed, trying Samsung-specific extractor: {}", e);
        }
    }

    // Decompress if needed
    let data = decompress_kernel_if_needed(kernel_data)?;
    info!("Samsung kallsyms: kernel bytes: {}", data.len());

    // Find potential function addresses by pattern matching
    let mut symbols = Vec::new();
    let mut found_by_pattern = HashMap::new();

    // Search for function patterns
    for (func_name, pattern) in SAMSUNG_FUNCTION_SIGNATURES {
        let pattern_len = pattern.len();
        
        for i in 0..data.len() - pattern_len {
            if data[i..i+pattern_len] == pattern[..] {
                // Align to 4-byte boundary for ARM64
                let addr = (i & !0x3) as u64;
                
                if !found_by_pattern.contains_key(&addr) {
                    // Add function symbol - use raw function name
                    let symbol = Symbol {
                        address: addr,
                        symbol_type: SymbolType::Text,
                        name: format!("{}_0x{:x}", func_name, addr),
                    };
                    found_by_pattern.insert(addr, symbol);
                }
            }
        }
    }
    
    // Direct scan for function prologues in ARM64 code
    // Common ARM64 function prologue patterns
    let arm64_patterns = [
        &[0xf8, 0x5f, 0xbc, 0xa9], // STP x24, x25, [sp, #-0x40]!
        &[0xf8, 0x57, 0xbd, 0xa9], // STP x24, x21, [sp, #-0x30]!
        &[0xf7, 0x5b, 0xbc, 0xa9], // STP x23, x22, [sp, #-0x40]!
        &[0xf7, 0x53, 0xbd, 0xa9], // STP x23, x20, [sp, #-0x30]!
        &[0xfd, 0x7b, 0xbc, 0xa9], // STP x29, x30, [sp, #-0x40]!
        &[0xfd, 0x7b, 0xbd, 0xa9], // STP x29, x30, [sp, #-0x30]!
    ];
    
    for pattern in &arm64_patterns {
        let pattern_len = pattern.len();
        
        for i in 0..(data.len() - pattern_len) {
            // For larger kernels, only scan certain regions to avoid false positives
            if data.len() > 10_000_000 && i % 4 != 0 {
                continue;  // Only check addresses aligned to 4 bytes for ARM64
            }
            
            if data[i..i+pattern_len] == pattern[..] {
                // Use aligned address
                let addr = (i & !0x3) as u64;
                
                if !found_by_pattern.contains_key(&addr) {
                    let symbol = Symbol {
                        address: addr,
                        symbol_type: SymbolType::Text, 
                        name: format!("function_0x{:x}", addr),
                    };
                    found_by_pattern.insert(addr, symbol);
                }
            }
        }
    }

    // Convert hashmap values to vector
    symbols.extend(found_by_pattern.into_values());

    // Sort by address
    symbols.sort_by_key(|s| s.address);
    
    info!("Samsung kallsyms: extracted {} symbols by pattern matching", symbols.len());
    
    // If we found very few symbols, look for more using ARM64-specific searches
    if symbols.len() < 100 {
        // Scan for more ARM64 function patterns - look for STP/STR instructions at aligned addresses
        for i in (0..data.len().saturating_sub(8)).step_by(4) {
            let instr = u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
            
            // Check for common ARM64 store instructions that often start functions
            let is_stp = (instr & 0xFFC00000) == 0xA9000000;
            let is_str = (instr & 0xFFC00000) == 0xF9000000;
            
            if (is_stp || is_str) && !symbols.iter().any(|s| s.address == i as u64) {
                // Only add if we don't already have this address
                symbols.push(Symbol {
                    address: i as u64,
                    symbol_type: SymbolType::Text,
                    name: format!("func_0x{:x}", i),
                });
            }
        }
    }
    
    info!("Samsung kallsyms: extracted {} total symbols", symbols.len());
    
    if symbols.is_empty() {
        return Err(KallsymsError::NotFound);
    }
    
    // Create a Kallsyms structure with our discovered symbols
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    let mut by_address: HashMap<u64, usize> = HashMap::new();
    
    for (i, sym) in symbols.iter().enumerate() {
        by_name.entry(sym.name.clone()).or_default().push(i);
        by_address.insert(sym.address, i);
    }
    
    Ok(Kallsyms {
        symbols,
        by_name,
        by_address,
    })
}